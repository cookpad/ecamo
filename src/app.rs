use actix_web::{web, HttpResponse};

use crate::config::Config;
use crate::error::Error;
use crate::internal_proxy::InternalProxy;
use crate::request::HttpRequestExt;
use crate::token::TokenWithSourceUrl;
use crate::token::{AnonymousIDToken, ProxyToken, UrlToken};

pub async fn main(config: Config) -> std::io::Result<actix_web::dev::Server> {
    let listener = listenfd::ListenFd::from_env()
        .take_tcp_listener(0)?
        .or_else(|| Some(std::net::TcpListener::bind(config.bind.clone()).unwrap()));
    run(config, listener.unwrap(), false).await
}

pub async fn run(
    config: Config,
    listener: std::net::TcpListener,
    is_test: bool,
) -> std::io::Result<actix_web::dev::Server> {
    let internal_proxy_url = launch_internal_proxy().await;
    let upstream = AppUpstream::new(&config, Some(internal_proxy_url));

    let app_state = AppState::new(&config, upstream);

    let server = actix_web::HttpServer::new(move || {
        let logger = actix_web::middleware::Logger::new(
            r#"status=%s request="%r" ip=%{r}a peer=%a id=%{x-request-id}i ecamo-action=%{x-ecamo-action}o ecamo-error=%{x-ecamo-error}o ecamo-source="%{x-ecamo-source}o" runtime=%T size=%b http-host="%{Host}i" http-origin="%{Origin}i" http-referer="%{Referer}i" ua="%{User-Agent}i""#,
        );
        actix_web::App::new()
            .wrap(logger)
            .app_data(web::Data::new(app_state.clone()))
            .service(index)
            .service(serve_redirect)
            .service(serve_proxy)
    });
    let server = if is_test {
        server.workers(1).disable_signals().system_exit()
    } else {
        server
    };
    let server = server.listen(listener)?.run();
    Ok(server)
}

#[derive(Debug, Clone)]
struct AppState<'a> {
    config: Config,
    signing_key: jsonwebkey::JsonWebKey,
    signing_decoding_keys: std::collections::HashMap<String, jsonwebtoken::DecodingKey<'a>>,
    service_decoding_keys: std::collections::HashMap<String, jsonwebtoken::DecodingKey<'a>>,
    upstream: AppUpstream,
}

impl AppState<'_> {
    fn new(config: &Config, upstream: AppUpstream) -> Self {
        Self {
            signing_key: config.signing_key().unwrap(),
            signing_decoding_keys: config.signing_decoding_keys(),
            service_decoding_keys: config.service_decoding_keys(),
            config: config.clone(),
            upstream,
        }
    }
}

#[derive(Debug, Clone)]
struct AppUpstream {
    http: reqwest::Client,
}

impl AppUpstream {
    fn new(config: &Config, internal_proxy_url: Option<reqwest::Url>) -> Self {
        let private_source_allowed_regexp = config.private_source_allowed_regexp.clone();
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .timeout(std::time::Duration::from_secs(config.timeout))
                .proxy(reqwest::Proxy::custom(move |url| {
                    if let Some(proxy_url) = &internal_proxy_url {
                        if let Some(r) = &private_source_allowed_regexp {
                            if r.is_match(url.as_str()) {
                                None
                            } else {
                                Some(proxy_url.clone())
                            }
                        } else {
                            Some(proxy_url.clone())
                        }
                    } else {
                        None
                    }
                }))
                .build()
                .unwrap(),
        }
    }
}

async fn launch_internal_proxy() -> reqwest::Url {
    let internal_proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_proxy_address = internal_proxy_listener.local_addr().unwrap();
    let proxy = InternalProxy::new(crate::internal_proxy::Control::permit_public());

    let mut url = reqwest::Url::parse("socks5://localhost:0").unwrap();
    url.set_ip_host(internal_proxy_address.ip()).unwrap();
    url.set_port(Some(internal_proxy_address.port())).unwrap();
    url.set_username(crate::internal_proxy::LOGIN).unwrap();
    url.set_password(Some(proxy.get_password().as_str()))
        .unwrap();

    tokio::spawn(async move {
        proxy
            .run(internal_proxy_listener)
            .await
            .expect("internal SOCKS5 proxy died")
    });

    url
}

#[actix_web::get("/")]
async fn index() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().body("ecamo"))
}

#[actix_web::get("/{prefix}/v1/r/{token}")]
async fn serve_redirect(
    state: web::Data<AppState<'_>>,
    path: web::Path<(String, String)>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let (_prefix, token) = path.into_inner();
    let service_origin = req.ecamo_service_origin(&state.config)?;

    let url_token = UrlToken::decode(&token, &service_origin, &state.service_decoding_keys)?;
    url::Url::parse(&url_token.ecamo_url).map_err(Error::UrlError)?;

    if !url_token.is_valid_source(&state.config) {
        return Err(Error::UnallowedSourceError);
    }

    if let Some(Ok(dest)) = req.headers().get("sec-fetch-dest").map(|hv| hv.to_str()) {
        if dest == "document" {
            return Ok(do_redirect_to_source(
                "redirect",
                &service_origin,
                "src-fetch-dest",
                url_token.ecamo_url,
            ));
        }
    }

    let auth_cookie = match req.cookie(state.config.auth_cookie_name()) {
        Some(c) => c,
        None => {
            return Ok(do_redirect_to_source(
                "redirect",
                &service_origin,
                "auth-cookie-missing",
                url_token.ecamo_url,
            ))
        }
    };

    let canonical_origin = req.ecamo_canonical_origin(&state.config)?;
    log::debug!("canonical_origin={}", canonical_origin);
    crate::token::decode_service_auth_token(
        auth_cookie.value(),
        &canonical_origin.origin().ascii_serialization(),
        &service_origin,
        &state.service_decoding_keys,
    )?;

    let proxy_token = ProxyToken::new(&url_token, &state.config);

    let loc = canonical_origin.join(
        format!(
            "/{}/v1/p/{}?t={}",
            state.config.prefix,
            &proxy_token.digest(),
            &proxy_token.encode(&state.signing_key)?
        )
        .as_ref(),
    )?;

    Ok(HttpResponse::Found()
        .insert_header(("x-ecamo-action", "redirect-to-canonical"))
        .insert_header(("Location", loc.to_string()))
        .insert_header((
            "Cache-Control",
            "no-cache, no-store, max-age=0, must-revalidate",
        ))
        .finish())
}

#[derive(Debug, serde::Deserialize)]
struct ProxyQuery {
    #[serde(default)]
    t: String,
}

#[actix_web::get("/{prefix}/v1/p/{digest}")]
async fn serve_proxy(
    state: web::Data<AppState<'_>>,
    path: web::Path<(String, String)>,
    query: web::Query<ProxyQuery>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let (_prefix, digest) = path.into_inner();

    if req.connection_info().host() != state.config.canonical_host {
        return Ok(HttpResponse::NotFound()
            .body("404 Not Found; proxy endpoint only works on canonical origin"));
    }

    let proxy_token = ProxyToken::decode(&query.t, &state.signing_decoding_keys)?;

    if !proxy_token.is_valid_source(&state.config) {
        return Err(Error::UnallowedSourceError);
    }
    proxy_token.verify(&digest)?;

    if let Some(Ok(dest)) = req.headers().get("sec-fetch-dest").map(|hv| hv.to_str()) {
        if dest == "document" {
            return Ok(do_redirect_to_source(
                "proxy",
                &proxy_token.ecamo_service_origin,
                "src-fetch-dest",
                proxy_token.ecamo_url,
            ));
        }
    }

    Ok(do_proxy(state, req, proxy_token).await?)
}

fn do_redirect_to_source(
    handler: &str,
    service: &str,
    reason: &str,
    url: String,
) -> actix_web::HttpResponse<actix_web::body::AnyBody> {
    log::info!(
        "handler={} action=redirect service={} reason={} to={}",
        handler,
        service,
        reason,
        url
    );
    HttpResponse::Found()
        .insert_header(("x-ecamo-action", "redirect-to-source"))
        .insert_header(("x-ecamo-source", url.clone()))
        .insert_header(("Location", url))
        .insert_header((
            "Cache-Control",
            "no-cache, no-store, max-age=0, must-revalidate",
        ))
        .finish()
}

async fn do_proxy(
    state: web::Data<AppState<'_>>,
    downstream_req: actix_web::HttpRequest,
    proxy_token: ProxyToken,
) -> Result<HttpResponse, Error> {
    let url = url::Url::parse(&proxy_token.ecamo_url).map_err(Error::UrlError)?;

    log::info!("handler=proxy action=start-proxy to={}", proxy_token.url());

    let mut upstream_req = state.upstream.http.get(url.clone());
    upstream_req = upstream_req
        .header("accept-encoding", "identity")
        .header("via", "1.1 ecamo");
    upstream_req = proxy_headers_to_upstream(upstream_req, &downstream_req, &state.config);

    if proxy_token.ecamo_send_token {
        let upstream_token =
            AnonymousIDToken::new(&url, &proxy_token.ecamo_service_origin, &state.config);
        let mut authorization_hv = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            upstream_token.encode(&state.signing_key)?
        ))
        .expect("failed to construct bearer token");
        authorization_hv.set_sensitive(true);
        upstream_req = upstream_req.header("authorization", authorization_hv);
    }

    let resp = match upstream_req.send().await {
        Err(e) => {
            if InternalProxy::is_reqwest_error_due_to_rejection(&e) {
                return Err(Error::UnallowedSourceError);
            } else {
                return Err(Error::SourceRequestError(e));
            }
        }
        Ok(r) => r,
    };

    if resp.status() != reqwest::StatusCode::OK {
        return proxy_handle_upstream_error(proxy_token, resp, state);
    }

    if let Some(len) = resp.content_length() {
        if len > state.config.max_length {
            return Err(Error::SourceResponseTooLargeError);
        }
    }

    match resp.headers().get("content-type").map(|hv| hv.to_str()) {
        Some(Ok(ct)) => {
            if !state.config.content_type_allowed.iter().any(|v| v == ct) {
                return Err(Error::InallowedContentTypeError);
            }
        }
        _ => return Err(Error::InallowedContentTypeError),
    }

    proxy_stream_response(proxy_token, resp, state)
}

fn proxy_stream_response(
    proxy_token: ProxyToken,
    resp: reqwest::Response,
    state: web::Data<AppState<'_>>,
) -> Result<HttpResponse, Error> {
    let mut downstream_resp = HttpResponse::Ok();
    downstream_resp
        .insert_header(("x-ecamo-action", "proxy-source"))
        .insert_header(("x-ecamo-source", proxy_token.url()))
        .insert_header(("X-Frame-Options", "deny"))
        .insert_header(("X-Content-Type-Options", "nosniff"));

    proxy_headers_to_downstream(&resp, &mut downstream_resp, &state.config, true);

    let chunking = if let Some(len) = resp.content_length() {
        log::info!(
            "handler=proxy action=response len={} to={}",
            len,
            proxy_token.url(),
        );
        downstream_resp.no_chunking(len);
        false
    } else {
        log::info!(
            "handler=proxy action=response len=- to={}",
            proxy_token.url(),
        );
        true
    };

    // TODO: "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"

    let stream = resp.bytes_stream();
    if chunking {
        let lstream = crate::limited_stream::LimitedStream::new(stream, state.config.max_length);
        Ok(downstream_resp.streaming(lstream))
    } else {
        Ok(downstream_resp.streaming(stream))
    }
}

fn proxy_handle_upstream_error(
    proxy_token: ProxyToken,
    resp: reqwest::Response,
    state: web::Data<AppState<'_>>,
) -> Result<HttpResponse, Error> {
    let (status, body) = if resp.status().is_client_error() || resp.status().is_server_error() {
        (
            resp.status(),
            format!("{} (from upstream)", resp.status().as_str()),
        )
    } else {
        (
            reqwest::StatusCode::BAD_REQUEST,
            format!(
                "{} (from upstream, converted to 400)",
                resp.status().as_str()
            ),
        )
    };

    log::info!(
        "handler=proxy action=upstream-response-error status={} to={}",
        status,
        proxy_token.url()
    );

    let mut downstream_resp = HttpResponse::build(status);
    downstream_resp
        .insert_header(("x-ecamo-action", "proxy-source"))
        .insert_header(("x-ecamo-source", proxy_token.url()))
        .insert_header(("X-Frame-Options", "deny"))
        .insert_header(("X-Content-Type-Options", "nosniff"));

    proxy_headers_to_downstream(&resp, &mut downstream_resp, &state.config, false);
    downstream_resp.insert_header(("content-type", "text/plain"));
    downstream_resp.insert_header(("x-ecamo-error", "source-response"));
    downstream_resp.insert_header(("x-ecamo-error-origin", "source"));

    Ok(downstream_resp.body(body))
}

fn proxy_headers_to_upstream(
    upstream: reqwest::RequestBuilder,
    downstream: &'_ actix_web::HttpRequest,
    _config: &Config,
) -> reqwest::RequestBuilder {
    let mut req = upstream;
    macro_rules! proxy_headers_transfer {
        ($k:literal) => {
            if let Some(Ok(v)) = downstream.headers().get($k).map(|hv| hv.to_str()) {
                req = req.header($k, v);
            }
        };
    }
    proxy_headers_transfer!("accept");
    req
}

fn proxy_headers_to_downstream<'a>(
    upstream: &reqwest::Response,
    downstream: &'a mut actix_web::HttpResponseBuilder,
    config: &Config,
    content_headers: bool,
) {
    macro_rules! proxy_headers_transfer {
        ($k:literal) => {
            if let Some(Ok(v)) = upstream.headers().get($k).map(|hv| hv.to_str()) {
                downstream.insert_header(($k, v));
            }
        };
        ($k:literal, $v:expr) => {
            if let Some(Ok(v)) = upstream.headers().get($k).map(|hv| hv.to_str()) {
                downstream.insert_header(($k, v));
            } else {
                downstream.insert_header(($k, $v));
            }
        };
    }
    proxy_headers_transfer!("cache-control", config.default_cache_control.clone());
    proxy_headers_transfer!("expires");
    proxy_headers_transfer!("last-modified");
    proxy_headers_transfer!("vary");

    if content_headers {
        proxy_headers_transfer!("content-type");
        proxy_headers_transfer!("etag");
    }
}

// ----

//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    fn init() {
//        let _ = env_logger::builder().is_test(true).try_init();
//    }
//
//    fn mock_config_and_state() -> (crate::test::TestConfig, AppState<'static>) {
//        init();
//        let test_config = crate::test::TestConfig::new();
//        let upstream = AppUpstream::new(&test_config.app_config, None);
//        let app_state = AppState::new(&test_config.app_config, upstream);
//        (test_config, app_state)
//    }
//}
