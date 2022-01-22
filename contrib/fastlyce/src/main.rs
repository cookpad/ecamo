use ecamo_fastlyce::error::Error;
use ecamo_fastlyce::key_bucket::FastlyPublicKeyBucket;

const PROXY_ENDPOINT_PREFIX: &str = "/.ecamo/v1/p/";
const PUBLIC_KEY_DICTIONARY_NAME: &str = "ecamo_public_keys";

const HSTS_HEADER: &str = "max-age=31536000";

#[fastly::main]
fn main(mut req: fastly::Request) -> Result<fastly::Response, fastly::Error> {
    log_fastly::init_simple("ecamo_log", log::LevelFilter::Info);
    let local = std::env::var("FASTLY_HOSTNAME").unwrap() == "localhost";

    if !local {
        if let Some(resp) = do_force_https(&req) {
            return Ok(resp);
        }
    }

    if is_proxy_endpoint(&req) {
        match serve_proxy(&req) {
            Ok(t) => do_proxy(t, req),
            Err(e) => {
                req.set_pass(true);
                let mut beresp = req.send("backend")?;
                beresp.set_header("x-ecamo-edge-error", e.error_string());
                set_common_response_headers(&mut beresp);
                Ok(beresp)
            }
        }
    } else {
        req.set_pass(true);
        let mut beresp = req.send("backend")?;
        set_common_response_headers(&mut beresp);
        Ok(beresp)
    }
}

fn serve_proxy(req: &fastly::Request) -> Result<ecamo::token::ProxyToken, Error> {
    let digest = req
        .get_path()
        .strip_prefix(PROXY_ENDPOINT_PREFIX)
        .unwrap_or("");
    let t = req.get_query_parameter("t").unwrap_or("");

    let keys_bucket = FastlyPublicKeyBucket::new(
        fastly::Dictionary::try_open(PUBLIC_KEY_DICTIONARY_NAME).expect("dictionary didn't open"),
    );
    let proxy_token =
        ecamo::token::ProxyToken::decode(t, &keys_bucket).map_err(Error::EcamoError)?;

    // Note: Don't verify source address here because it is performed on backend
    proxy_token.custom.verify(digest)?;

    Ok(proxy_token.custom)
}

fn do_proxy(
    proxy_token: ecamo::token::ProxyToken,
    mut req: fastly::Request,
) -> Result<fastly::Response, fastly::Error> {
    use fastly::experimental::RequestCacheKey as _;
    req.set_pass(false);
    req.set_cache_key_str(&format!(
        "v1:proxy:{}|{}|{}|{}",
        req.get_method_str(),
        proxy_token.ecamo_send_token,
        proxy_token.ecamo_service_origin,
        proxy_token.ecamo_url.as_str(),
    ));

    let mut beresp = req.send("backend")?;
    beresp.set_header("x-ecamo-edge", "ok");
    set_common_response_headers(&mut beresp);
    Ok(beresp)
}

fn is_proxy_endpoint(req: &fastly::Request) -> bool {
    match req.get_method() {
        &fastly::http::Method::GET | &fastly::http::Method::HEAD => {
            req.get_path().starts_with(PROXY_ENDPOINT_PREFIX)
        }
        _ => false,
    }
}

fn do_force_https(req: &fastly::Request) -> Option<fastly::Response> {
    if req.get_tls_protocol().is_none() {
        let mut url = req.get_url().clone();
        url.set_scheme("https").unwrap();
        Some(
            fastly::Response::from_status(fastly::http::StatusCode::FOUND)
                .with_header("location", url.as_str())
                .with_header("strict-transport-security", HSTS_HEADER),
        )
    } else {
        None
    }
}

fn set_common_response_headers(resp: &mut fastly::Response) {
    let local = std::env::var("FASTLY_HOSTNAME").unwrap() == "localhost";
    if !local {
        resp.set_header("strict-transport-security", HSTS_HEADER);
    }

    if local {
        resp.set_header("x-ecamo-edge-local", "local");
    }
}
