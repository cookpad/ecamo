use ecamo_fastlyce::access_log::EcamoCustomLogLine;
use ecamo_fastlyce::error::Error;
use ecamo_fastlyce::key_bucket::FastlyPublicKeyBucket;

const PROXY_ENDPOINT_PREFIX: &str = "/.ecamo/v1/p/";

const PUBLIC_KEY_DICTIONARY_NAME: &str = "ecamo_public_keys";
const LOG_ENDPOINT: &str = "ecamo_log";
const ACCESS_LOG_ENDPOINT: &str = "ecamo_access";

const HSTS_HEADER: &str = "max-age=31536000";

#[fastly::main]
fn main(req: fastly::Request) -> Result<fastly::Response, fastly::Error> {
    init_logging();
    let mut log_line =
        ecamo_fastlyce::access_log::LogLine::<EcamoCustomLogLine>::new(ACCESS_LOG_ENDPOINT, &req)?;
    log_line.custom.accept = req.get_header_str_lossy("accept").map(|hv| hv.into_owned());

    match handle_request(req) {
        Ok(mut resp) => {
            set_common_response_headers(&mut resp);
            complete_log_line(&mut log_line, &resp);
            log_line.complete_with_response(&resp)?;
            Ok(resp)
        }
        Err(e) => {
            log_line.complete_with_error(&e)?;
            Err(e)
        }
    }
}

fn handle_request(mut req: fastly::Request) -> Result<fastly::Response, fastly::Error> {
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
                Ok(beresp)
            }
        }
    } else {
        req.set_pass(true);
        let beresp = req.send("backend")?;
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
    Ok(beresp)
}

fn is_proxy_endpoint(req: &fastly::Request) -> bool {
    matches!(
        req.get_method(),
        &fastly::http::Method::GET | &fastly::http::Method::HEAD
    ) && req.get_path().starts_with(PROXY_ENDPOINT_PREFIX)
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

fn complete_log_line(
    log_line: &mut ecamo_fastlyce::access_log::LogLine<EcamoCustomLogLine>,
    resp: &fastly::Response,
) {
    log_line.custom.ecamo_action = resp
        .get_header_str_lossy("x-ecamo-action")
        .map(|hv| hv.into_owned());
    log_line.custom.ecamo_edge_error = resp
        .get_header_str_lossy("x-ecamo-edge-error")
        .map(|hv| hv.into_owned());
    log_line.custom.ecamo_error = resp
        .get_header_str_lossy("x-ecamo-error")
        .map(|hv| hv.into_owned());
    log_line.custom.ecamo_reason = resp
        .get_header_str_lossy("x-ecamo-reason")
        .map(|hv| hv.into_owned());
    log_line.custom.ecamo_source = resp
        .get_header_str_lossy("x-ecamo-source")
        .map(|hv| hv.into_owned());
}

fn init_logging() {
    log_fastly::Logger::builder()
        .max_level(log::LevelFilter::Info)
        .default_endpoint(LOG_ENDPOINT)
        .echo_stdout(true)
        .echo_stderr(true)
        .init();
    if let Err(e) = fastly::log::set_panic_endpoint(LOG_ENDPOINT) {
        log::warn!("set_panic_endpoint is failing: {e}");
    }
}
