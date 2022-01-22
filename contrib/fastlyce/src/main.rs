use ecamo_fastlyce::error::Error;
use ecamo_fastlyce::key_bucket::FastlyPublicKeyBucket;

const PROXY_ENDPOINT_PREFIX: &str = "/.ecamo/v1/p/";
const PUBLIC_KEY_DICTIONARY_NAME: &str = "ecamo_public_keys";

#[fastly::main]
fn main(mut req: fastly::Request) -> Result<fastly::Response, fastly::Error> {
    log_fastly::init_simple("ecamo_log", log::LevelFilter::Info);
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
        return Ok(req.send("backend")?);
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
        ecamo::token::ProxyToken::decode(&t, &keys_bucket).map_err(Error::EcamoError)?;

    // Note: Don't verify source address here because it is performed on backend
    proxy_token.custom.verify(&digest)?;

    Ok(proxy_token.custom)
}

fn do_proxy(
    proxy_token: ecamo::token::ProxyToken,
    mut req: fastly::Request,
) -> Result<fastly::Response, fastly::Error> {
    use fastly::experimental::RequestCacheKey as _;
    req.set_cache_key_str(&format!(
        "{}|{}|{}",
        proxy_token.ecamo_send_token,
        proxy_token.ecamo_service_origin,
        proxy_token.ecamo_url.as_str(),
    ));
    let mut beresp = req.send("backend")?;
    beresp.set_header("x-ecamo-edge", "ok");
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
