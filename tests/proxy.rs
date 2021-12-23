mod support;
use support::*;

use ecamo::test;

macro_rules! assert_response_header {
    ($v:expr, $l:literal, $r:expr) => {
        assert_eq!($v.headers().get($l).unwrap().to_str().unwrap(), $r);
    };
    ($v:expr, $l:literal) => {
        assert_eq!($v.headers().get($l).is_none(), true);
    };
}

fn make_proxy_token(env: &Environment, url: String) -> (String, String) {
    test::encode_proxy_token(
        &env.test_config.private_key,
        ecamo::token::UrlToken {
            ecamo_url: url::Url::parse(&url).unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
        Some(60),
        true,
    )
}

#[actix_rt::test]
async fn test_proxy_canonical_host() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let resp = http
        .get(env.url.join("/.ecamo/v1/p/foobar").unwrap())
        .header("host", "service1.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_proxy_invalid_token_key() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = test::encode_proxy_token(
        &env.test_config.service_key_1,
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
        Some(60),
        true,
    );

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_proxy_invalid_token_iss() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = test::encode_proxy_token(
        &env.test_config.private_key,
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
        Some(60),
        false,
    );

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_proxy_invalid_token_exp() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = test::encode_proxy_token(
        &env.test_config.private_key,
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
        None,
        true,
    );

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_proxy_invalid_digest() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (_dgst, token) = make_proxy_token(&env, "http://upstream.test.invalid/test".to_owned());

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/PkjrjXJ83cN0SaYKJJlqfr7dUPHNl6Y3wxP5RYnXpsDUMN4zO2jLkOpzHTeejO9F?t={}", token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_proxy_invalid_digest2() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (_dgst, token) = make_proxy_token(&env, "http://upstream.test.invalid/test".to_owned());

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/not-valid-base64url?t={}", token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_proxy_invalid_source() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) =
        make_proxy_token(&env, "http://invalid-upstream.test.invalid/test".to_owned());

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_proxy_200() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = make_proxy_token(&env, format!("{}/test.gif", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_response_header!(resp, "content-type", "image/gif");
    assert_response_header!(resp, "etag", "W/\"deadbeef\"");
    assert_response_header!(resp, "expires", "60");
    assert_response_header!(resp, "cache-control", "max-age=60, public");
    assert_response_header!(resp, "vary", "accept");

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes, TEST_GIF.clone());
}

#[actix_rt::test]
async fn test_proxy_200_chunked() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = make_proxy_token(&env, format!("{}/chunked.gif", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_response_header!(resp, "content-type", "image/gif");

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes, TEST_GIF.clone());
}

#[actix_rt::test]
async fn test_proxy_40x() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = make_proxy_token(&env, format!("{}/404", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    assert_response_header!(resp, "x-ecamo-error-origin", "source");
    assert_response_header!(resp, "content-type", "text/plain");
    assert_response_header!(resp, "etag");
    assert_response_header!(resp, "expires", "60");
    assert_response_header!(resp, "cache-control", "max-age=60, public");
    assert_response_header!(resp, "vary", "accept");
}

#[actix_rt::test]
async fn test_proxy_inallowed_private_source() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let orig_url = format!("{}/test.gif", mockito::server_url());
    let url = orig_url.replace("127.0.0.1", "localhost");
    assert_ne!(orig_url, url);
    let (dgst, token) = make_proxy_token(&env, url);

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert_response_header!(resp, "x-ecamo-error-origin");
}

#[actix_rt::test]
async fn test_proxy_too_long() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = make_proxy_token(&env, format!("{}/large.gif", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert_response_header!(resp, "x-ecamo-error-origin");
}

#[actix_rt::test]
async fn test_proxy_inallowed_content_type() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = make_proxy_token(&env, format!("{}/text", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert_response_header!(resp, "x-ecamo-error-origin");
}

#[actix_rt::test]
async fn test_proxy_connect_error() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) = make_proxy_token(&env, "http://127.0.0.1:0/invalid".to_owned());

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_response_header!(resp, "x-ecamo-error-origin");
}

#[actix_rt::test]
async fn test_proxy_too_long_chunked() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let (dgst, token) =
        make_proxy_token(&env, format!("{}/chunked-large.gif", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await;

    let err = bytes.err().unwrap();
    assert!(err.is_body());
}

#[actix_rt::test]
async fn test_proxy_send_token() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();
    let mut mockserv = httptest::Server::run();

    let (dgst, token) = test::encode_proxy_token(
        &env.test_config.private_key,
        ecamo::token::UrlToken {
            ecamo_url: url::Url::parse(mockserv.url("/guarded.gif").to_string().as_ref()).unwrap(),
            ecamo_send_token: true,
        },
        "https://service1.test.invalid",
        Some(60),
        true,
    );

    log::debug!("{}", mockserv.url("/"));

    mockserv.expect(
        httptest::Expectation::matching(httptest::matchers::all_of![
            httptest::matchers::request::method_path("GET", "/guarded.gif"),
            httptest::matchers::request::headers(HttptestAnonymousIDTokenMatcher {
                aud: url::Url::parse(&mockserv.url("").to_string())
                    .unwrap()
                    .origin()
                    .ascii_serialization(),
                svc: "https://service1.test.invalid".to_owned(),
                key: env.test_config.private_key_decoding.clone(),
            }),
        ])
        .respond_with(httptest::responders::status_code(200)),
    );

    let _resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .send()
        .await
        .unwrap();

    mockserv.verify_and_clear();
}

#[actix_rt::test]
async fn test_proxy_request_headers() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let _mock = mockito::mock("GET", "/headers.gif")
        .match_header("accept", "image/gif")
        .with_body(TEST_GIF.clone())
        .with_header("content-type", "image/gif")
        .with_header("etag", "W/\"headers\"")
        .create();

    let (dgst, token) = make_proxy_token(&env, format!("{}/headers.gif", mockito::server_url()));

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/p/{}?t={}", dgst, token))
                .unwrap(),
        )
        .header("host", "ecamo.test.invalid")
        .header("accept", "image/gif")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_response_header!(resp, "etag", "W/\"headers\"");
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes, TEST_GIF.clone());
}
