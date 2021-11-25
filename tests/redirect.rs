mod support;
use support::*;

use ecamo::test;

fn make_valid_url_token(env: &Environment) -> String {
    test::encode_url_token(
        &env.test_config.service_key_1,
        "svc1",
        ecamo::token::UrlToken {
            iss: "https://service1.test.invalid".to_owned(),
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
    )
}

fn make_valid_auth_token_cookie(env: &Environment) -> String {
    let token = test::generate_auth_token(
        &env.test_config.service_key_1,
        "svc1",
        "https://service1.test.invalid",
    );
    format!("__Host-ecamo_token={}", token)
}

#[actix_rt::test]
async fn test_redirect_invalid_service() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let url_token = test::encode_url_token(
        &env.test_config.service_key_2,
        "isvc",
        ecamo::token::UrlToken {
            iss: "https://invalid-service.test.invalid".to_owned(),
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
    );
    let auth_token = format!(
        "__Host-ecamo_token={}",
        test::generate_auth_token(
            &env.test_config.service_key_2,
            "isvc",
            "https://invalid-service.test.invalid",
        )
    );

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/r/{}", url_token))
                .unwrap(),
        )
        .header("host", "invalid-service.test.invalid")
        .header("cookie", auth_token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_redirect_invalid_url_token_key() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let token = test::encode_url_token(
        &env.test_config.service_key_2,
        "svc1",
        ecamo::token::UrlToken {
            iss: "https://service1.test.invalid".to_owned(),
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
    );

    let resp = http
        .get(env.url.join(&format!("/.ecamo/v1/r/{}", token)).unwrap())
        .header("host", "service1.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_redirect_invalid_url_token_iss() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let token = test::encode_url_token(
        &env.test_config.service_key_1,
        "svc1",
        ecamo::token::UrlToken {
            iss: "https://service2.test.invalid".to_owned(),
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
    );

    let resp = http
        .get(env.url.join(&format!("/.ecamo/v1/r/{}", token)).unwrap())
        .header("host", "service1.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_redirect_invalid_source() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let token = test::encode_url_token(
        &env.test_config.service_key_1,
        "svc1",
        ecamo::token::UrlToken {
            iss: "https://service1.test.invalid".to_owned(),
            ecamo_url: "http://unallowed-upstream.test.invalid/test"
                .try_into()
                .unwrap(),
            ecamo_send_token: false,
        },
    );

    let resp = http
        .get(env.url.join(&format!("/.ecamo/v1/r/{}", token)).unwrap())
        .header("host", "service1.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_redirect_invalid_source_format() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let token = UrlTokenInString::encode(
        &env.test_config.service_key_1,
        "svc1",
        "https://service1.test.invalid".to_owned(),
        "http://in%va~lid.test.invalid".try_into().unwrap(),
    );

    let resp = http
        .get(env.url.join(&format!("/.ecamo/v1/r/{}", token)).unwrap())
        .header("host", "service1.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_redirect_source_by_cookie() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let token = make_valid_url_token(&env);

    let resp = http
        .get(env.url.join(&format!("/.ecamo/v1/r/{}", token)).unwrap())
        .header("host", "service1.test.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "http://upstream.test.invalid/test"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-cache, no-store, max-age=0, must-revalidate"
    );
}

#[actix_rt::test]
async fn test_redirect_source_by_fetch_dest() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let token = make_valid_url_token(&env);

    let resp = http
        .get(env.url.join(&format!("/.ecamo/v1/r/{}", token)).unwrap())
        .header("host", "service1.test.invalid")
        .header("cookie", make_valid_auth_token_cookie(&env))
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "http://upstream.test.invalid/test"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-cache, no-store, max-age=0, must-revalidate"
    );
}

// TODO: test_redirect_invalid_auth_token_exp

#[actix_rt::test]
async fn test_redirect_invalid_auth_token_key() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let url_token = make_valid_url_token(&env);

    let auth_token = test::generate_auth_token(
        &env.test_config.service_key_2,
        "svc1",
        "https://service1.test.invalid",
    );

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/r/{}", url_token))
                .unwrap(),
        )
        .header("host", "service1.test.invalid")
        .header("cookie", format!("__Host-ecamo_token={}", auth_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_redirect_invalid_auth_token_iss() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let url_token = make_valid_url_token(&env);

    let auth_token = test::generate_auth_token(
        &env.test_config.service_key_1,
        "svc1",
        "https://service2.test.invalid",
    );

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/r/{}", url_token))
                .unwrap(),
        )
        .header("host", "service1.test.invalid")
        .header("cookie", format!("__Host-ecamo_token={}", auth_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_redirect_proxy() {
    let env = init_and_spawn().await;
    let http = build_reqwest_client();

    let url_token = make_valid_url_token(&env);
    let auth_token = make_valid_auth_token_cookie(&env);

    let resp = http
        .get(
            env.url
                .join(&format!("/.ecamo/v1/r/{}", url_token))
                .unwrap(),
        )
        .header("host", "service1.test.invalid")
        .header("cookie", auth_token)
        .header("sec-fetch-dest", "image")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-cache, no-store, max-age=0, must-revalidate"
    );

    let url = url::Url::parse(resp.headers().get("location").unwrap().to_str().unwrap()).unwrap();

    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str().unwrap(), "ecamo.test.invalid");
    assert_eq!(
        url.path(),
        "/.ecamo/v1/p/4NDjngsnmTsgtuEwT-xuia33YXiYq3j_4zm4XRawQwYAhbdlcbe4HybG-iDuY2pI"
    );

    let (_, proxy_token_str) = url.query_pairs().find(|(k, _)| k == "t").unwrap();
    let proxy_token = ecamo::token::ProxyToken::decode(
        &proxy_token_str,
        &env.test_config.app_config.signing_decoding_keys(),
    )
    .unwrap();

    let exp = chrono::Utc::now() + chrono::Duration::seconds(90);
    assert!(proxy_token.exp < exp.timestamp());

    assert_eq!(proxy_token.iss, "ecamo:s");
    assert_eq!(proxy_token.aud, "ecamo:p");
    assert_eq!(
        proxy_token.ecamo_service_origin,
        "https://service1.test.invalid"
    );
    assert_eq!(
        proxy_token.ecamo_url.as_str(),
        "http://upstream.test.invalid/test"
    );
    assert_eq!(proxy_token.ecamo_send_token, false);
}
