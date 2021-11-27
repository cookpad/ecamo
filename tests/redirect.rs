mod support;
use support::*;

use jwt_simple::prelude::ECDSAP256KeyPairLike;

use ecamo::test;

fn make_valid_url_token(env: &Environment) -> String {
    test::encode_url_token(
        &env.test_config.service_key_1,
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
    )
}

fn make_valid_auth_token_cookie(env: &Environment) -> String {
    let token = test::generate_auth_token(
        &env.test_config.service_key_1,
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
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://invalid-service.test.invalid",
    );
    let auth_token = format!(
        "__Host-ecamo_token={}",
        test::generate_auth_token(
            &env.test_config.service_key_2,
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
        &env.test_config.service_key_invalid,
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
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
        ecamo::token::UrlToken {
            ecamo_url: "http://upstream.test.invalid/test".try_into().unwrap(),
            ecamo_send_token: false,
        },
        "https://service2.test.invalid",
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
        ecamo::token::UrlToken {
            ecamo_url: "http://unallowed-upstream.test.invalid/test"
                .try_into()
                .unwrap(),
            ecamo_send_token: false,
        },
        "https://service1.test.invalid",
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

    let claims = jwt_simple::claims::Claims::with_custom_claims(
        UrlTokenInString {
            ecamo_url: "http://in%va~lid.test.invalid".to_owned(),
        },
        std::time::Duration::new(60, 0).into(),
    )
    .with_issuer("https://service1.test.invalid");
    let token = env.test_config.service_key_1.sign(claims).unwrap();

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
    assert!(proxy_token.expires_at.unwrap().as_secs() < exp.timestamp().try_into().unwrap());

    assert_eq!(proxy_token.issuer.unwrap(), "ecamo:s");
    assert!(proxy_token
        .audiences
        .unwrap()
        .contains(&std::collections::HashSet::from_iter(
            ["ecamo:p".to_owned()].into_iter()
        )));
    assert_eq!(
        proxy_token.custom.ecamo_service_origin,
        "https://service1.test.invalid"
    );
    assert_eq!(
        proxy_token.custom.ecamo_url.as_str(),
        "http://upstream.test.invalid/test"
    );
    assert_eq!(proxy_token.custom.ecamo_send_token, false);
}
