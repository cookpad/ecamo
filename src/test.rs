pub struct TestConfig<'a> {
    pub app_config: crate::config::Config,
    pub private_key: jsonwebtoken::EncodingKey,
    pub service_key_1: jsonwebtoken::EncodingKey,
    pub service_key_2: jsonwebtoken::EncodingKey,

    pub private_key_decoding: jsonwebtoken::DecodingKey<'a>,
}

impl TestConfig<'_> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let private_key = jsonwebkey::Key::generate_p256();
        let service_key_1 = jsonwebkey::Key::generate_p256();
        let service_key_2 = jsonwebkey::Key::generate_p256();

        let mut private_jwk = jsonwebkey::JsonWebKey::new(private_key.clone());
        private_jwk.key_id = Some("prv".to_owned());

        let app_config = crate::config::Config {
            bind: "127.0.0.1:0".to_owned(),
            canonical_host: "ecamo.test.invalid".to_owned(),
            private_keys: [("prv".to_owned(), private_jwk)].into(),
            service_public_keys: [
                (
                    "https://service1.test.invalid svc1".to_owned(),
                    jsonwebkey::JsonWebKey::new(service_key_1.clone()),
                ),
                (
                    "https://service2.test.invalid svc2".to_owned(),
                    jsonwebkey::JsonWebKey::new(service_key_2.clone()),
                ),
                (
                    "https://invalid-service.test.invalid isvc".to_owned(),
                    jsonwebkey::JsonWebKey::new(service_key_2.clone()),
                ),
            ]
            .into(),

            signing_kid: Some("prv".to_owned()),

            service_host_regexp: Some(regex::Regex::new(r"^service.?\.test\.invalid$").unwrap()),
            source_allowed_regexp: Some(
                regex::Regex::new(
                    r"^http://(127\.0\.0\.1:\d+|\[::1\]:\d+|localhost:\d+|upstream\.test\.invalid)/",
                )
                .unwrap(),
            ),
            source_blocked_regexp: Some(
                regex::Regex::new(
                    r"^http://(127\.0\.0\.1:\d+|localhost:\d+|upstream\.test\.invalid)/blocked$",
                )
                .unwrap(),
            ),
            private_source_allowed_regexp: Some(
                regex::Regex::new(r"^http://(127\.0\.0\.1:\d+|\[::1\]:\d+)/").unwrap(),
            ),
            content_type_allowed: crate::config::default_content_type_allowed(),

            prefix: ".ecamo".to_owned(),
            max_redirects: 1,
            token_lifetime: 60,
            timeout: 3,
            max_length: 100,

            auth_cookie: None,
            default_cache_control: "public, max-age=3600".to_owned(),

            insecure: false,
        };

        Self {
            app_config,
            private_key: private_key.to_encoding_key(),
            service_key_1: service_key_1.to_encoding_key(),
            service_key_2: service_key_2.to_encoding_key(),
            private_key_decoding: private_key.to_decoding_key(),
        }
    }
}

pub fn encode_url_token(
    key: &jsonwebtoken::EncodingKey,
    kid: &str,
    payload: crate::token::UrlToken,
) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid.to_string());

    jsonwebtoken::encode(&header, &payload, key).unwrap()
}

#[derive(Debug, serde::Serialize)]
struct AuthToken {
    iss: String,
    aud: String,
    exp: i64,
}

pub fn generate_auth_token(key: &jsonwebtoken::EncodingKey, kid: &str, iss: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid.to_string());

    let exp = chrono::Utc::now() + chrono::Duration::seconds(60);
    let payload = AuthToken {
        iss: iss.to_string(),
        aud: "https://ecamo.test.invalid".to_owned(),
        exp: exp.timestamp(),
    };

    jsonwebtoken::encode(&header, &payload, key).unwrap()
}

pub fn encode_proxy_token(
    key: &jsonwebtoken::EncodingKey,
    kid: &str,
    payload: crate::token::UrlToken,
    lifetime: i64,
    valid_iss: bool,
) -> (String, String) {
    let exp = chrono::Utc::now() + chrono::Duration::seconds(lifetime);

    let payload = crate::token::ProxyToken {
        iss: match valid_iss {
            true => "ecamo:s".to_owned(),
            false => "ecamo:invalid".to_owned(),
        },
        aud: "ecamo:p".to_owned(),
        exp: exp.timestamp(),
        ecamo_service_origin: payload.iss,
        ecamo_url: payload.ecamo_url,
        ecamo_send_token: payload.ecamo_send_token,
    };
    let dgst = payload.digest();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid.to_string());
    let token = jsonwebtoken::encode(&header, &payload, key).unwrap();

    (dgst, token)
}
