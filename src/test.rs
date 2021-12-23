use elliptic_curve::sec1::ToEncodedPoint;
use jwt_simple::prelude::ECDSAP256KeyPairLike;

pub struct TestConfig {
    pub app_config: crate::config::Config,
    pub private_key: jwt_simple::algorithms::ES256KeyPair,
    pub service_key_1: jwt_simple::algorithms::ES256KeyPair,
    pub service_key_2: jwt_simple::algorithms::ES256KeyPair,

    pub private_key_invalid: jwt_simple::algorithms::ES256KeyPair,
    pub service_key_invalid: jwt_simple::algorithms::ES256KeyPair,

    pub private_key_decoding: jwt_simple::algorithms::ES256PublicKey,
}

impl TestConfig {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let private_key = elliptic_curve::SecretKey::<p256::NistP256>::random(rand::thread_rng());
        let service_key_1 = elliptic_curve::SecretKey::<p256::NistP256>::random(rand::thread_rng());
        let service_key_2 = elliptic_curve::SecretKey::<p256::NistP256>::random(rand::thread_rng());

        let private_keypair =
            jwt_simple::algorithms::ES256KeyPair::from_bytes(private_key.to_bytes().as_ref())
                .unwrap()
                .with_key_id("prv");
        let service_keypair_1 =
            jwt_simple::algorithms::ES256KeyPair::from_bytes(service_key_1.to_bytes().as_ref())
                .unwrap()
                .with_key_id("svc1");
        let service_keypair_2 =
            jwt_simple::algorithms::ES256KeyPair::from_bytes(service_key_2.to_bytes().as_ref())
                .unwrap()
                .with_key_id("svc2");
        let service_keypair_invalid =
            jwt_simple::algorithms::ES256KeyPair::from_bytes(service_key_2.to_bytes().as_ref())
                .unwrap()
                .with_key_id("svc1");
        let private_keypair_invalid =
            jwt_simple::algorithms::ES256KeyPair::from_bytes(service_key_2.to_bytes().as_ref())
                .unwrap()
                .with_key_id("prv");
        let private_key_decoding = jwt_simple::algorithms::ES256PublicKey::from_bytes(
            private_key.public_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();

        let app_config = crate::config::Config {
            bind: "127.0.0.1:0".to_owned(),
            canonical_host: "ecamo.test.invalid".to_owned(),
            private_keys: [("prv".to_owned(), private_key.into())].into(),
            service_public_keys: [
                (
                    "https://service1.test.invalid svc1".to_owned(),
                    service_key_1.public_key().into(),
                ),
                (
                    "https://service2.test.invalid svc2".to_owned(),
                    service_key_2.public_key().into(),
                ),
                (
                    "https://invalid-service.test.invalid isvc".to_owned(),
                    service_key_2.public_key().into(),
                ),
            ]
            .into(),

            signing_kid: "prv".to_owned(),

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
            private_key: private_keypair,
            service_key_1: service_keypair_1,
            service_key_2: service_keypair_2,
            service_key_invalid: service_keypair_invalid,
            private_key_invalid: private_keypair_invalid,
            private_key_decoding,
        }
    }
}

pub fn encode_url_token(
    key: &jwt_simple::algorithms::ES256KeyPair,
    payload: crate::token::UrlToken,
    iss: &str,
) -> String {
    let mut claims = jwt_simple::claims::Claims::with_custom_claims(
        payload,
        std::time::Duration::new(0, 0).into(),
    )
    .with_issuer(iss);
    claims.issued_at = None;
    claims.expires_at = None;
    claims.invalid_before = None;
    key.sign(claims).unwrap()
}

pub fn generate_auth_token(key: &jwt_simple::algorithms::ES256KeyPair, iss: &str) -> String {
    let claims = jwt_simple::claims::Claims::create(std::time::Duration::new(60, 0).into())
        .with_issuer(iss)
        .with_audience("https://ecamo.test.invalid");
    key.sign(claims).unwrap()
}

pub fn encode_proxy_token(
    key: &jwt_simple::algorithms::ES256KeyPair,
    payload: crate::token::UrlToken,
    iss: &str,
    lifetime: Option<u64>,
    valid_iss: bool,
) -> (String, String) {
    let payload = crate::token::ProxyToken {
        ecamo_service_origin: iss.to_string(),
        ecamo_url: payload.ecamo_url,
        ecamo_send_token: payload.ecamo_send_token,
    };
    let dgst = payload.digest();
    let mut claims = jwt_simple::claims::Claims::with_custom_claims(
        payload,
        std::time::Duration::new(lifetime.unwrap_or(0), 0).into(),
    )
    .with_issuer(match valid_iss {
        true => "ecamo:s",
        false => "ecamo:invalid",
    })
    .with_audience("ecamo:p");

    if lifetime.is_none() {
        claims.invalid_before = None;
        claims.expires_at =
            Some(claims.issued_at.unwrap() - std::time::Duration::new(36000, 0).into());
        claims.issued_at = None;
    }

    let token = key.sign(claims).unwrap();

    (dgst, token)
}
