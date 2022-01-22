use crate::config::Config;
use crate::error::Error;

use jwt_simple::algorithms::ECDSAP256PublicKeyLike;
use jwt_simple::claims::JWTClaims;

pub trait TokenWithSourceUrl {
    fn is_valid_source(&self, config: &Config) -> bool {
        // Note this doesn't perform check of private source
        let url = self.url();

        if let Some(p) = &config.source_allowed_regexp {
            if !p.is_match(url) {
                return false;
            }
        }

        if let Some(p) = &config.source_blocked_regexp {
            if p.is_match(url) {
                return false;
            }
        }

        true
    }

    fn url(&self) -> &str;
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct UrlToken {
    #[serde(rename = "ecamo:url")]
    pub ecamo_url: url::Url,

    #[serde(rename = "ecamo:send-token", default)]
    pub ecamo_send_token: bool,
}

impl UrlToken {
    pub fn decode<T: crate::key_lookup::PublicKeyLookup>(
        token: &str,
        iss: &str,
        keys: &T,
    ) -> Result<JWTClaims<Self>, Error> {
        let metadata = jwt_simple::token::Token::decode_metadata(token)?;

        let kid = metadata
            .key_id()
            .ok_or_else(|| Error::MissingClaimError("kid".to_owned()))?;
        let key_name = format!("{} {}", iss, kid);
        let key = keys
            .lookup(&key_name)
            .ok_or_else(|| Error::UnknownKeyError(key_name.clone()))?;

        let verification = jwt_simple::common::VerificationOptions {
            allowed_issuers: Some(std::collections::HashSet::from_iter(
                [iss.to_string()].into_iter(),
            )),
            ..Default::default()
        };

        match key.verify_token::<Self>(token, Some(verification)) {
            Ok(claims) => Ok(claims),
            Err(jwt_error) => {
                // anyhow
                if let Some(serde_error) =
                    jwt_error.root_cause().downcast_ref::<serde_json::Error>()
                {
                    // XXX: it should be url error during deserialization...
                    Err(Error::TokenDeserializationError(serde_error.to_string()))
                } else {
                    Err(jwt_error.into())
                }
            }
        }
    }
}

impl TokenWithSourceUrl for UrlToken {
    fn url(&self) -> &str {
        self.ecamo_url.as_ref()
    }
}

pub fn decode_service_auth_token<T: crate::key_lookup::PublicKeyLookup>(
    token: &str,
    aud: &str,
    iss: &str,
    keys: &T,
) -> Result<JWTClaims<serde_json::Value>, Error> {
    let metadata = jwt_simple::token::Token::decode_metadata(token)?;

    let kid = metadata
        .key_id()
        .ok_or_else(|| Error::MissingClaimError("kid".to_owned()))?;
    let key_name = format!("{iss} {kid}");
    let key = keys
        .lookup(&key_name)
        .ok_or_else(|| Error::UnknownKeyError(key_name.clone()))?;

    let verification = jwt_simple::common::VerificationOptions {
        allowed_audiences: Some(std::collections::HashSet::from_iter(
            [aud.to_string()].into_iter(),
        )),
        allowed_issuers: Some(std::collections::HashSet::from_iter(
            [iss.to_string()].into_iter(),
        )),
        ..Default::default()
    };

    Ok(key.verify_token::<serde_json::Value>(token, Some(verification))?)
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct ProxyToken {
    #[serde(rename = "ecamo:svc")]
    pub ecamo_service_origin: String,

    #[serde(rename = "ecamo:url")]
    pub ecamo_url: url::Url,

    #[serde(rename = "ecamo:tok", default)]
    pub ecamo_send_token: bool,
}

impl ProxyToken {
    pub fn new(url_token: &JWTClaims<UrlToken>, config: &Config) -> Result<JWTClaims<Self>, Error> {
        let custom_claims = Self {
            ecamo_service_origin: url_token
                .issuer
                .as_ref()
                .ok_or_else(|| Error::MissingClaimError("iss".to_owned()))?
                .clone(),
            ecamo_url: url_token.custom.ecamo_url.clone(),
            ecamo_send_token: url_token.custom.ecamo_send_token,
        };

        Ok(jwt_simple::claims::Claims::with_custom_claims(
            custom_claims,
            std::time::Duration::new(config.token_lifetime, 0).into(),
        )
        .with_issuer("ecamo:s")
        .with_audience("ecamo:p"))
    }

    pub fn decode<T: crate::key_lookup::PublicKeyLookup>(
        token: &str,
        keys: &T,
    ) -> Result<JWTClaims<Self>, Error> {
        let metadata = jwt_simple::token::Token::decode_metadata(token)?;

        let kid = metadata
            .key_id()
            .ok_or_else(|| Error::MissingClaimError("kid".to_owned()))?
            .to_string();
        let key = keys
            .lookup(&kid)
            .ok_or_else(|| Error::UnknownKeyError(kid.clone()))?;

        let verification = jwt_simple::common::VerificationOptions {
            allowed_issuers: Some(std::collections::HashSet::from_iter(
                ["ecamo:s".to_owned()].into_iter(),
            )),
            allowed_audiences: Some(std::collections::HashSet::from_iter(
                ["ecamo:p".to_owned()].into_iter(),
            )),
            ..Default::default()
        };

        Ok(key.verify_token::<Self>(token, Some(verification))?)
    }

    pub fn digest(&self) -> String {
        use sha2::Digest;
        let dgst = sha2::Sha384::digest(self.ecamo_url.as_str().as_bytes());
        base64::encode_config(dgst, base64::URL_SAFE_NO_PAD)
    }

    pub fn verify(&self, digest: &str) -> Result<(), Error> {
        use sha2::Digest;

        let expected_dgst = sha2::Sha384::digest(self.ecamo_url.as_str().as_bytes());
        let actual_dgst = base64::decode_config(digest, base64::URL_SAFE_NO_PAD)?;

        // Note: no need to use constant_time_eq as an actual URL is stored in ProxyToken JWT
        if actual_dgst.len() != 48
            || expected_dgst.len() != 48
            || expected_dgst[0..48] != actual_dgst[0..48]
        {
            return Err(Error::InvalidTokenError("URL digest mismatch".to_owned()));
        }

        Ok(())
    }
}

impl TokenWithSourceUrl for ProxyToken {
    fn url(&self) -> &str {
        self.ecamo_url.as_str()
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct AnonymousIDToken {
    #[serde(rename = "ecamo:svc")]
    pub ecamo_service_origin: String,
}

impl AnonymousIDToken {
    pub fn new(url: &url::Url, service_origin: &str, config: &Config) -> JWTClaims<Self> {
        let custom_claims = Self {
            ecamo_service_origin: service_origin.to_string(),
        };
        jwt_simple::claims::Claims::with_custom_claims(
            custom_claims,
            std::time::Duration::new(config.token_lifetime, 0).into(),
        )
        .with_issuer(format!("https://{}", config.canonical_host))
        .with_subject("anonymous")
        .with_audience(url.origin().ascii_serialization())
    }
}
