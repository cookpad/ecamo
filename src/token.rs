use crate::config::Config;
use crate::error::Error;

pub trait TokenWithSourceUrl {
    fn is_valid_source(&self, config: &Config) -> bool {
        // Note this doesn't perform check of private source
        let url = self.url();

        if let Some(p) = &config.source_allowed_regexp {
            if !p.is_match(&url) {
                return false;
            }
        }

        if let Some(p) = &config.source_blocked_regexp {
            if p.is_match(&url) {
                return false;
            }
        }

        true
    }

    fn url(&self) -> &str;
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct UrlToken {
    pub iss: String,

    #[serde(rename = "ecamo:url")]
    pub ecamo_url: String,

    #[serde(rename = "ecamo:send-token", default)]
    pub ecamo_send_token: bool,
}

impl UrlToken {
    pub fn decode(
        token: &str,
        iss: &str,
        keys: &std::collections::HashMap<String, jsonwebtoken::DecodingKey>,
    ) -> Result<Self, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(Error::JWTError)?;

        let kid = header
            .kid
            .ok_or_else(|| Error::MissingClaimError("kid".to_owned()))?;
        let key_name = format!("{} {}", iss, kid);
        let key = keys
            .get(&key_name)
            .ok_or_else(|| Error::UnknownKeyError(key_name.clone()))?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.iss = Some(iss.to_string());
        validation.validate_exp = false;

        Ok(jsonwebtoken::decode::<UrlToken>(token, key, &validation).map(|d| d.claims)?)
    }
}

impl TokenWithSourceUrl for UrlToken {
    fn url(&self) -> &str {
        self.ecamo_url.as_ref()
    }
}

pub fn decode_service_auth_token(
    token: &str,
    aud: &str,
    iss: &str,
    keys: &std::collections::HashMap<String, jsonwebtoken::DecodingKey>,
) -> Result<serde_json::Value, Error> {
    let header = jsonwebtoken::decode_header(token).map_err(Error::JWTError)?;

    let kid = header
        .kid
        .ok_or_else(|| Error::MissingClaimError("kid".to_owned()))?;
    let key_name = format!("{} {}", iss, kid);
    let key = keys
        .get(&key_name)
        .ok_or_else(|| Error::UnknownKeyError(key_name.clone()))?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[aud]);
    validation.iss = Some(iss.to_string());

    Ok(jsonwebtoken::decode::<serde_json::Value>(token, key, &validation).map(|d| d.claims)?)
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct ProxyToken {
    pub iss: String,
    pub aud: String,
    pub exp: i64,

    #[serde(rename = "ecamo:svc")]
    pub ecamo_service_origin: String,

    #[serde(rename = "ecamo:url")]
    pub ecamo_url: String,

    #[serde(rename = "ecamo:tok", default)]
    pub ecamo_send_token: bool,
}

impl ProxyToken {
    pub fn new(url_token: &UrlToken, config: &Config) -> Self {
        let exp = chrono::Utc::now() + chrono::Duration::seconds(config.token_lifetime);

        Self {
            iss: "ecamo:s".to_owned(),
            aud: "ecamo:p".to_owned(),
            exp: exp.timestamp(),
            ecamo_service_origin: url_token.iss.clone(),
            ecamo_url: url_token.ecamo_url.clone(),
            ecamo_send_token: url_token.ecamo_send_token,
        }
    }

    pub fn encode(&self, jwk: &jsonwebkey::JsonWebKey) -> Result<String, Error> {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(jwk.key_id.clone().ok_or(Error::MissingKeyIdError)?);
        let token = jsonwebtoken::encode(&header, &self, &jwk.key.to_encoding_key())?;
        Ok(token)
    }

    pub fn decode(
        token: &str,
        keys: &std::collections::HashMap<String, jsonwebtoken::DecodingKey>,
    ) -> Result<Self, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(Error::JWTError)?;

        let kid = header
            .kid
            .ok_or_else(|| Error::MissingClaimError("no kid present in header".to_string()))?;
        let key = keys
            .get(&kid)
            .ok_or_else(|| Error::UnknownKeyError(kid.clone()))?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.iss = Some("ecamo:s".to_owned());
        validation.set_audience(&["ecamo:p"]);

        let token = jsonwebtoken::decode::<Self>(token, key, &validation).map(|d| d.claims)?;
        Ok(token)
    }

    pub fn digest(&self) -> String {
        use sha2::Digest;
        let dgst = sha2::Sha384::digest(self.ecamo_url.as_bytes());
        base64::encode_config(dgst, base64::URL_SAFE_NO_PAD)
    }

    pub fn verify(&self, digest: &str) -> Result<(), Error> {
        use sha2::Digest;

        let expected_dgst = sha2::Sha384::digest(self.ecamo_url.as_bytes());
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
pub struct UpstreamRequestToken {
    pub iss: String,
    pub aud: String,
    pub exp: i64,

    #[serde(rename = "ecamo:svc")]
    pub ecamo_service_origin: String,
}

impl UpstreamRequestToken {
    pub fn new(url: &url::Url, service_origin: &str, config: &Config) -> Self {
        let exp = chrono::Utc::now() + chrono::Duration::seconds(config.token_lifetime);

        Self {
            iss: "ecamo".to_owned(),
            aud: url.origin().ascii_serialization(),
            exp: exp.timestamp(),
            ecamo_service_origin: service_origin.to_string(),
        }
    }

    pub fn encode(&self, jwk: &jsonwebkey::JsonWebKey) -> Result<String, Error> {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = jwk.key_id.clone();
        let token = jsonwebtoken::encode(&header, &self, &jwk.key.to_encoding_key())?;
        Ok(token)
    }
}
