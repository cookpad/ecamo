fn default_prefix() -> String {
    ".ecamo".to_string()
}

fn default_max_redirects() -> u64 {
    0
}

fn default_timeout() -> u64 {
    10
}

fn default_max_length() -> u64 {
    5242880
}

fn default_token_lifetime() -> i64 {
    45
}

fn default_default_cache_control() -> String {
    "public, max-age=3600".to_string()
}

fn default_bind() -> String {
    "[::]:3000".to_string()
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: String,

    pub canonical_host: String,

    pub private_keys: std::collections::HashMap<String, jsonwebkey::JsonWebKey>,
    pub service_public_keys: std::collections::HashMap<String, jsonwebkey::JsonWebKey>,

    pub signing_kid: Option<String>,

    #[serde(with = "serde_regex")]
    pub service_host_regexp: Option<regex::Regex>,
    #[serde(with = "serde_regex")]
    pub source_allowed_regexp: Option<regex::Regex>,
    #[serde(with = "serde_regex")]
    pub source_blocked_regexp: Option<regex::Regex>,
    #[serde(with = "serde_regex")]
    pub private_source_allowed_regexp: Option<regex::Regex>,

    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u64,
    #[serde(default = "default_token_lifetime")]
    pub token_lifetime: i64,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_max_length")]
    pub max_length: u64,

    pub auth_cookie: Option<String>,

    #[serde(default = "default_default_cache_control")]
    pub default_cache_control: String,

    #[serde(default = "bool::default")]
    pub insecure: bool,
}

impl Config {
    pub fn signing_key(&self) -> Result<jsonwebkey::JsonWebKey, crate::error::Error> {
        if self.private_keys.is_empty() {
            return Err(crate::error::Error::UndeterminableKeyError);
        }
        let jwk = if self.private_keys.len() == 1 {
            self.private_keys.values().next().unwrap()
        } else {
            let kid = self
                .signing_kid
                .as_ref()
                .ok_or(crate::error::Error::UndeterminableKeyError)?;
            self.private_keys
                .get(kid)
                .ok_or(crate::error::Error::UnknownKeyError(kid.clone()))?
        };

        if jwk.key_id.is_none() {
            return Err(crate::error::Error::MissingKeyIdError);
        }

        Ok(jwk.clone())
    }

    pub fn signing_decoding_keys<'a>(
        &self,
    ) -> std::collections::HashMap<String, jsonwebtoken::DecodingKey<'a>> {
        self.private_keys
            .iter()
            .map(|(kid, jwk)| (kid.clone(), jwk.key.to_decoding_key()))
            .collect()
    }

    pub fn service_decoding_keys<'a>(
        &self,
    ) -> std::collections::HashMap<String, jsonwebtoken::DecodingKey<'a>> {
        self.service_public_keys
            .iter()
            .map(|(kid, jwk)| (kid.clone(), jwk.key.to_decoding_key()))
            .collect()
    }

    pub fn auth_cookie_name(&self) -> &str {
        match &self.auth_cookie {
            Some(x) => x.as_ref(),
            None => {
                if self.insecure {
                    "ecamo_token"
                } else {
                    "__Host-ecamo_token"
                }
            }
        }
    }
}
