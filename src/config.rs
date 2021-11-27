use elliptic_curve::sec1::ToEncodedPoint;

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

fn default_token_lifetime() -> u64 {
    45
}

pub(crate) fn default_content_type_allowed() -> Vec<String> {
    vec![
        "image/avif".to_owned(),
        "image/bmp".to_owned(),
        "image/cgm".to_owned(),
        "image/g3fax".to_owned(),
        "image/gif".to_owned(),
        "image/heic".to_owned(),
        "image/heic-sequence".to_owned(),
        "image/heif".to_owned(),
        "image/heif-sequence".to_owned(),
        "image/ief".to_owned(),
        "image/jp2".to_owned(),
        "image/jpeg".to_owned(),
        "image/jpg".to_owned(),
        "image/pict".to_owned(),
        "image/png".to_owned(),
        "image/prs.btif".to_owned(),
        "image/svg+xml".to_owned(),
        "image/tiff".to_owned(),
        "image/vnd.adobe.photoshop".to_owned(),
        "image/vnd.djvu".to_owned(),
        "image/vnd.dwg".to_owned(),
        "image/vnd.dxf".to_owned(),
        "image/vnd.fastbidsheet".to_owned(),
        "image/vnd.fpx".to_owned(),
        "image/vnd.fst".to_owned(),
        "image/vnd.fujixerox.edmics-mmr".to_owned(),
        "image/vnd.fujixerox.edmics-rlc".to_owned(),
        "image/vnd.microsoft.icon".to_owned(),
        "image/vnd.ms-modi".to_owned(),
        "image/vnd.net-fpx".to_owned(),
        "image/vnd.wap.wbmp".to_owned(),
        "image/vnd.xiff".to_owned(),
        "image/webp".to_owned(),
        "image/x-cmu-raster".to_owned(),
        "image/x-cmx".to_owned(),
        "image/x-icon".to_owned(),
        "image/x-macpaint".to_owned(),
        "image/x-pcx".to_owned(),
        "image/x-pict".to_owned(),
        "image/x-portable-anymap".to_owned(),
        "image/x-portable-bitmap".to_owned(),
        "image/x-portable-graymap".to_owned(),
        "image/x-portable-pixmap".to_owned(),
        "image/x-quicktime".to_owned(),
        "image/x-rgb".to_owned(),
        "image/x-xbitmap".to_owned(),
        "image/x-xpixmap".to_owned(),
        "image/x-xwindowdump".to_owned(),
    ]
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

    pub private_keys: std::collections::HashMap<String, elliptic_curve::JwkEcKey>,
    pub service_public_keys: std::collections::HashMap<String, elliptic_curve::JwkEcKey>,

    pub signing_kid: String,

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
    pub token_lifetime: u64,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_max_length")]
    pub max_length: u64,

    #[serde(default = "default_content_type_allowed")]
    pub content_type_allowed: Vec<String>,

    pub auth_cookie: Option<String>,

    #[serde(default = "default_default_cache_control")]
    pub default_cache_control: String,

    #[serde(default)]
    pub insecure: bool,
}

pub type PublicKeyBucket =
    std::collections::HashMap<String, jwt_simple::algorithms::ES256PublicKey>;

impl Config {
    // why jwt-simple doesn't provide a way to instantiate a key pair from ecdsa crate object?

    pub fn signing_key(&self) -> Result<jwt_simple::algorithms::ES256KeyPair, crate::error::Error> {
        let key = self
            .private_keys
            .get(&self.signing_kid)
            .ok_or_else(|| crate::error::Error::UnknownKeyError(self.signing_kid.clone()))?;
        // TODO: Assert key.crv()
        let secret_key = elliptic_curve::SecretKey::<p256::NistP256>::from_jwk(key)?;
        let signing_key = ecdsa::SigningKey::from(secret_key);

        Ok(
            jwt_simple::algorithms::ES256KeyPair::from_bytes(signing_key.to_bytes().as_ref())
                .unwrap()
                .with_key_id(&self.signing_kid),
        )
    }

    pub fn signing_decoding_keys(&self) -> PublicKeyBucket {
        make_jwk_hashmap(&self.private_keys)
    }

    pub fn service_decoding_keys(&self) -> PublicKeyBucket {
        make_jwk_hashmap(&self.service_public_keys)
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

fn make_jwk_hashmap(
    keys: &std::collections::HashMap<String, elliptic_curve::JwkEcKey>,
) -> PublicKeyBucket {
    keys.iter()
        .map(|(kid, jwk)| {
            let public_key =
                elliptic_curve::PublicKey::<p256::NistP256>::from_jwk(jwk).expect("TODO:");
            let jwtkey = jwt_simple::algorithms::ES256PublicKey::from_bytes(
                public_key.to_encoded_point(false).as_bytes(),
            )
            .unwrap();
            (kid.clone(), jwtkey)
        })
        .collect()
}
