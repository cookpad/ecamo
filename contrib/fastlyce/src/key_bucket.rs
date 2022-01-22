pub struct FastlyPublicKeyBucket {
    dictionary: fastly::Dictionary,
    //cache: ecamo::key_lookup::PublicKeyBucket,
}

impl FastlyPublicKeyBucket {
    pub fn new(dictionary: fastly::Dictionary) -> Self {
        Self {
            dictionary,
            // cache: std::collections::HashMap::new(),
        }
    }

    fn get_from_dictionary(
        &self,
        key_name: &str,
    ) -> Result<Option<jwt_simple::algorithms::ES256PublicKey>, Box<dyn std::error::Error>> {
        let jwk_string = if let Some(s) = self.dictionary.get(key_name) {
            s
        } else {
            return Ok(None);
        };

        let jwk: ecamo::config::JwkObject = serde_json::from_str(&jwk_string)?;
        let public_key: jwt_simple::algorithms::ES256PublicKey = jwk.try_into()?;
        Ok(Some(public_key))
    }
}

impl ecamo::key_lookup::PublicKeyLookup for FastlyPublicKeyBucket {
    fn lookup(
        &self,
        key_name: &str,
    ) -> Option<std::borrow::Cow<jwt_simple::algorithms::ES256PublicKey>> {
        match self.get_from_dictionary(key_name) {
            Ok(Some(k)) => Some(std::borrow::Cow::Owned(k)),
            Ok(None) => None,
            Err(e) => {
                log::warn!("public key error: key_name={key_name}, e={e}");
                // TODO: log
                None
            }
        }
        //if let Some(k) = self.cache.get(key_name) {
        //    return Some(k);
        //}

        //if let Some(public_key) = self.get_from_dictionary(key_name).unwrap() {
        //    let key = &public_key;
        //    self.cache.insert(key_name.to_string(), public_key);
        //    Some(key)
        //} else {
        //    None
        //}
    }
}
