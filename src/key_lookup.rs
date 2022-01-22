pub trait PublicKeyLookup {
    fn lookup(
        &self,
        key_name: &str,
    ) -> Option<std::borrow::Cow<jwt_simple::algorithms::ES256PublicKey>>;
}

pub type PublicKeyBucket =
    std::collections::HashMap<String, jwt_simple::algorithms::ES256PublicKey>;

impl PublicKeyLookup for PublicKeyBucket {
    fn lookup(
        &self,
        key_name: &str,
    ) -> Option<std::borrow::Cow<jwt_simple::algorithms::ES256PublicKey>> {
        match self.get(key_name) {
            Some(k) => Some(std::borrow::Cow::Borrowed(k)),
            None => None,
        }
    }
}
