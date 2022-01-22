pub trait PublicKeyLookup {
    fn lookup(&self, key_name: &str) -> Option<&jwt_simple::algorithms::ES256PublicKey>;
}

pub type PublicKeyBucket =
    std::collections::HashMap<String, jwt_simple::algorithms::ES256PublicKey>;

impl PublicKeyLookup for PublicKeyBucket {
    fn lookup(&self, key_name: &str) -> Option<&jwt_simple::algorithms::ES256PublicKey> {
        self.get(key_name)
    }
}
