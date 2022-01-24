# ecamo_fastlyce: Ecamo Fastly Compute@Edge deployment

ecamo_fastlyce enables edge caching of proxy endpoint on $ECAMO_CANONICAL_HOST (`/.ecamo/v1/p/...`) by verifying `?t=` query parameter at edge and caching backend response.

this doesn't support actual proxying function that the proxy endpoint does. You need to setup actual Ecamo server and set to a Compute Service backend.
In the other hands, this crate aims to support edge verification of `?t=` for caching.

## Deploy

- Ecamo server should be set up as a backend named `backend`
- `ecamo_public_keys` dictionary should be set up as follows with content based on `$ECAMO_PRIVATE_KEYS`: 
  - key: JWK `kid`
  - value: JWK JSON string; this should not contain private key
