# Ecamo - SSL image proxy with JWT authentication

Ecamo (embedded camo) is a HTTP reverse proxy heavily inspired by [atmos/camo](https://github.com/atmos/camo).

The original Camo aims to enable loading images behind cleartext HTTP server to avoid mixed content issue. In addition to that, Ecamo also aims to avoid using of third party cookies when loading images from other origins where require appropriate session cookies like company's internal screenshot server.

We've been used Camo in our internal wiki to serve some external images for long time, but due to recent movement around third-party cookies, we need a similar system to allow embedding internal screenshot services without using third-party cookie.

## How it works (at a glance)

Basically, as like as Camo does, Ecamo receives URL data and retrives a resource on URL on behalf of user.

Unlike Camo, an _origin_ must set up routing to Ecamo under a path with predefined prefix for Ecamo. For instance, when a _Ecamo prefix_ is set to `/.ecamo/`, then it should be routed to Ecamo server. Single Ecamo server works on multiple applications (= origins).

Ecamo is designed to be used as follows and `wiki.corp.example.com` is expected to set an _authorisation cookie_ for Ecamo.

```html
<!-- On origin https://wiki.corp.example.com -->
<img src="https://wiki.corp.example.com/.ecamo/v1/r/abcdef.abcdef...">
```

Ecamo will redirect this URL to Ecamo's _canonical origin._ with a short-lived token based on an _authorisation cookie_. Actual contents are only served on a _canonical origin_ for security reasons.

### Redirect to a source

To allow user to recognise a canonical URL of a requested content, when a end user directly opened `/.ecamo/...` URL, Ecamo redirects them directly to a source image (more exactly, when a request without an authorisation cookie or a request with Sec-Fetch-Dest=document).

This behaviour is disabled for source URLs subject for _auth delegation._

## Deploy

### Configuration

Configuration is done through environment variables.

- `ECAMO_CANONICAL_HOST` (required): HTTP Host header value of an _canonical origin._ Used to serve actual content.
- `ECAMO_SERVICE_PUBLIC_KEYS` (required): JSON object where key is token `kid` and value is JWK object, used by services for signing an authorisation cookie and an ecamo URL. Supports ES256 keys.
- `ECAMO_PRIVATE_KEYS` (required): JSON object where key is `"${SERVICE_ORIGIN} ${kid}"` and value is JWK object, used by Ecamo for signing an short-lived authorization token in URL and request header. Supports ES256 keys. e.g. `{"https://service.test.invalid key_1": {"kid": "key_1", ...}}`
- `ECAMO_SIGNING_KID`: `kid` to use primarily in `$ECAMO_PRIVATE_KEYS`. Required when `$ECAMO_PRIVATE_KEYS` contains multiple JWKs.
- `ECAMO_SERVICE_HOST_REGEXP`: Regexp to validate a _service origin_ Host header. when unspecified, any origins work as a _service origin_.
- `ECAMO_SOURCE_ALLOWED_REGEXP`: Regexp to validate a source URL. When specified, any unmatching source URL will be denied.
- `ECAMO_SOURCE_BLOCKED_REGEXP`: Regexp to reject a source URL. When specified, any matching source URL will be denied.
- `ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP`: Regexp to validate a source URL in case of a destination IP address resolved into a _private IP address_. Any unmatching source URL connecting to a private IP address will be denied. When unspecified, any connection attempts to private IP address will be denied. Note that a URL has to be allowed also with `ECAMO_SOURCE_ALLOWED_REGEXP`.
- `ECAMO_PREFIX` (default: `.ecamo`): An _ecamo prefix_ explained earlier. This is an URL prefix especially when embedded in a _service origin,_ more exactly used when redirecting requests to a _service origin_ from a _canonical origin._
- `ECAMO_MAX_REDIRECTS`: Maximum number of HTTP redirections allowed during a single HTTP request to fetch a source URL.
- `ECAMO_MAX_LENGTH`: Maximum number of `Content-Length` allowed to be proxied from a source URL.
- `ECAMO_CONTENT_TYPE_ALLOWED` (default: common image/* types): `Content-Type` allowed to be proxied. Specify in comma separeted values.
- `ECAMO_TIMEOUT`: Timeout in seconds to fetch a source URL.
- `ECAMO_AUTH_COOKIE` (default: `__Host-ecamo_token`, when insecure mode=`ecamo_token`): Cookie name to store an _authorisation token._
- `ECAMO_DEFUALT_CACHE_CONTROL` (default=`public, max-age=3600`): cache-control header value to response when it is missing in a source URL response
- `ECAMO_INSECURE`: When given, some features work on plain HTTP for development.

### `sec-x-ecamo-service-host` header

## Usage

To use Ecamo, a _service origin_ has to generate a _signed URL_ and an _authorisation token._

### Generating a ecamo URL

format: `https://${SERVICE_HOST}/${PREFIX}/v1/r/${TOKEN}`

where:

- `SERVICE_HOST`: any string is permitted; but subject for validation of `$ECAMO_SERVICE_HOST_REGEXP`
- `PREFIX`: any string is permitted. 
- `TOKEN`: JWT (JSON Web Token) with the following constraints:
  - header:
    - `alg`: Must be `ES256`
    - `kid`: Must be set to a one defined in `$ECAMO_SIGNING_PUBLIC_KEYS`
  - claims:
    - `iss`: Must be identical to a HTTP origin of _service origin,_ but port number should not be present. (e.g. `https://service.test.invalid`)
    - `ecamo:url`: source URL
    - `ecamo:send-token` (optional): Boolean to indicate whether auth delegation is required or not

#### Note

- Note that a generated signature is not identical per signing action. if you're going to enable edge caching, make sure your application generates ecamo URL as infrequently as possible.
- It is recommended to leave `exp` claim unset to avoid requiring token regeneration. Access restriction is designed to be done by an _auth cookie._ not on a _ecamo URL._

### Generating an authorisation token

An authorisation token is a JWT signed by a key specified in `$ECAMO_SIGNING_PUBLIC_KEYS`, with the following constraints. It should be stored to a cookie named a value of `$ECAMO_AUTH_COOKIE` (default to `__Host-ecamo_token`)

- header:
  - `alg`: Must be `ES256`
  - `kid`: Must be set to a one defined in `$ECAMO_SIGNING_PUBLIC_KEYS`
- claims:
  - `iss` must be identical to an hostname of _service origin._
  - `aud` must be `$ECAMO_CANONICAL_HOST`.

It is recommended to align cookie expiration and token lifetime.

## Misc

### Auth delegation

### Using with CDN

### SSRF Prevention (Private IP addresses)

TODO:

Due to reqwest's current API limitation, Ecamo launches a SOCKS5 proxy to restrict connection to private IP addresses when `$ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP` is configured. The internal proxy is used only for requests not matching `$ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP`. For such requests any attempts to the following addresses will be denied:
