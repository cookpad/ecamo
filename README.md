# Ecamo - SSL image proxy with JWT authentication

Ecamo (embedded camo) is a HTTP reverse proxy heavily inspired by [atmos/camo](https://github.com/atmos/camo).

The original Camo aims to enable loading images behind cleartext HTTP server to avoid mixed content issue. In addition to that, Ecamo also aims to avoid using of third party cookies when loading images from other origins where require appropriate session cookies like company's internal screenshot server.

We've been used Camo in our internal wiki to serve some external images for long time, but due to recent movement around third-party cookies, we need a similar system to allow embedding internal screenshot services without using third-party cookie.

## How it works (at a glance)

Basically, as like as Camo does, Ecamo receives URL data and retrives a resource on URL on behalf of user.

Unlike Camo, an _origin_ must set up routing to Ecamo under a path with a predefined prefix of Ecamo. For instance, when a _Ecamo prefix_ is set to `/.ecamo/`, then any requests prefixed with `/.ecamo/` on the origin should be routed to Ecamo server. Single Ecamo server works for multiple applications (= origins).

Ecamo is designed to be used as follows.

```html
<!-- On origin https://wiki.corp.example.com -->
<img src="/.ecamo/v1/r/{URL_TOKEN}...">
```

In this example, an _origin_ is `wiki.corp.example.com` and is expected to set an _authorisation cookie_ for Ecamo. And `URL_TOKEN` specifies a URL of actual content. _authorisation cookies_ and _URL tokens_ are formatted in JWT and must be signed by _origin_ owned P-256 private key.

Then Ecamo will redirect this URL to Ecamo's _canonical origin_ with a short-lived token based on an _authorisation cookie_. A user will receive an actual content of URL specified from _origin._

## Deploy

### Configuration

Configuration is done through environment variables.

- `ECAMO_BIND` (default: `[::]:3000`): bind address
- `ECAMO_CANONICAL_HOST` (required): HTTP Host header value of an _canonical origin._ Used to serve actual content. You may need to specify port number for non-standard ports.
- `ECAMO_SERVICE_PUBLIC_KEYS` (required): JSON object where key is `"${SERVICE_ORIGIN} ${kid}"` and value is JWK object, used by services for signing an authorisation cookie and an ecamo URL. Supports ES256 keys. e.g. `{"https://service.test.invalid key_1": {"kid": "key_1", ...}}`
- `ECAMO_PRIVATE_KEYS` (required): JSON object where key is token `kid` and value is JWK object, used by Ecamo for signing an short-lived authorization token in URL and request header. Supports ES256 keys. 
- `ECAMO_SIGNING_KID`: `kid` to use primarily in `$ECAMO_PRIVATE_KEYS`.
- `ECAMO_SERVICE_HOST_REGEXP`: Regexp to validate a _service origin_ Host header. when unspecified, any origins work as a _service origin_.
- `ECAMO_SOURCE_ALLOWED_REGEXP`: Regexp to validate a source URL. When specified, any unmatching source URL will be denied.
- `ECAMO_SOURCE_BLOCKED_REGEXP`: Regexp to reject a source URL. When specified, any matching source URL will be denied.
- `ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP`: Regexp to validate a source URL in case of a destination IP address resolved into a _private IP address_. Any unmatching source URL connecting to a private IP address will be denied. When unspecified, any connection attempts to private IP address will be denied. Note that a URL has to be allowed also with `ECAMO_SOURCE_ALLOWED_REGEXP`.
- `ECAMO_PREFIX` (default: `.ecamo`): An _ecamo prefix_ explained earlier. This is an URL prefix especially when embedded in a _service origin,_ more exactly used when redirecting requests to a _service origin_ from a _canonical origin._
- `ECAMO_MAX_REDIRECTS` (default: `0`): Maximum number of HTTP redirections allowed during a single HTTP request to fetch a source URL. When allowed, any URLs will be allowed when following redirection (`ECAMO_*_REGEXP` doesn't work but `ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP` works)
- `ECAMO_MAX_LENGTH`: Maximum number of `Content-Length` allowed to be proxied from a source URL. If a `chunked` response exceeds the limit, such proxied response will be terminated (a client will see unexpected EOF)
- `ECAMO_CONTENT_TYPE_ALLOWED` (default: common image/* types): `Content-Type` allowed to be proxied. Specify in comma separeted values.
- `ECAMO_TIMEOUT`: Timeout in seconds to fetch a source URL.
- `ECAMO_AUTH_COOKIE` (default: `__Host-ecamo_token`, when insecure mode=`ecamo_token`): Cookie name to store an _authorisation token._
- `ECAMO_DEFUALT_CACHE_CONTROL` (default=`public, max-age=3600`): cache-control header value to response when it is missing in a source URL response
- `ECAMO_INSECURE`: When given, some features work on plain HTTP for development.

### `sec-x-ecamo-service-host` header

You can use `sec-x-ecamo-service-host` request header to Ecamo server to explicitly specify a _service origin_ Host header. This should work well especially if you put your Ecamo server behind reverse proxies and you need to set specific `Host` (`:authority`) header.

(In the other hands this is similar to `X-Forwarded-Host` request header)

## Usage

To use Ecamo, a _service origin_ has to generate a _URL token_ and an _authorisation token._

### Generating a ecamo URL

Use the following format to make a request to Ecamo:

`https://${SERVICE_HOST}/${PREFIX}/v1/r/${URL_TOKEN}`

where:

- `SERVICE_HOST`: any string is permitted; but subject for validation of `$ECAMO_SERVICE_HOST_REGEXP`
- `PREFIX`: recommended to be identical to `$ECAMO_PREFIX` but any string is permitted.
- `URL_TOKEN`: JWT (JSON Web Token) with the following constraints
  - header:
    - `alg`: Must be `ES256`
    - `kid`: Must be set to a one defined in `$ECAMO_SIGNING_PUBLIC_KEYS`
  - claims:
    - `iss`: Must be identical to a Web origin of _service origin._ (e.g. `https://service.test.invalid`)
    - `ecamo:url`: source URL
    - `ecamo:send-token` (optional): Set to `true` to send _anonymous ID token_ to the source URL.

#### Note

- Note that a _URL token_ is indeterministic per signing action. If you're going to enable edge caching, make sure your application generates ecamo URL as infrequently as possible.
- `exp` and `nbf` claims are not validated.

### Generating an authorisation cookie

An _authorisation cookie_ is a JWT signed by a key specified in `$ECAMO_SIGNING_PUBLIC_KEYS`, with the following constraints. It should be stored to a cookie named a value of `$ECAMO_AUTH_COOKIE` (default to `__Host-ecamo_token`)

- Headers:
  - `alg`: Must be `ES256`
  - `kid`: Must be set to a one defined in `$ECAMO_SIGNING_PUBLIC_KEYS`
- Claims:
  - `exp` must be provided.
  - `iss` must be identical to an web origin of _service origin._ (e.g. `https://service.test.invalid`)
  - `aud` must be set to an web origin of _canonical origin._ (e.g. `https://$ECAMO_CANONICAL_HOST`)
- Recommendations:
  - Align cookie expiration and token lifetime.
  - Keep lifetime as short as possible. __[Using JWT in cookies is a terrible idea](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/) in general,__ but we assume an application is doing their authentication at their own and the `ecamo-token` is derived from its session store. If `ecamo-token` can be derived from other session tokens, then its lifetime can be short.


## Misc

### Redirect to a source

To allow user to recognise a canonical URL of a requested content, when a end user directly opened `/.ecamo/...` URL, Ecamo redirects them directly to a source image (more exactly, when a request without an authorisation cookie or a request with Sec-Fetch-Dest=document).

### Anonymous ID Token

If `ecamo:send-token` of a URL token is set to true, Ecamo will set a ID token as a Bearer token (`Authorization: Bearer ...`).

The token doesn't contain user information, for example:

```json
{
  "iss": "https://ecamo.test.invalid",
  "sub": "anonymous",
  "aud": "https://source.test.invalid",
  "exp": ...,
  "iat": ...,
  "ecamo:svc": "https://service.test.invalid"
}
```

### Using with CDN

TBD

### SSRF Prevention (Private IP addresses)

Due to reqwest's current API limitation, Ecamo launches a SOCKS5 proxy to restrict connection to private IP addresses when `$ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP` is configured. The internal proxy is used only for requests not matching `$ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP`. For such requests any attempts to the following addresses will be denied:

## License

MIT License

Copyright 2021 Cookpad Inc.
