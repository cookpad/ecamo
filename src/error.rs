#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("some claims are missing: {0}")]
    MissingClaimError(String),

    #[error("missing key kid={0}")]
    UnknownKeyError(String),

    #[error("service host is not allowed")]
    UnallowedServiceHostError,

    #[error("source is not allowed")]
    UnallowedSourceError,

    #[error("content too large")]
    SourceResponseTooLargeError,

    #[error(transparent)]
    ECError(#[from] elliptic_curve::Error),

    #[error(transparent)]
    JWTError(#[from] jwt_simple::Error),

    #[error("base64 decode error")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("invalid token: {0}")]
    InvalidTokenError(String),

    #[error(transparent)]
    UrlError(#[from] url::ParseError),

    #[error("unable to deserialize given JWT: {0}")]
    TokenDeserializationError(String),

    #[cfg(feature = "webapp")]
    #[error("request error")]
    SourceRequestError(#[from] reqwest::Error),

    #[error("signing key is missing kid")]
    MissingKeyIdError,

    #[error("content-type is not allowed")]
    InallowedContentTypeError,

    #[error("{0}")]
    UnknownError(String),
}

impl Error {
    pub fn error_string(&self) -> &str {
        match *self {
            Self::Base64DecodeError(_) => "bad-request",
            Self::InvalidTokenError(_) => "invalid-token",
            Self::JWTError(_) => "jwt",
            Self::MissingClaimError(_) => "missing-claim",
            Self::UnallowedServiceHostError => "unallowed-service-host",
            Self::UnallowedSourceError => "unallowed-source",
            Self::UnknownKeyError(_) => "unknown-key",
            Self::SourceResponseTooLargeError => "source-response-too-large",
            Self::InallowedContentTypeError => "unallowed-content-type",
            Self::UrlError(_) => "url",
            Self::TokenDeserializationError(_) => "token-deserialization",

            #[cfg(feature = "webapp")]
            Self::SourceRequestError(_) => "source-request",

            _ => "unknown",
        }
    }
}

#[cfg(feature = "webapp")]
impl actix_web::ResponseError for Error {
    fn status_code(&self) -> actix_http::StatusCode {
        match *self {
            Self::Base64DecodeError(_) => actix_http::StatusCode::BAD_REQUEST,
            Self::InvalidTokenError(_) => actix_http::StatusCode::UNAUTHORIZED,
            Self::JWTError(_) => actix_http::StatusCode::UNAUTHORIZED,
            Self::MissingClaimError(_) => actix_http::StatusCode::BAD_REQUEST,
            Self::UnallowedServiceHostError => actix_http::StatusCode::FORBIDDEN,
            Self::UnallowedSourceError => actix_http::StatusCode::FORBIDDEN,
            Self::UnknownKeyError(_) => actix_http::StatusCode::UNAUTHORIZED,
            Self::SourceRequestError(_) => actix_http::StatusCode::BAD_GATEWAY,
            Self::SourceResponseTooLargeError => actix_http::StatusCode::FORBIDDEN,
            Self::InallowedContentTypeError => actix_http::StatusCode::FORBIDDEN,
            Self::UrlError(_) => actix_http::StatusCode::BAD_REQUEST,
            Self::TokenDeserializationError(_) => actix_http::StatusCode::BAD_REQUEST,
            _ => actix_http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::web::HttpResponse {
        log::warn!(
            "ecamo::error::Error({}): {}",
            self.error_string(),
            self.to_string()
        );
        actix_web::HttpResponse::build(self.status_code())
            .insert_header(("x-ecamo-error", self.error_string()))
            .body(format!("Error: {}", self.error_string()))
    }
}
