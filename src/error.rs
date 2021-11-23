use actix_web::ResponseError;

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
    UpstreamResponseTooLargeError,

    #[error("jwterror")]
    JWTError(#[from] jsonwebtoken::errors::Error),

    #[error("base64 decode error")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("invalid token: {0}")]
    InvalidTokenError(String),

    #[error("cannot build or parse given url")]
    UrlError(#[from] url::ParseError),

    #[error("request error")]
    UpstreamRequestError(#[from] reqwest::Error),

    #[error("signing key is undeterminable; specify $ECAMO_SIGNING_KID")]
    UndeterminableKeyError,

    #[error("signing key is missing kid")]
    MissingKeyIdError,

    #[error("content-type is not allowed")]
    InallowedContentTypeError,

    #[error("{0}")]
    UnknownError(String),
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_http::StatusCode {
        match *self {
            Self::Base64DecodeError(_) => actix_http::StatusCode::BAD_REQUEST,
            Self::InvalidTokenError(_) => actix_http::StatusCode::UNAUTHORIZED,
            Self::JWTError(_) => actix_http::StatusCode::UNAUTHORIZED,
            Self::MissingClaimError(_) => actix_http::StatusCode::BAD_REQUEST,
            Self::UnallowedServiceHostError => actix_http::StatusCode::FORBIDDEN,
            Self::UnallowedSourceError => actix_http::StatusCode::FORBIDDEN,
            Self::UnknownKeyError(_) => actix_http::StatusCode::UNAUTHORIZED,
            Self::UpstreamRequestError(_) => actix_http::StatusCode::BAD_GATEWAY,
            Self::UpstreamResponseTooLargeError => actix_http::StatusCode::FORBIDDEN,
            Self::InallowedContentTypeError => actix_http::StatusCode::FORBIDDEN,
            Self::UrlError(_) => actix_http::StatusCode::BAD_REQUEST,
            _ => actix_http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
