#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    EcamoError(#[from] ecamo::error::Error),
}

impl Error {
    //pub fn status_code(&self) -> fastly::http::StatusCode {
    //    match *self {
    //        _ => fastly::http::StatusCode::INTERNAL_SERVER_ERROR,
    //    }
    //}

    pub fn error_string(&self) -> &str {
        match &*self {
            Error::EcamoError(e) => e.error_string(),
        }
    }
}

//impl std::convert::Into<fastly::Response> for Error {
//    fn into(self) -> fastly::Response {
//        fastly::Response::from_status(self.status_code())
//            .with_body(format!("Err: {}", self.error_string()))
//    }
//}
