use crate::config::Config;
use crate::error::Error;

pub trait HttpRequestExt: actix_web::HttpMessage {
    fn ecamo_service_host(&self, config: &Config) -> Result<String, Error> {
        let host = self.headers().get("sec-x-ecamo-service-host").map_or_else(
            || self.ecamo_host(),
            |v| v.to_str().unwrap_or("").to_string(),
        );

        if let Some(p) = &config.service_host_regexp {
            // TODO: service_host_regexp unchecked on proxy endpoint
            if !p.is_match(&host) {
                return Err(Error::UnallowedServiceHostError);
            }
        }

        Ok(host)
    }

    fn ecamo_service_origin(&self, config: &Config) -> Result<String, Error> {
        let scheme = self.ecamo_scheme(config);
        let host = self.ecamo_service_host(config)?;
        Ok(format!("{}://{}", scheme, host))
    }

    fn ecamo_host(&self) -> String;
    fn ecamo_scheme(&self, config: &Config) -> String;
    fn ecamo_canonical_origin(&self, config: &Config) -> Result<url::Url, Error>;
}

impl HttpRequestExt for actix_web::HttpRequest {
    fn ecamo_host(&self) -> String {
        self.connection_info().host().to_string()
    }

    fn ecamo_scheme(&self, config: &Config) -> String {
        match (config.insecure, self.connection_info().scheme()) {
            (false, _) => "https",
            (true, "https") => "https",
            (true, _) => "http",
        }
        .to_owned()
    }

    fn ecamo_canonical_origin(&self, config: &Config) -> Result<url::Url, Error> {
        let scheme = self.ecamo_scheme(config);
        let s = format!("{}://{}", scheme, config.canonical_host);
        url::Url::parse(&s).map_err(Error::UrlError)
    }
}
