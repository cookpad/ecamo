#[derive(serde::Serialize, Debug)]
pub struct LogLine<CustomLogLine: serde::Serialize> {
    status: u16,
    time: String,
    method: String,
    url: String,
    cache: Option<String>,
    reqtime: i64,
    xff: Option<String>,
    peer: String,
    vhost: Option<String>,

    ua: Option<String>,

    protocol: &'static str,
    fsly_backend: Option<String>,
    fsly_host: Option<String>,
    fsly_pop: Option<String>,
    fsly_service_version: Option<String>,
    fsly_trace_id: Option<String>,
    fsly_timer: Option<String>,
    fsly_tls_protocol: Option<String>,
    fsly_tls_cipher: Option<String>,

    error: Option<String>,

    #[serde(skip)]
    ts: chrono::DateTime<chrono::Utc>,

    #[serde(skip)]
    log_endpoint: fastly::log::Endpoint,

    #[serde(flatten)]
    pub custom: CustomLogLine,
}

#[derive(serde::Serialize, Debug, Default)]
pub struct NoCustomLogLine;

impl<T: Default + serde::Serialize> LogLine<T> {
    pub fn new<E>(endpoint: E, req: &fastly::Request) -> Result<Self, fastly::Error>
    where
        E: TryInto<fastly::log::Endpoint>,
        <E as TryInto<fastly::log::Endpoint>>::Error: Into<fastly::Error>,
    {
        Self::new_with_custom(endpoint, req, Default::default())
    }
}

impl<T: serde::Serialize> LogLine<T> {
    pub fn new_with_custom<E>(
        endpoint: E,
        req: &fastly::Request,
        custom: T,
    ) -> Result<Self, fastly::Error>
    where
        E: TryInto<fastly::log::Endpoint>,
        <E as TryInto<fastly::log::Endpoint>>::Error: Into<fastly::Error>,
    {
        let log_endpoint = endpoint.try_into().map_err(|e| e.into())?;
        let now = chrono::Utc::now();
        Ok(Self {
            status: 0,
            time: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            method: req.get_method_str().to_owned(),
            url: req.get_url_str().to_owned(),
            cache: None,
            reqtime: -1,
            xff: req
                .get_header_str_lossy("x-forwarded-for")
                .map(|hv| hv.into_owned()),
            peer: req
                .get_client_ip_addr()
                .expect("req should be client request")
                .to_string(),
            vhost: req.get_header_str_lossy("host").map(|hv| hv.into_owned()),

            ua: req
                .get_header_str_lossy("user-agent")
                .map(|hv| hv.into_owned()),

            protocol: version_to_str(req.get_version()),
            fsly_backend: None,
            fsly_host: std::env::var("FASTLY_HOSTNAME").ok(),
            fsly_pop: std::env::var("FASTLY_POP").ok(),
            fsly_service_version: std::env::var("FASTLY_SERVICE_VERSION").ok(),
            fsly_trace_id: std::env::var("FASTLY_TRACE_ID").ok(),
            fsly_timer: None,
            fsly_tls_protocol: req.get_tls_protocol().map(|x| x.to_string()),
            fsly_tls_cipher: req.get_tls_cipher_openssl_name().map(|x| x.to_string()),

            error: None,

            ts: now,
            log_endpoint,
            custom,
        })
    }

    pub fn complete_with_response(mut self, resp: &fastly::Response) -> Result<(), std::io::Error> {
        let now = chrono::Utc::now();
        self.status = resp.get_status().as_u16();
        self.cache = resp
            .get_header_str_lossy("x-cache")
            .map(|hv| hv.into_owned());
        self.reqtime = (now - self.ts).num_milliseconds();
        self.fsly_backend = resp.get_backend_name().map(|s| s.to_string());
        self.fsly_timer = resp
            .get_header_str_lossy("x-timer")
            .map(|hv| hv.into_owned());

        self.emit()
    }

    pub fn complete_with_error(
        mut self,
        e: impl AsRef<dyn std::error::Error>,
    ) -> Result<(), std::io::Error> {
        let now = chrono::Utc::now();
        self.status = 500;
        self.reqtime = (now - self.ts).num_milliseconds();
        self.error = Some(e.as_ref().to_string());

        self.emit()
    }

    fn emit(mut self) -> Result<(), std::io::Error> {
        use std::io::Write as _;
        // Call `write` once, the same way that log-fastly crate does.
        let buf = serde_json::to_string(&self)?;
        if let Err(e) = write!(self.log_endpoint, "{}", buf) {
            // "invalid log endpoint handle" per implementation of fastly::log
            if e.kind() == std::io::ErrorKind::InvalidInput {
                // do nothing
            } else {
                return Err(e);
            }
        }
        Ok(())
    }
}

fn version_to_str(v: fastly::http::Version) -> &'static str {
    match v {
        fastly::http::Version::HTTP_09 => "HTTP/0.9",
        fastly::http::Version::HTTP_10 => "HTTP/1.0",
        fastly::http::Version::HTTP_11 => "HTTP/1.1",
        fastly::http::Version::HTTP_2 => "HTTP/2",
        fastly::http::Version::HTTP_3 => "HTTP/3",
        _ => "UNKNOWN",
    }
}

//-------------

#[derive(serde::Serialize, Debug, Default)]
pub struct EcamoCustomLogLine {
    pub accept: Option<String>,
    pub ecamo_action: Option<String>,
    pub ecamo_edge_error: Option<String>,
    pub ecamo_error: Option<String>,
    pub ecamo_reason: Option<String>,
    pub ecamo_source: Option<String>,
}
