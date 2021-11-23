use ecamo::test;

lazy_static::lazy_static! {
    pub static ref TEST_GIF: Vec<u8> = {
        let mut path = std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        path.push("tests/test.gif");
        std::fs::read(path).unwrap()
    };
}

pub struct Environment {
    pub test_config: test::TestConfig,
    pub url: reqwest::Url,
    pub upstream_mock: mockito::Mock,
    pub upstream_mock_large: mockito::Mock,
    pub upstream_mock_chunked: mockito::Mock,
    pub upstream_mock_chunked_large: mockito::Mock,
    pub upstream_mock_404: mockito::Mock,
    pub upstream_mock_text: mockito::Mock,
}

pub async fn init_and_spawn() -> Environment {
    let _ = env_logger::builder().is_test(true).try_init();
    let test_config = crate::test::TestConfig::new();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

    let mut url = reqwest::Url::parse("http://localhost:0").unwrap();
    url.set_ip_host(listener.local_addr().unwrap().ip())
        .unwrap();
    url.set_port(Some(listener.local_addr().unwrap().port()))
        .unwrap();

    let server = ecamo::app::run(test_config.app_config.clone(), listener, true)
        .await
        .unwrap();

    tokio::spawn(async move { server.await.unwrap() });

    let upstream_mock = mockito::mock("GET", "/test.gif")
        .with_body(TEST_GIF.clone())
        .with_header("content-type", "image/gif")
        .with_header("etag", "W/\"deadbeef\"")
        .with_header("expires", "60")
        .with_header("cache-control", "max-age=60, public")
        .with_header("vary", "accept")
        .create();

    let upstream_mock_large = mockito::mock("GET", "/large.gif")
        .with_body(
            [
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
                TEST_GIF.clone(),
            ]
            .concat(),
        )
        .with_header("content-type", "image/gif")
        .with_header("etag", "W/\"deadbeef\"")
        .with_header("expires", "60")
        .with_header("cache-control", "max-age=60, public")
        .with_header("vary", "accept")
        .create();

    let upstream_mock_chunked = mockito::mock("GET", "/chunked.gif")
        .with_body_from_fn(upstream_mock_chunked_body)
        .with_header("content-type", "image/gif")
        .create();
    let upstream_mock_chunked_large = mockito::mock("GET", "/chunked-large.gif")
        .with_body_from_fn(upstream_mock_chunked_large_body)
        .with_header("content-type", "image/gif")
        .create();

    let upstream_mock_404 = mockito::mock("GET", "/404")
        .with_body("{\"four-oh-four\": 404}")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_header("etag", "W/\"deadbeef\"")
        .with_header("expires", "60")
        .with_header("cache-control", "max-age=60, public")
        .with_header("vary", "accept")
        .create();

    let upstream_mock_text = mockito::mock("GET", "/text")
        .with_body("Hello")
        .with_header("content-type", "text/plain")
        .create();

    Environment {
        test_config,
        url,
        upstream_mock,
        upstream_mock_large,
        upstream_mock_chunked,
        upstream_mock_chunked_large,
        upstream_mock_404,
        upstream_mock_text,
    }
}

pub fn build_reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap()
}

fn upstream_mock_chunked_body(body: &mut dyn std::io::Write) -> std::io::Result<()> {
    for b in TEST_GIF.clone().into_iter() {
        body.write_all(&[b])?;
    }
    body.flush()?;
    Ok(())
}

fn upstream_mock_chunked_large_body(body: &mut dyn std::io::Write) -> std::io::Result<()> {
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    upstream_mock_chunked_body(body)?;
    log::debug!("waf");
    Ok(())
}
