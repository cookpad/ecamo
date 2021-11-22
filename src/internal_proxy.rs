// FIXME: Internal SOCKS5 proxy to restrict connections to specific IP addresses. Remove when Reqwest supported doing authorization on outgoing connections by SocketAddr.
//        https://github.com/seanmonstar/reqwest/issues/1125
//
use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::global_ip;

pub const LOGIN: &str = "ecamo";
const VERSION: u8 = 5;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_VERSION: u8 = 0x1;
const AUTH_OK: u8 = 0x0;

const CMD_STREAM: u8 = 0x1;

const ADDRTYPE_IPV4: u8 = 0x1;
const ADDRTYPE_IPV6: u8 = 0x4;

const REPLY_OK: u8 = 0x0;
const REPLY_FAIL: u8 = 0x1;
const REPLY_ADDRTYPE_UNSUPPORTED: u8 = 0x8;

#[derive(Clone, Debug)]
pub struct InternalProxy {
    state: Arc<State>,
}

#[derive(Debug)]
struct State {
    password: String,
    control: Control,
}

impl InternalProxy {
    pub fn new(control: Control) -> Self {
        use rand::Rng;
        let password = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(40)
            .map(char::from)
            .collect();

        let state = State { password, control };

        return InternalProxy {
            state: Arc::new(state),
        };
    }

    pub fn is_reqwest_error_due_to_rejection(err: &reqwest::Error) -> bool {
        if !err.is_connect() {
            return false;
        }

        if let Some(source_err) = err.source() {
            if let Some(hyper_err) = source_err.downcast_ref::<hyper::Error>() {
                // XXX: to_string()
                if hyper_err.is_connect()
                    && hyper_err.to_string() == "error trying to connect: socks connect error: Address type not supported"
                {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_password(&self) -> String {
        self.state.password.clone()
    }

    pub async fn run(self, listener: tokio::net::TcpListener) -> tokio::io::Result<()> {
        log::debug!("InternalProxy#run: started");
        loop {
            let (mut conn, addr) = listener.accept().await?;
            let addr_str = format!("{}", addr);
            log::debug!("InternalProxy#run: got stream");
            let this = self.clone();
            tokio::spawn(async move {
                log::debug!("InternalProxy#run: accepted connection");
                if let Err(e) = this.handle(&mut conn, addr).await {
                    log::error!("InternalProxy: stream({}) got error, {}", addr_str, e);
                    if let Err(e) = conn.shutdown().await {
                        log::error!(
                            "InternalProxy: stream({}) got error while shutdown, {}",
                            addr_str,
                            e
                        );
                    };
                }
            });
        }
    }

    async fn handle(
        &self,
        conn: &mut tokio::net::TcpStream,
        addr: std::net::SocketAddr,
    ) -> tokio::io::Result<()> {
        let handshake = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.handshake(conn, addr),
        )
        .await?;
        match handshake {
            Ok(Some(peer)) => {
                do_proxy(conn, peer).await?;
            }
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        return Ok(());
    }

    async fn handshake(
        &self,
        stream: &mut tokio::net::TcpStream,
        addr: std::net::SocketAddr,
    ) -> tokio::io::Result<Option<tokio::net::TcpStream>> {
        {
            // Read handshake (ver, nauths, method*)
            let mut ver = [0u8];
            stream.read_exact(&mut ver).await?;
            if ver[0] != VERSION {
                log::warn!(
                    "InternalProxy#handshake: {} attempted to handshake with unknown version ({:x?})",
                    addr,
                    ver
                );
                todo!();
            }

            let mut nauth = [0u8];
            stream.read_exact(&mut nauth).await?;
            let mut meths = vec![0u8; nauth[0] as usize];
            stream.read_exact(&mut meths).await?;
            if !meths.contains(&AUTH_PASSWORD) {
                log::warn!(
                    "InternalProxy#handshake: {} attempted to handshake with unsupported auth (nauth={:x?}, meths={:x?})",
                    addr,
                    nauth,
                    meths
                );
                todo!();
            }

            // Request User/Password authentication
            stream.write_all(&[VERSION, AUTH_PASSWORD]).await?;
        }

        {
            // Read User/Password
            let mut ver = [0u8];
            stream.read_exact(&mut ver).await?;
            if ver[0] != AUTH_VERSION {
                log::warn!("InternalProxy#handshake: {} attempted to authenticate with unknown version ({:x?})", addr, ver);
                todo!();
            }

            let mut len = [0u8];
            stream.read_exact(&mut len).await?;
            let mut login_buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut login_buf).await?;
            stream.read_exact(&mut len).await?;
            let mut password_buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut password_buf).await?;

            if login_buf != LOGIN.as_bytes()
                || !constant_time_eq::constant_time_eq(
                    self.state.password.as_bytes(),
                    &password_buf,
                )
            {
                log::warn!(
                    "InternalProxy#handshake: {} attempted to login but failed (wrong password)",
                    addr
                );
                return tokio::io::Result::Ok(None);
            }

            // Response authenticated
            stream.write_all(&[AUTH_VERSION, AUTH_OK]).await?;
        }

        let peer_addr = {
            // Read CONNECT request
            let mut ver = [0u8];
            stream.read_exact(&mut ver).await?;
            if ver[0] != VERSION {
                log::warn!("InternalProxy#handshake: {} attempted to request something with unknown version ({:x?})", addr, ver);
                todo!();
            }
            let mut cmd = [0u8];
            stream.read_exact(&mut cmd).await?;
            if cmd[0] != CMD_STREAM {
                log::warn!(
                    "InternalProxy#handshake: {} attempted to request unsupported command ({:x?})",
                    addr,
                    cmd
                );
                todo!();
            }

            let mut rsv = [0u8];
            stream.read_exact(&mut rsv).await?;

            let mut addrtype = [0u8];
            stream.read_exact(&mut addrtype).await?;

            let dstaddr = match addrtype[0] {
                ADDRTYPE_IPV4 => {
                    let mut bytes = [0u8; 4];
                    stream.read_exact(&mut bytes).await?;
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(bytes))
                }
                ADDRTYPE_IPV6 => {
                    let mut bytes = [0u8; 16];
                    stream.read_exact(&mut bytes).await?;
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
                }
                _ => {
                    log::warn!("InternalProxy#handshake: {} attempted to request unsupported addrtype ({:x?})", addr, addrtype);
                    todo!();
                }
            };

            let mut portbytes = [0u8; 2];
            stream.read_exact(&mut portbytes).await?;

            std::net::SocketAddr::from((dstaddr, u16::from_be_bytes(portbytes)))
        };

        log::debug!(
            "InternalProxy#handshake: {} wants to connect {}",
            addr,
            peer_addr
        );

        match self
            .state
            .control
            .decide(ControlRequest { address: peer_addr })
        {
            ControlAction::Permit => {}
            ControlAction::Deny => {
                log::warn!(
                    "InternalProxy#handshake: {} => {}, connection decided to reject",
                    addr,
                    peer_addr,
                );
                let (atyp, addrlen) = match peer_addr {
                    std::net::SocketAddr::V4(_) => (ADDRTYPE_IPV4, 4),
                    std::net::SocketAddr::V6(_) => (ADDRTYPE_IPV6, 16),
                };
                let mut replybuf = [0u8; 22];
                replybuf[0] = VERSION;
                replybuf[1] = REPLY_ADDRTYPE_UNSUPPORTED;
                replybuf[3] = atyp;
                stream.write_all(&replybuf[0..(4 + 2 + addrlen)]).await?;
                stream.shutdown().await?;

                return Ok(None);
            }
        }

        match tokio::net::TcpStream::connect(&peer_addr).await {
            Ok(peer_conn) => {
                let mut replybuf = [0u8; 22];
                replybuf[0] = VERSION;
                replybuf[1] = REPLY_OK;
                match peer_conn.local_addr().unwrap() {
                    std::net::SocketAddr::V4(v4) => {
                        replybuf[3] = ADDRTYPE_IPV4;
                        replybuf[4..(4 + 4)].copy_from_slice(&v4.ip().octets());
                        replybuf[(4 + 4)..(4 + 4 + 2)].copy_from_slice(&v4.port().to_be_bytes());
                        stream.write_all(&replybuf[0..(4 + 4 + 2)]).await?;
                    }
                    std::net::SocketAddr::V6(v6) => {
                        replybuf[3] = ADDRTYPE_IPV6;
                        replybuf[4..(4 + 16)].copy_from_slice(&v6.ip().octets());
                        replybuf[(4 + 16)..(4 + 16 + 2)].copy_from_slice(&v6.port().to_be_bytes());
                        stream.write_all(&replybuf[0..(4 + 16 + 2)]).await?;
                    }
                }
                return Ok(Some(peer_conn));
            }
            Err(e) => {
                log::warn!(
                    "InternalProxy#handshake: {} => {}, connection failure, {}",
                    addr,
                    peer_addr,
                    e
                );
                let (atyp, addrlen) = match peer_addr {
                    std::net::SocketAddr::V4(_) => (ADDRTYPE_IPV4, 4),
                    std::net::SocketAddr::V6(_) => (ADDRTYPE_IPV6, 16),
                };
                let mut replybuf = [0u8; 22];
                replybuf[0] = VERSION;
                replybuf[1] = REPLY_FAIL;
                replybuf[3] = atyp;
                stream.write_all(&replybuf[0..(4 + 2 + addrlen)]).await?;
                stream.shutdown().await?;
                return Ok(None);
            }
        }
    }
}

async fn do_proxy(
    client: &mut tokio::net::TcpStream,
    mut peer: tokio::net::TcpStream,
) -> tokio::io::Result<()> {
    tokio::io::copy_bidirectional(client, &mut peer).await?;
    return Ok(());
}

#[derive(Debug)]
pub struct Control {
    inner: ControlKind,
}

impl Control {
    pub fn permit_all() -> Self {
        Self {
            inner: ControlKind::PermitAll,
        }
    }

    pub fn permit_public() -> Self {
        Self {
            inner: ControlKind::PermitPublic,
        }
    }

    pub fn decide(&self, request: ControlRequest) -> ControlAction {
        match self.inner {
            ControlKind::PermitAll => ControlAction::Permit,
            ControlKind::PermitPublic => self.permit_if_public(&request),
        }
    }

    fn permit_if_public(&self, request: &ControlRequest) -> ControlAction {
        match request.address {
            std::net::SocketAddr::V4(a) => {
                log::debug!("permit_if_public: ipv4addr={}", a);
                if global_ip::ipv4addr_is_global(a.ip()) {
                    return ControlAction::Permit;
                }
            }
            std::net::SocketAddr::V6(a) => {
                log::debug!("permit_if_public: ipv6addr={}", a);
                if global_ip::ipv6addr_is_global(a.ip()) {
                    return ControlAction::Permit;
                }
            }
        }
        log::debug!("permit_if_public: a={}, deny", request.address);
        ControlAction::Deny
    }
}

#[derive(Debug)]
pub enum ControlKind {
    PermitAll,
    PermitPublic,
}

#[derive(Debug)]
pub struct ControlRequest {
    address: std::net::SocketAddr,
}

#[derive(Debug)]
pub enum ControlAction {
    Permit,
    Deny,
}

// ------

#[cfg(test)]
mod tests {
    use super::*;

    struct TestInternalProxy {
        url: reqwest::Url,
    }

    impl TestInternalProxy {
        async fn spawn(control: Control) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();

            let proxy = InternalProxy::new(control);

            let mut url = reqwest::Url::parse("socks5://localhost:0").unwrap();
            url.set_ip_host(address.ip()).unwrap();
            url.set_port(Some(address.port())).unwrap();
            url.set_username(LOGIN).unwrap();
            url.set_password(Some(proxy.get_password().as_str()))
                .unwrap();

            log::trace!("TestInternalProxy: url={}", url);

            tokio::spawn(async move {
                proxy.run(listener).await.unwrap();
                log::debug!("TestInternalProxy: shutdown");
            });

            Self { url }
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn build_reqwest_client(proxy_url: reqwest::Url) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .proxy(reqwest::Proxy::all(proxy_url).unwrap())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_normal() {
        init();
        let _m = mockito::mock("GET", "/hello")
            .with_status(200)
            .with_body("Hello\n")
            .create();

        let server = TestInternalProxy::spawn(Control::permit_all()).await;
        let client = build_reqwest_client(server.url.clone());

        let resp = client
            .get(
                reqwest::Url::parse(mockito::server_url().as_ref())
                    .unwrap()
                    .join("/hello")
                    .unwrap(),
            )
            .send()
            .await;

        assert_eq!(resp.is_ok(), true);
        let resp = resp.unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_reject_internal() {
        init();
        let _m = mockito::mock("GET", "/hello")
            .with_status(200)
            .with_body("Hello\n")
            .create();

        let server = TestInternalProxy::spawn(Control::permit_public()).await;
        let client = build_reqwest_client(server.url.clone());

        let resp = client
            .get(
                reqwest::Url::parse(mockito::server_url().as_ref())
                    .unwrap()
                    .join("/hello")
                    .unwrap(),
            )
            .send()
            .await;

        assert_eq!(resp.is_err(), true);
        assert_eq!(
            InternalProxy::is_reqwest_error_due_to_rejection(&resp.err().unwrap()),
            true
        );
    }
}
