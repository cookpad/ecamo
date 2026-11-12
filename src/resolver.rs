use std::net::SocketAddr;

// reqwest's SOCKS connector tries only the first resolved address, and our tasks may lack IPv6 routes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ipv4FirstResolver;

impl reqwest::dns::Resolve for Ipv4FirstResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let mut addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            addrs.sort_by_key(SocketAddr::is_ipv6);
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
