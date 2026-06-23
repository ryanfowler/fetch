use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use http::header::HeaderValue;
use hyper_util::client::proxy::matcher;
#[cfg(unix)]
use tokio::net::UnixStream;
use url::Url;

use super::client::{ClientConfig, connect_direct_tcp_config, record_dns_trace};
use super::{Error, ErrorKind};
use crate::duration::TimeoutBudget;
use crate::error::FetchError;

pub(super) async fn dial_stream_for_config(
    config: &ClientConfig,
    url: &Url,
    proxy: Option<&Proxy>,
    timeout: TimeoutBudget,
) -> Result<
    (
        crate::net::DialStream,
        bool,
        bool,
        Option<SocketAddr>,
        Option<Duration>,
    ),
    Error,
> {
    match proxy {
        Some(proxy) if proxy.is_http_proxy() && url.scheme() == "http" => {
            let proxy_url = crate::net::parse_proxy_url(&proxy.url)
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let stream =
                crate::net::dial_http_proxy_stream_with_tls(&proxy.url, &proxy_url, timeout, None)
                    .await
                    .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            Ok((stream, true, true, None, None))
        }
        Some(proxy) if proxy.is_http_proxy() => {
            let proxy_url = crate::net::parse_proxy_url(&proxy.url)
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let proxy_authorization = proxy
                .basic_auth()
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let stream = crate::net::dial_http_proxy_tunnel(
                &proxy.url,
                &proxy_url,
                url,
                timeout,
                None,
                proxy_authorization,
            )
            .await
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            Ok((stream, false, true, None, None))
        }
        Some(proxy)
            if proxy.scheme().is_ok_and(|scheme| scheme == "socks5")
                && target_override_addrs(config, url).is_some() =>
        {
            let proxy_url = crate::net::parse_proxy_url(&proxy.url)
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            let addrs = target_override_addrs(config, url).expect("checked above");
            dial_socks5_proxy_to_addrs(&proxy_url, addrs, timeout)
                .await
                .map(|stream| (stream, false, true, None, None))
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))
        }
        Some(proxy) => crate::net::dial_proxy(&proxy.url, url, None, timeout)
            .await
            .map(|stream| (stream, false, true, None, None))
            .map_err(|err| Error::from_fetch(ErrorKind::Connect, err)),
        None if config.unix_socket.is_some() => {
            #[cfg(unix)]
            {
                let path = config.unix_socket.as_deref().expect("unix socket checked");
                UnixStream::connect(path)
                    .await
                    .map(|stream| {
                        (
                            Box::pin(stream) as crate::net::DialStream,
                            false,
                            false,
                            None,
                            None,
                        )
                    })
                    .map_err(|err| Error::with_source(ErrorKind::Connect, err.to_string(), err))
            }
            #[cfg(not(unix))]
            {
                Err(Error::connect("--unix is not supported on this platform"))
            }
        }
        None => {
            let trace = connect_direct_tcp_config(config, url, timeout)
                .await
                .map_err(|err| Error::from_fetch(ErrorKind::Connect, err))?;
            record_dns_trace(config, url, &trace);
            let remote_addr = trace.stream.peer_addr().ok();
            let tcp_duration = trace.tcp_duration;
            Ok((
                Box::pin(trace.stream) as crate::net::DialStream,
                false,
                true,
                remote_addr,
                Some(tcp_duration),
            ))
        }
    }
}

pub(super) fn proxy_for_config(config: &ClientConfig, url: &Url) -> Option<Proxy> {
    config
        .proxies
        .iter()
        .find_map(|proxy| proxy.selected_for(url))
}

fn target_override_addrs(config: &ClientConfig, url: &Url) -> Option<Vec<SocketAddr>> {
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    let mut addrs = config.dns_overrides.get(host)?.clone();
    for addr in &mut addrs {
        addr.set_port(port);
    }
    (!addrs.is_empty()).then_some(addrs)
}

async fn dial_socks5_proxy_to_addrs(
    proxy_url: &Url,
    addrs: Vec<SocketAddr>,
    timeout: TimeoutBudget,
) -> Result<crate::net::DialStream, FetchError> {
    let mut last_err = None;
    for addr in addrs {
        match crate::net::dial_socks5_proxy_to_addr(proxy_url, addr, timeout).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| FetchError::Runtime("lookup returned no addresses".to_string())))
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub(super) url: String,
    kind: ProxyKind,
    no_proxy: Option<NoProxy>,
    basic_auth: Option<HeaderValue>,
}

#[derive(Clone)]
enum ProxyKind {
    All,
    Http,
    Https,
    System(Arc<matcher::Matcher>),
}

impl Proxy {
    pub(crate) fn all(proxy: &str) -> Result<Self, Error> {
        parse_proxy(proxy)?;
        Ok(Self {
            url: proxy.to_string(),
            kind: ProxyKind::All,
            no_proxy: None,
            basic_auth: None,
        })
    }

    pub(crate) fn http(proxy: &str) -> Result<Self, Error> {
        parse_proxy(proxy)?;
        Ok(Self {
            url: proxy.to_string(),
            kind: ProxyKind::Http,
            no_proxy: None,
            basic_auth: None,
        })
    }

    pub(crate) fn https(proxy: &str) -> Result<Self, Error> {
        parse_proxy(proxy)?;
        Ok(Self {
            url: proxy.to_string(),
            kind: ProxyKind::Https,
            no_proxy: None,
            basic_auth: None,
        })
    }

    pub(crate) fn system() -> Self {
        Self {
            url: String::new(),
            kind: ProxyKind::System(Arc::new(matcher::Matcher::from_system())),
            no_proxy: None,
            basic_auth: None,
        }
    }

    pub(crate) fn no_proxy(mut self, no_proxy: NoProxy) -> Self {
        self.no_proxy = Some(no_proxy);
        self
    }

    pub(crate) fn selected_for_url(&self, url: &Url) -> Option<Self> {
        self.selected_for(url)
    }

    pub(crate) fn uses_local_target_dns(&self) -> bool {
        self.scheme().is_ok_and(|scheme| scheme == "socks5")
    }

    fn applies_to(&self, url: &Url) -> bool {
        if self.no_proxy.as_ref().is_some_and(|no_proxy| {
            crate::http::client::no_proxy_matches_url(url, no_proxy.0.as_deref())
        }) {
            return false;
        }
        match &self.kind {
            ProxyKind::All => true,
            ProxyKind::Http => url.scheme() == "http",
            ProxyKind::Https => url.scheme() == "https",
            ProxyKind::System(_) => self.system_selected_for(url).is_some(),
        }
    }

    pub(super) fn selected_for(&self, url: &Url) -> Option<Self> {
        match &self.kind {
            ProxyKind::System(_) => self.system_selected_for(url),
            _ => self.applies_to(url).then(|| self.clone()),
        }
    }

    fn system_selected_for(&self, url: &Url) -> Option<Self> {
        let ProxyKind::System(matcher) = &self.kind else {
            return None;
        };
        let uri = url.as_str().parse::<Uri>().ok()?;
        let intercepted = matcher.intercept(&uri)?;
        let proxy_url = intercepted.uri().to_string();
        let mut proxy = Self::all(&proxy_url).ok()?;
        proxy.basic_auth = intercepted.basic_auth().cloned();
        Some(proxy)
    }

    pub(super) fn is_http_proxy(&self) -> bool {
        crate::net::parse_proxy_url(&self.url)
            .map(|url| matches!(url.scheme(), "http" | "https"))
            .unwrap_or(false)
    }

    fn scheme(&self) -> Result<String, FetchError> {
        crate::net::parse_proxy_url(&self.url).map(|url| url.scheme().to_string())
    }

    pub(super) fn basic_auth(&self) -> Result<Option<String>, FetchError> {
        if let Some(auth) = &self.basic_auth {
            return auth
                .to_str()
                .map(|value| Some(value.to_string()))
                .map_err(|err| FetchError::Message(format!("invalid proxy authorization: {err}")));
        }
        let url = crate::net::parse_proxy_url(&self.url)?;
        crate::net::proxy_basic_auth(&url)
    }
}

fn parse_proxy(proxy: &str) -> Result<(), Error> {
    crate::net::parse_proxy_url(proxy)
        .map(|_| ())
        .map_err(|err| Error::from_fetch(ErrorKind::Request, err))
}

#[derive(Clone)]
pub(crate) struct NoProxy(Option<String>);

impl NoProxy {
    pub(crate) fn from_env() -> Self {
        Self(
            std::env::var("NO_PROXY")
                .or_else(|_| std::env::var("no_proxy"))
                .ok(),
        )
    }
}
