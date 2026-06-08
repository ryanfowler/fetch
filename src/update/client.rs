use std::time::{Duration, Instant};

use http::header::{ACCEPT, CONTENT_LENGTH, LOCATION, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::cli::Cli;
use crate::core;
use crate::duration::{TimeoutBudget, duration_from_seconds};
use crate::error::FetchError;
use crate::http::{client, transport};

const INTERNAL_UPDATE_URL_ENV: &str = "FETCH_INTERNAL_UPDATE_URL";

#[derive(Debug, Deserialize)]
pub(super) struct Release {
    pub(super) tag_name: String,
    pub(super) assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Asset {
    pub(super) name: String,
    pub(super) browser_download_url: String,
}

pub(super) struct UpdateClient<'a> {
    cli: Option<&'a Cli>,
    pub(super) timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    allow_insecure_http: bool,
    client: Mutex<Option<UpdateCachedClient>>,
}

#[derive(Clone)]
struct UpdateCachedClient {
    origin: String,
    client: client::UrlClient,
}

pub(super) async fn latest_release(client: &UpdateClient<'_>) -> Result<Release, FetchError> {
    let url = format!(
        "{}/repos/ryanfowler/fetch/releases/latest",
        update_url().trim_end_matches('/')
    );
    let response = update_get(client, &url).await?;
    if !response.status().is_success() {
        return Err(format!(
            "unable to fetch the latest release: received status: {}",
            response.status().as_u16()
        )
        .into());
    }
    let release: Release = serde_json::from_slice(response.body())
        .map_err(|err| FetchError::Message(format!("unable to fetch the latest release: {err}")))?;
    if release.tag_name.is_empty() {
        return Err("unable to fetch the latest release: no tag found".into());
    }
    Ok(release)
}

pub(super) async fn update_get(
    client: &UpdateClient<'_>,
    url: &str,
) -> Result<UpdateResponse, FetchError> {
    client.get(url).await
}

pub(super) async fn update_get_stream(
    client: &UpdateClient<'_>,
    url: &str,
) -> Result<UpdateStreamingResponse, FetchError> {
    client.get_stream(url).await
}

impl<'a> UpdateClient<'a> {
    pub(super) fn new(cli: &'a Cli) -> Result<Self, FetchError> {
        let timeout = cli
            .timeout
            .map(|seconds| duration_from_seconds("timeout", seconds))
            .transpose()?;
        let connect_timeout = cli
            .connect_timeout
            .map(|seconds| duration_from_seconds("connect-timeout", seconds))
            .transpose()?;
        Ok(Self {
            cli: Some(cli),
            timeout,
            connect_timeout,
            allow_insecure_http: internal_update_url_override_allows_insecure_http(),
            client: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(super) fn test(timeout: Option<Duration>) -> Self {
        Self {
            cli: None,
            timeout,
            connect_timeout: None,
            allow_insecure_http: false,
            client: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(super) fn test_allow_insecure_http(timeout: Option<Duration>) -> Self {
        Self {
            cli: None,
            timeout,
            connect_timeout: None,
            allow_insecure_http: true,
            client: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(super) fn test_with_cli_allow_insecure_http(
        cli: &'a Cli,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            cli: Some(cli),
            timeout,
            connect_timeout: None,
            allow_insecure_http: true,
            client: Mutex::new(None),
        }
    }

    async fn get(&self, raw_url: &str) -> Result<UpdateResponse, FetchError> {
        self.get_stream(raw_url).await?.into_buffered().await
    }

    async fn get_stream(&self, raw_url: &str) -> Result<UpdateStreamingResponse, FetchError> {
        let mut url = url::Url::parse(raw_url)?;
        validate_update_url(&url, self.allow_insecure_http)?;
        let request_start = Instant::now();
        let budget = TimeoutBudget::started_at(self.timeout, request_start);
        let mut redirects = 0usize;
        loop {
            let client = budget
                .run(Box::pin(async { self.client_for_url(&url).await }))
                .await?;
            let headers = update_headers();
            let mut request = client
                .client
                .request(Method::GET, url.clone())
                .headers(headers);
            if let Some(timeout) = budget.remaining()? {
                request = request.timeout(timeout);
            }
            let response = budget
                .run(Box::pin(async move {
                    request.send().await.map_err(FetchError::from)
                }))
                .await?;
            if !is_update_redirect(response.status()) {
                return Ok(UpdateStreamingResponse { response, budget });
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    FetchError::Runtime("redirect response missing Location".to_string())
                })?;
            if redirects >= 10 {
                return Err(FetchError::Runtime(
                    "exceeded maximum number of redirects: 10".to_string(),
                ));
            }
            url = update_redirect_target(&url, location, self.allow_insecure_http)?;
            redirects += 1;
        }
    }

    async fn client_for_url(&self, url: &url::Url) -> Result<client::UrlClient, FetchError> {
        let origin = update_client_origin(url)?;
        {
            let cache = self.client.lock().await;
            if let Some(cached) = cache.as_ref().filter(|cached| cached.origin == origin) {
                return Ok(cached.client.clone());
            }
        }

        let client = self.build_client_for_url(url).await?;
        let mut cache = self.client.lock().await;
        if let Some(cached) = cache.as_ref().filter(|cached| cached.origin == origin) {
            return Ok(cached.client.clone());
        }
        *cache = Some(UpdateCachedClient {
            origin,
            client: client.clone(),
        });
        Ok(client)
    }

    async fn build_client_for_url(&self, url: &url::Url) -> Result<client::UrlClient, FetchError> {
        let Some(cli) = self.cli else {
            let mut builder = transport::Client::builder()
                .use_rustls_tls()
                .no_brotli()
                .no_gzip()
                .no_zstd();
            if let Some(timeout) = self.connect_timeout {
                builder = builder.connect_timeout(timeout);
            }
            return Ok(client::UrlClient {
                client: builder.build()?,
                dns_resolution: None,
            });
        };

        let context = client::ClientBuildContext {
            mode: client::ClientMode::Request(None),
            request_timeout: None,
            connect_timeout: self.connect_timeout,
            request_start: Instant::now(),
            session: None,
            connect_timing: None,
        };
        client::build_client_for_url(cli, url, &context).await
    }
}

fn validate_update_url(url: &url::Url, allow_insecure_http: bool) -> Result<(), FetchError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure_http => Ok(()),
        "http" => Err(FetchError::Message(
            "refusing insecure self-update URL: self-update downloads require HTTPS".to_string(),
        )),
        scheme => Err(FetchError::Message(format!(
            "unsupported self-update URL scheme '{scheme}': self-update downloads require HTTPS"
        ))),
    }
}

fn update_redirect_target(
    current_url: &url::Url,
    location: &str,
    allow_insecure_http: bool,
) -> Result<url::Url, FetchError> {
    let url = current_url
        .join(location)
        .map_err(|err| FetchError::Runtime(format!("invalid redirect location: {err}")))?;
    validate_update_url(&url, allow_insecure_http)?;
    Ok(url)
}

fn update_client_origin(url: &url::Url) -> Result<String, FetchError> {
    let authority = crate::net::url_authority(url)?;
    Ok(format!("{}://{authority}", url.scheme()))
}

fn update_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&core::user_agent()).expect("valid user agent"),
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(core::DEFAULT_ACCEPT_HEADER),
    );
    headers
}

fn is_update_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

#[derive(Debug)]
pub(super) struct UpdateResponse {
    status: StatusCode,
    body: bytes::Bytes,
}

impl UpdateResponse {
    pub(super) fn status(&self) -> StatusCode {
        self.status
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }
}

pub(super) struct UpdateStreamingResponse {
    pub(super) response: transport::Response,
    pub(super) budget: TimeoutBudget,
}

impl UpdateStreamingResponse {
    pub(super) fn status(&self) -> StatusCode {
        self.response.status()
    }

    pub(super) fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    pub(super) fn content_length(&self) -> Option<u64> {
        content_length(self.headers())
    }

    pub(super) async fn into_buffered(self) -> Result<UpdateResponse, FetchError> {
        self.into_buffered_with_limit(None, "response body exceeded maximum allowed size")
            .await
    }

    pub(super) async fn into_buffered_with_limit(
        self,
        max_body_bytes: Option<u64>,
        limit_error: &'static str,
    ) -> Result<UpdateResponse, FetchError> {
        let budget = self.budget;
        let status = self.response.status();
        let headers = self.response.headers().clone();
        let (mut body, _) = self.response.into_body_with_deadline();
        let capacity = content_length(&headers)
            .map(|len| max_body_bytes.map_or(len, |max| len.min(max)))
            .and_then(|len| usize::try_from(len).ok())
            .unwrap_or(0);
        let mut bytes = Vec::with_capacity(capacity);
        while let Some(frame) = budget
            .run(Box::pin(async {
                match body.frame().await {
                    Some(Ok(frame)) => Ok(Some(frame)),
                    Some(Err(err)) => {
                        Err(FetchError::Runtime(format!("response body error: {err}")))
                    }
                    None => Ok(None),
                }
            }))
            .await?
        {
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            if let Some(max) = max_body_bytes {
                let current = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                let chunk = u64::try_from(data.len()).unwrap_or(u64::MAX);
                if current.saturating_add(chunk) > max {
                    return Err(limit_error.into());
                }
            }
            bytes.extend_from_slice(&data);
        }
        Ok(UpdateResponse {
            status,
            body: bytes::Bytes::from(bytes),
        })
    }
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn update_url() -> String {
    internal_update_url_override().unwrap_or_else(|| "https://api.github.com".to_string())
}

fn internal_update_url_override() -> Option<String> {
    std::env::var(INTERNAL_UPDATE_URL_ENV).ok()
}

fn internal_update_url_override_allows_insecure_http() -> bool {
    internal_update_url_override()
        .is_some_and(|raw_url| url::Url::parse(&raw_url).is_ok_and(|url| url.scheme() == "http"))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        start_artifact_response, start_slow_redirect_response, start_update_proxy,
    };
    use super::*;
    use http::StatusCode;
    use std::time::Duration;

    #[test]
    fn update_requests_use_go_client_headers() {
        let headers = update_headers();

        assert_eq!(
            headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            Some(core::user_agent().as_str())
        );
        assert_eq!(
            headers.get(ACCEPT).and_then(|v| v.to_str().ok()),
            Some(core::DEFAULT_ACCEPT_HEADER)
        );
    }

    #[test]
    fn update_client_origin_keys_default_ports_and_ipv6_hosts() {
        let url = url::Url::parse("https://example.com/releases/latest").unwrap();
        assert_eq!(
            update_client_origin(&url).unwrap(),
            "https://example.com:443"
        );

        let url = url::Url::parse("http://[::1]/artifact").unwrap();
        assert_eq!(update_client_origin(&url).unwrap(), "http://[::1]:80");
    }

    #[test]
    fn update_redirect_target_rejects_https_to_http_by_default() {
        let url = url::Url::parse("https://updates.example/start").unwrap();

        let err =
            update_redirect_target(&url, "http://updates.example/artifact", false).unwrap_err();

        assert!(
            err.to_string()
                .contains("self-update downloads require HTTPS"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn update_client_rejects_initial_http_by_default() {
        let client = UpdateClient::test(None);

        let err = update_get(&client, "http://127.0.0.1:1/artifact")
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("self-update downloads require HTTPS"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn update_client_internal_test_override_allows_local_http_fixture() {
        let (url, join) = start_artifact_response(
            vec![("Content-Length", "2".to_string())],
            vec![b"ok".to_vec()],
        );
        let client = UpdateClient::test_allow_insecure_http(None);

        let response = update_get(&client, &url).await.unwrap();
        join.join().unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"ok");
    }

    #[tokio::test]
    async fn update_client_uses_shared_proxy_config() {
        let (proxy_url, join) = start_update_proxy("proxied update");
        let cli =
            <Cli as clap::Parser>::try_parse_from(["fetch", "--update", "--proxy", &proxy_url])
                .unwrap();
        let client = UpdateClient::test_with_cli_allow_insecure_http(&cli, None);

        let response = update_get(&client, "http://updates.example/artifact")
            .await
            .unwrap();
        let request_line = join.join().unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"proxied update");
        assert!(
            request_line.starts_with("GET http://updates.example/artifact HTTP/1.1"),
            "{request_line}"
        );
    }

    #[tokio::test]
    async fn update_redirects_share_one_request_timeout_budget() {
        let (url, join) =
            start_slow_redirect_response(Duration::from_millis(150), Duration::from_millis(150));
        let client = UpdateClient::test_allow_insecure_http(Some(Duration::from_millis(220)));

        let err = update_get(&client, &url).await.unwrap_err();
        let _ = join.join();

        assert!(
            err.to_string().contains("request timed out after 220ms"),
            "{err}"
        );
    }
}
