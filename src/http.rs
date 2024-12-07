use std::{
    env,
    io::{self, BufReader, Read},
    str::FromStr,
    time::Duration,
};

use flate2::bufread::{DeflateDecoder, GzDecoder};
use jiff::{tz::TimeZone, Zoned};
use reqwest::{
    blocking::{self, Client, ClientBuilder},
    header::{
        HeaderMap, HeaderName, HeaderValue, ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING,
        CONTENT_LENGTH, USER_AGENT,
    },
    Method, Proxy, StatusCode, Url, Version,
};

use crate::{aws_sigv4, body::Body, error::Error, Http};

static DEFAULT_CONNECT_TIMEOUT_MS: u64 = 60_000;
static APP_STRING: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[derive(Copy, Clone, Debug)]
enum ContentEncoding {
    None,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl From<&str> for ContentEncoding {
    fn from(value: &str) -> Self {
        [
            ("gzip", Self::Gzip),
            ("deflate", Self::Deflate),
            ("br", Self::Brotli),
            ("zstd", Self::Zstd),
        ]
        .into_iter()
        .find_map(|(v, c)| {
            if value.eq_ignore_ascii_case(v) {
                Some(c)
            } else {
                None
            }
        })
        .unwrap_or(Self::None)
    }
}

pub(crate) struct RequestBuilder<'a> {
    url: &'a str,
    basic: Option<&'a str>,
    bearer: Option<&'a str>,
    body: Option<Body>,
    content_type: Option<&'a str>,
    method: Option<&'a str>,
    multipart: Option<blocking::multipart::Form>,
    headers: &'a [String],
    proxy: Option<&'a str>,
    query: &'a [String],
    timeout: Option<Duration>,
    version: Option<Http>,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(url: &'a str) -> Self {
        Self {
            url,
            basic: None,
            bearer: None,
            body: None,
            content_type: None,
            method: None,
            multipart: None,
            headers: &[],
            proxy: None,
            query: &[],
            timeout: None,
            version: None,
        }
    }

    pub(crate) fn with_method(mut self, method: Option<&'a str>) -> Self {
        self.method = method;
        self
    }

    pub(crate) fn with_headers(mut self, headers: &'a [String]) -> Self {
        self.headers = headers;
        self
    }

    pub(crate) fn with_query(mut self, query: &'a [String]) -> Self {
        self.query = query;
        self
    }

    pub(crate) fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub(crate) fn with_version(mut self, version: Option<Http>) -> Self {
        self.version = version;
        self
    }

    pub(crate) fn with_content_type(mut self, content_type: Option<&'a str>) -> Self {
        self.content_type = content_type;
        self
    }

    pub(crate) fn with_body(mut self, body: Option<Body>) -> Self {
        self.body = body;
        self
    }

    pub(crate) fn with_proxy(mut self, proxy: Option<&'a str>) -> Self {
        self.proxy = proxy;
        self
    }

    pub(crate) fn with_bearer(mut self, bearer: Option<&'a str>) -> Self {
        self.bearer = bearer;
        self
    }

    pub(crate) fn with_basic(mut self, basic: Option<&'a str>) -> Self {
        self.basic = basic;
        self
    }

    pub(crate) fn with_multipart(mut self, multipart: Option<blocking::multipart::Form>) -> Self {
        self.multipart = multipart;
        self
    }

    pub(crate) fn build(self) -> Result<Request, Error> {
        // Parse our request dependencies.
        let url = parse_url(self.url)?;
        let method = parse_method(self.method)?;
        let headers = parse_headers(self.headers)?;
        let query = parse_query(self.query);

        // Build the blocking HTTP client.
        let mut builder = ClientBuilder::new()
            .use_rustls_tls()
            .timeout(self.timeout)
            .connect_timeout(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS));
        if let Some(v) = self.version {
            builder = match v {
                Http::One => builder.http1_only(),
                Http::Two => builder.http2_prior_knowledge(),
                // Http::Three => builder.http3_prior_knowledge(),
            }
        }
        if let Some(proxy) = self.proxy {
            builder = builder.proxy(Proxy::all(proxy)?);
        }
        let client = builder.build()?;

        // Build the blocking HTTP request.
        let mut builder = client
            .request(method, url)
            .header(USER_AGENT, APP_STRING)
            .query(&query);

        // Optionally add basic/bearer authentication.
        if let Some(basic) = self.basic {
            let (user, pass) = if let Some((user, pass)) = basic.split_once(':') {
                (user, Some(pass))
            } else {
                (basic, None)
            };
            builder = builder.basic_auth(user, pass);
        }
        if let Some(token) = self.bearer {
            builder = builder.bearer_auth(token);
        }

        // Add multipart form, if provided.
        if let Some(form) = self.multipart {
            builder = builder.multipart(form);
        }

        let mut req = builder.build()?;

        // Set all the relevant headers.
        let req_headers = req.headers_mut();
        req_headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json,image/webp,*/*"),
        );

        let mut encoding_requested = false;
        req_headers.entry(ACCEPT_ENCODING).or_insert_with(|| {
            encoding_requested = true;
            HeaderValue::from_static("gzip, deflate, br, zstd")
        });

        req_headers.insert(USER_AGENT, HeaderValue::from_static(APP_STRING));

        for header in headers.iter() {
            req_headers.insert(header.0, header.1.clone());
        }

        if let Some(content_type) = self.content_type {
            let value = HeaderValue::from_str(content_type).unwrap();
            req_headers.insert("content-type", value);
        }

        // Ensure the appropriate HTTP version is set on the request.
        if let Some(version) = self.version {
            *req.version_mut() = match version {
                Http::One => Version::HTTP_11,
                Http::Two => Version::HTTP_2,
                // Http::Three => Version::HTTP_3,
            };
        }

        if let Some(body) = self.body {
            if let Some(content_length) = body.content_length() {
                req.headers_mut().insert(
                    CONTENT_LENGTH,
                    HeaderValue::from_str(&content_length.to_string()).unwrap(),
                );
            }
            *req.body_mut() = Some(body.into());
        }

        Ok(Request {
            client,
            req,
            encoding_requested,
        })
    }
}

pub(crate) struct Request {
    client: Client,
    req: blocking::Request,
    encoding_requested: bool,
}

impl Request {
    #[allow(dead_code)] // Used in aws-sigv4 testing.
    pub(crate) fn new_test(method: Method, url: Url) -> Self {
        let client = Client::new();
        let req = blocking::Request::new(method, url);
        Self {
            client,
            req,
            encoding_requested: false,
        }
    }

    pub(crate) fn send(self) -> Result<Response, Error> {
        let res = self.client.execute(self.req)?;

        let mut enc = ContentEncoding::None;
        if self.encoding_requested {
            if let Some(encoding) = res.headers().get(CONTENT_ENCODING) {
                if let Ok(encoding) = encoding.to_str() {
                    enc = ContentEncoding::from(encoding);
                }
            }
        }

        Ok(Response { res, enc })
    }

    pub(crate) fn version(&self) -> Version {
        self.req.version()
    }

    pub(crate) fn method(&self) -> &Method {
        self.req.method()
    }

    pub(crate) fn url(&self) -> &Url {
        self.req.url()
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        self.req.headers()
    }

    pub(crate) fn headers_mut(&mut self) -> &mut HeaderMap {
        self.req.headers_mut()
    }

    pub(crate) fn body_mut(&mut self) -> &mut Option<blocking::Body> {
        self.req.body_mut()
    }

    pub(crate) fn sign(&mut self, sigv4: SigV4) -> Result<(), Error> {
        let now = Zoned::now().with_time_zone(TimeZone::UTC);
        aws_sigv4::sign(
            self,
            &sigv4.access_key,
            &sigv4.secret_key,
            &sigv4.region,
            &sigv4.service,
            &now,
        )
    }
}

pub(crate) struct Response {
    res: blocking::Response,
    enc: ContentEncoding,
}

impl Response {
    pub(crate) fn status(&self) -> StatusCode {
        self.res.status()
    }

    pub(crate) fn version(&self) -> Version {
        self.res.version()
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        self.res.headers()
    }

    pub(crate) fn content_length(&self) -> Option<u64> {
        self.res.content_length()
    }

    pub(crate) fn into_reader(self) -> io::Result<impl Read> {
        Decoder::new(self.res, self.enc)
    }
}

fn parse_url(url: &str) -> Result<Url, Error> {
    Url::parse(url)
        .or_else(|err| {
            if matches!(err, url::ParseError::RelativeUrlWithoutBase) {
                Url::parse(&["https://", url.strip_prefix("//").unwrap_or(url)].concat())
            } else {
                Err(err)
            }
        })
        .map_err(Into::into)
        .and_then(|url| {
            if ["http", "https"].contains(&url.scheme()) {
                Ok(url)
            } else {
                let msg = format!("url scheme '{}' not supported", url.scheme());
                Err(Error::new(msg))
            }
        })
}

fn parse_method(input: Option<&str>) -> Result<Method, Error> {
    if let Some(method) = input {
        Method::from_bytes(method.as_bytes())
            .map_err(|_| Error::new(format!("invalid method: {method}")))
    } else {
        Ok(Method::GET)
    }
}

fn parse_headers(headers: &[String]) -> Result<HeaderMap, Error> {
    let mut out = HeaderMap::with_capacity(headers.len());
    for raw in headers {
        if let Some((raw_key, raw_val)) = raw.split_once(":") {
            let key = HeaderName::from_str(raw_key.trim())?;
            let val = HeaderValue::from_str(raw_val.trim())?;
            out.insert(key, val);
        } else {
            let key = HeaderName::from_str(raw.trim())?;
            out.insert(key, HeaderValue::from_static(""));
        }
    }
    Ok(out)
}

fn parse_query(query: &[String]) -> Vec<(&str, &str)> {
    query
        .iter()
        .map(|q| {
            if let Some((key, val)) = q.split_once('=') {
                (key, val)
            } else {
                (q.as_str(), "")
            }
        })
        .collect()
}

pub(crate) struct SigV4 {
    region: String,
    service: String,
    access_key: String,
    secret_key: String,
}

impl SigV4 {
    pub(crate) fn parse(s: &str) -> Result<Self, Error> {
        let (region, service) = match s.split_once('/') {
            None => return Err(Error::new("aws-sigv4: format must be 'REGION/SERVICE'")),
            Some(v) => v,
        };
        let access_key = get_sigv4_var("AWS_ACCESS_KEY_ID")?;
        let secret_key = get_sigv4_var("AWS_SECRET_ACCESS_KEY")?;

        Ok(Self {
            region: region.to_string(),
            service: service.to_string(),
            access_key,
            secret_key,
        })
    }
}

fn get_sigv4_var(key: &str) -> Result<String, Error> {
    env::var(key).map_err(|_| Error::new(format!("aws-sigv4: {key} env var must be set")))
}

enum Decoder<'a, R: Read> {
    Passthrough(R),
    Brotli(Box<brotli::Decompressor<R>>),
    Deflate(Box<DeflateDecoder<BufReader<R>>>),
    Gzip(Box<GzDecoder<BufReader<R>>>),
    Zstd(Box<zstd::Decoder<'a, BufReader<R>>>),
}

impl<R: Read> Decoder<'_, R> {
    fn new(r: R, ct: ContentEncoding) -> io::Result<Self> {
        Ok(match ct {
            ContentEncoding::None => Self::Passthrough(r),
            ContentEncoding::Gzip => Self::Gzip(Box::new(GzDecoder::new(
                BufReader::with_capacity(1 << 14, r),
            ))),
            ContentEncoding::Deflate => Self::Deflate(Box::new(DeflateDecoder::new(
                BufReader::with_capacity(1 << 14, r),
            ))),
            ContentEncoding::Brotli => {
                Self::Brotli(Box::new(brotli::Decompressor::new(r, 1 << 14)))
            }
            ContentEncoding::Zstd => Self::Zstd(Box::new(zstd::Decoder::with_buffer(
                BufReader::with_capacity(1 << 14, r),
            )?)),
        })
    }
}

impl<R: Read> Read for Decoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Decoder::Passthrough(r) => r.read(buf),
            Decoder::Brotli(r) => r.read(buf),
            Decoder::Deflate(r) => r.read(buf),
            Decoder::Gzip(r) => r.read(buf),
            Decoder::Zstd(r) => r.read(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_url;

    #[test]
    fn test_parse_url() {
        let url = parse_url("http://example.com").expect("no error");
        assert_eq!(url.as_str(), "http://example.com/");

        let url = parse_url("https://example.com").expect("no error");
        assert_eq!(url.as_str(), "https://example.com/");

        let url = parse_url("//example.com").expect("no error");
        assert_eq!(url.as_str(), "https://example.com/");

        let url = parse_url("example.com").expect("no error");
        assert_eq!(url.as_str(), "https://example.com/");
    }

    // #[test]
    // fn test_build_request() {
    //     let req = Request::new()
    //     let req = build_http_request(
    //         &Client::new(),
    //         Method::GET,
    //         Url::parse("https://example.com/path?first=value").unwrap(),
    //         HeaderMap::new(),
    //         parse_query(&[
    //             "key3=".to_string(),
    //             "key1=val1".to_string(),
    //             "key2".to_string(),
    //         ]),
    //         None,
    //         None,
    //     )
    //     .expect("no error");
    //     assert_eq!(
    //         req.url().query().expect("not None"),
    //         "first=value&key3=&key1=val1&key2="
    //     )
    // }
}
