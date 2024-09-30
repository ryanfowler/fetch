use std::{
    env,
    io::{self, BufReader, Read},
    str::FromStr,
    time::Duration,
};

use flate2::bufread::GzDecoder;
use jiff::{tz::TimeZone, Zoned};
use reqwest::{
    blocking::{self, Client, ClientBuilder},
    header::{
        HeaderMap, HeaderName, HeaderValue, ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, USER_AGENT,
    },
    Method, StatusCode, Url, Version,
};

use crate::{aws_sigv4, error::Error, Cli, Http};

static DEFAULT_CONNECT_TIMEOUT_MS: u64 = 60_000;
static APP_STRING: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[derive(Copy, Clone, Debug)]
enum ContentEncoding {
    None,
    Gzip,
    Brotli,
    Zstd,
}

impl From<&str> for ContentEncoding {
    fn from(value: &str) -> Self {
        [
            ("gzip", Self::Gzip),
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

pub(crate) struct Request {
    client: Client,
    req: blocking::Request,
    encoding_requested: bool,
}

impl Request {
    pub(crate) fn new(cli: &Cli) -> Result<Self, Error> {
        // Parse our request dependencies.
        let url = parse_url(&cli.url)?;
        let method = parse_method(cli.method.as_deref())?;
        let headers = parse_headers(&cli.header)?;
        let query = parse_query(&cli.query);

        // Build the blocking HTTP client.
        let mut builder = ClientBuilder::new()
            .use_rustls_tls()
            .connect_timeout(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS));
        if let Some(duration) = cli.timeout {
            builder = builder.timeout(Some(duration.into()));
        }
        if let Some(v) = cli.http {
            builder = match v {
                Http::One => builder.http1_only(),
                Http::Two => builder.http2_prior_knowledge(),
                // Http::Three => builder.http3_prior_knowledge(),
            }
        }
        let client = builder.build()?;

        // Build the blocking HTTP request.
        let mut req = client
            .request(method.clone(), url.clone())
            .header(ACCEPT, "*/*")
            .header(USER_AGENT, APP_STRING)
            .headers(headers)
            .query(&query)
            .build()?;

        let mut encoding_requested = false;
        req.headers_mut().entry(ACCEPT_ENCODING).or_insert_with(|| {
            encoding_requested = true;
            HeaderValue::from_static("gzip, br, zstd")
        });

        // Sign the request if necessary.
        if let Some(sigv4) = &cli.aws_sigv4 {
            sign_aws_sigv4(sigv4, &mut req)?;
        }

        // Ensure the appropriate HTTP version is set on the request.
        if let Some(version) = &cli.http {
            *req.version_mut() = match version {
                Http::One => Version::HTTP_11,
                Http::Two => Version::HTTP_2,
                // Http::Three => Version::HTTP_3,
            };
        }

        Ok(Self {
            client,
            req,
            encoding_requested,
        })
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

fn sign_aws_sigv4(opts: &str, req: &mut blocking::Request) -> Result<(), Error> {
    let (region, service) = match opts.split_once(':') {
        None => return Err(Error::new("aws-sigv4: format must be 'REGION:SERVICE'")),
        Some(v) => v,
    };
    let access_key = get_sigv4_var("AWS_ACCESS_KEY_ID")?;
    let secret_key = get_sigv4_var("AWS_SECRET_ACCESS_KEY")?;

    let now = Zoned::now().with_time_zone(TimeZone::UTC);
    aws_sigv4::sign(req, &access_key, &secret_key, region, service, &now)
}

fn get_sigv4_var(key: &str) -> Result<String, Error> {
    env::var(key).map_err(|_| Error::new(format!("aws-sigv4: {key} must be provided")))
}

enum Decoder<'a, R: Read> {
    Passthrough(R),
    Brotli(Box<brotli::Decompressor<R>>),
    Gzip(Box<GzDecoder<BufReader<R>>>),
    Zstd(Box<zstd::Decoder<'a, BufReader<R>>>),
}

impl<'a, R: Read> Decoder<'a, R> {
    fn new(r: R, ct: ContentEncoding) -> io::Result<Self> {
        Ok(match ct {
            ContentEncoding::None => Self::Passthrough(r),
            ContentEncoding::Gzip => Self::Gzip(Box::new(GzDecoder::new(
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

impl<'a, R: Read> Read for Decoder<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Decoder::Passthrough(r) => r.read(buf),
            Decoder::Brotli(r) => r.read(buf),
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
