use std::{env, io::Write, str::FromStr, time::Duration};

use jiff::{tz::TimeZone, Zoned};
use reqwest::{
    blocking::{Client, ClientBuilder, Request, Response},
    header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, USER_AGENT},
    Method, Url, Version,
};
use termcolor::{BufferedStandardStream, ColorChoice};

use crate::{
    aws_sigv4,
    error::Error,
    fetch::{Verbosity, IS_STDERR_TTY},
    format::format_request,
    Cli, Http, APP_STRING,
};

static DEFAULT_CONNECT_TIMEOUT_MS: u64 = 30_000;

pub(crate) fn make_request(opts: &Cli, verbosity: Verbosity) -> Result<Option<Response>, Error> {
    let url = parse_url(&opts.url)?;
    let method = parse_method(opts.method.as_deref())?;
    let headers = parse_headers(&opts.header)?;
    let query = parse_query(&opts.query);

    let mut builder = ClientBuilder::new()
        .use_rustls_tls()
        .connect_timeout(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS));
    if let Some(duration) = opts.timeout {
        builder = builder.timeout(Some(duration.into()));
    }
    if let Some(v) = opts.http {
        builder = match v {
            Http::One => builder.http1_only(),
            Http::Two => builder.http2_prior_knowledge(),
            // Http::Three => builder.http3_prior_knowledge(),
        }
    }

    let client = builder.build()?;
    let req = build_request(
        &client,
        method.clone(),
        url.clone(),
        headers,
        query,
        opts.aws_sigv4.as_deref(),
        opts.http.as_deref(),
    )?;

    if verbosity > Verbosity::Verbose || opts.dry_run {
        let choice = if *IS_STDERR_TTY {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        };
        let mut stderr = BufferedStandardStream::stderr(choice);
        format_request(&mut stderr, &req)?;
        if opts.dry_run {
            return Ok(None);
        } else {
            writeln!(&mut stderr)?;
        }
    }

    client.execute(req).map(Some).map_err(Into::into)
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

fn build_request(
    client: &Client,
    method: Method,
    url: Url,
    headers: HeaderMap,
    query: Vec<(&str, &str)>,
    sigv4: Option<&str>,
    http_version: Option<&Http>,
) -> Result<Request, Error> {
    let mut req = client
        .request(method.clone(), url.clone())
        .header(ACCEPT, "*/*")
        .header(USER_AGENT, APP_STRING)
        .headers(headers)
        .query(&query)
        .build()?;

    if let Some(sigv4) = sigv4 {
        sign_aws_sigv4(sigv4, &mut req)?;
    }

    if let Some(version) = http_version {
        *req.version_mut() = match version {
            Http::One => Version::HTTP_11,
            Http::Two => Version::HTTP_2,
            // Http::Three => Version::HTTP_3,
        };
    }

    Ok(req)
}

fn sign_aws_sigv4(opts: &str, req: &mut Request) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
    use reqwest::{blocking::Client, header::HeaderMap, Method};
    use url::Url;

    use crate::http::parse_query;

    use super::{build_request, parse_url};

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

    #[test]
    fn test_build_request() {
        let req = build_request(
            &Client::new(),
            Method::GET,
            Url::parse("https://example.com/path?first=value").unwrap(),
            HeaderMap::new(),
            parse_query(&[
                "key3=".to_string(),
                "key1=val1".to_string(),
                "key2".to_string(),
            ]),
            None,
            None,
        )
        .expect("no error");
        assert_eq!(
            req.url().query().expect("not None"),
            "first=value&key3=&key1=val1&key2="
        )
    }
}
