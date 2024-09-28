use std::{env, io::Write, str::FromStr, time::Duration};

use jiff::{tz::TimeZone, Zoned};
use reqwest::{
    blocking::{Client, ClientBuilder, Request, Response},
    header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, USER_AGENT},
    Method, Url,
};
use termcolor::{BufferedStandardStream, ColorChoice};
use url::ParseError;

use crate::{
    aws_sigv4,
    error::Error,
    fetch::{Verbosity, IS_STDERR_TTY},
    format::format_request,
    Cli, Http, APP_STRING,
};

static SCHEME_HTTP: &str = "http";
static SCHEME_HTTPS: &str = "https";

static DEFAULT_CONNECT_TIMEOUT_MS: u64 = 30_000;
static DEFAULT_TIMEOUT_SECONDS: u64 = 600;

pub(crate) fn make_request(opts: &Cli, verbosity: Verbosity) -> Result<Option<Response>, Error> {
    let (mut url, no_scheme) = parse_url(&opts.url)?;
    let method = parse_method(opts.method.as_deref())?;
    let headers = parse_headers(&opts.header)?;

    let mut builder = ClientBuilder::new()
        .use_rustls_tls()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS))
        .connect_timeout(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS));
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
        opts.aws_sigv4.as_deref(),
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

    match client.execute(req) {
        Ok(res) => Ok(Some(res)),
        Err(err) => {
            if no_scheme && url.set_scheme(SCHEME_HTTP).is_ok() {
                let headers = parse_headers(&opts.header)?;
                let req = build_request(&client, method, url, headers, opts.aws_sigv4.as_deref())?;
                client.execute(req).map(Some).map_err(|e| e.into())
            } else {
                Err(err.into())
            }
        }
    }
}

fn parse_url(url: &str) -> Result<(Url, bool), ParseError> {
    // TODO(ryanfowler): We can do this better.
    if !url.contains("://") {
        let url = Url::parse(&format!("{SCHEME_HTTPS}://{url}"))?;
        Ok((url, true))
    } else {
        let url = Url::parse(url)?;
        Ok((url, false))
    }
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

fn build_request(
    client: &Client,
    method: Method,
    url: Url,
    headers: HeaderMap,
    sigv4: Option<&str>,
) -> Result<Request, Error> {
    let mut req = client
        .request(method.clone(), url.clone())
        .header(ACCEPT, "*/*")
        .header(USER_AGENT, APP_STRING)
        .headers(headers)
        .build()?;

    if let Some(sigv4) = sigv4 {
        sign_aws_sigv4(sigv4, &mut req)?;
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
