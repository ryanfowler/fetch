use std::{
    borrow::Cow,
    collections::BTreeMap,
    io::{self, Write},
};

use hmac::{
    digest::generic_array::{typenum, GenericArray},
    Hmac, Mac,
};
use jiff::{fmt::strtime, Zoned};
use percent_encoding::percent_encode_byte;
use reqwest::header::HeaderValue;
use sha2::{Digest, Sha256};
use url::form_urlencoded::parse;

use crate::{error::Error, http::Request};

static HDR_CONTENT_SHA256: &str = "x-amz-content-sha256";
static EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

// signs an HTTP request using the AWS signature v4 protocol:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
pub(crate) fn sign(
    req: &mut Request,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    now: &Zoned,
) -> Result<(), Error> {
    let datetime = strtime::format("%Y%m%dT%H%M%SZ", now)?;

    let payload = get_payload_hash(req, service)?;

    let headers = req.headers_mut();
    headers.insert("x-amz-date", HeaderValue::from_str(&datetime).unwrap());
    if service == "s3" {
        headers
            .entry(HDR_CONTENT_SHA256)
            .or_insert_with(|| HeaderValue::from_str(&payload).unwrap());
    }

    let signed_headers = get_signed_headers(req);
    let canonical_req = build_canonical_request(req, &signed_headers, &payload)?;
    let string_to_sign = build_string_to_sign(&datetime, region, service, &canonical_req)?;

    let date = &datetime[..8];
    let signing_key = derive_signing_key(secret_key, date, region, service);

    let signature = hex_encode(hmac_sha256(&signing_key, &string_to_sign));

    let keys = signed_headers
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>()
        .join(";");
    let auth = format!("AWS4-HMAC-SHA256 Credential={access_key}/{date}/{region}/{service}/aws4_request,SignedHeaders={keys},Signature={signature}");
    req.headers_mut()
        .insert("authorization", HeaderValue::from_str(&auth).unwrap());
    Ok(())
}

fn get_payload_hash(req: &mut Request, service: &str) -> Result<String, Error> {
    // Use the value from the x-amz-content-sha256 header, if provided.
    if let Some(content_sha256) = req.headers().get(HDR_CONTENT_SHA256) {
        return Ok(content_sha256.to_str().unwrap_or("").to_string());
    }

    if let Some(body) = req.body_mut() {
        // If we have the body in memory, take the sha256.
        if let Some(bytes) = body.as_bytes() {
            Ok(hex_sha256(bytes))
        } else if service == "s3" {
            // The body is a reader, but the service is "s3". Use the unsigned
            // payload indicator.
            Ok(UNSIGNED_PAYLOAD.to_string())
        } else {
            // Read the body into memory to hash it.
            let bytes = body.buffer()?;
            Ok(hex_sha256(bytes))
        }
    } else {
        // No body, use the empty hash.
        Ok(EMPTY_SHA256.to_string())
    }
}

fn get_signed_headers(req: &Request) -> Vec<(&str, String)> {
    req.headers()
        .iter()
        .filter_map(|(key, val)| match key.as_str() {
            "authorization" | "content-length" | "user-agent" => None,
            _ => val.to_str().ok().map(|v| (key.as_str(), v)),
        })
        .chain(std::iter::once(("host", req.url().authority())))
        .fold(BTreeMap::<&str, String>::new(), |mut map, (key, val)| {
            map.entry(key)
                .and_modify(|v| {
                    *v = [v, val].join(",");
                })
                .or_insert_with(|| val.to_string());
            map
        })
        .into_iter()
        .collect()
}

fn build_canonical_request(
    req: &Request,
    headers: &[(&str, String)],
    payload: &str,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);

    writeln!(&mut out, "{}", req.method().as_str())?;

    let url = req.url();
    write_uri_escaped(&mut out, url.path(), false)?;
    writeln!(&mut out)?;

    if let Some(raw) = url.query() {
        let query = get_query_params(raw.as_bytes());
        for (i, (key, val)) in query.into_iter().enumerate() {
            if i > 0 {
                out.write_all(b"&")?;
            }
            write_uri_escaped(&mut out, &key, true)?;
            out.write_all(b"=")?;
            write_uri_escaped(&mut out, &val, true)?;
        }
    }
    writeln!(&mut out)?;

    for (key, val) in headers {
        writeln!(&mut out, "{key}:{}", val.trim())?;
    }
    writeln!(&mut out)?;

    for (i, (key, _)) in headers.iter().enumerate() {
        if i > 0 {
            out.write_all(b";")?;
        }
        write!(&mut out, "{key}")?;
    }
    writeln!(&mut out)?;

    out.write_all(payload.as_bytes())?;

    Ok(out)
}

fn get_query_params(raw: &[u8]) -> Vec<(Cow<str>, Cow<str>)> {
    let mut query = parse(raw).collect::<Vec<_>>();
    query.sort();
    query
}

fn build_string_to_sign(
    datetime: &str,
    region: &str,
    service: &str,
    can_req: impl AsRef<[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(1024);

    writeln!(&mut out, "AWS4-HMAC-SHA256")?;
    writeln!(&mut out, "{datetime}")?;
    writeln!(
        &mut out,
        "{}/{region}/{service}/aws4_request",
        &datetime[..8]
    )?;
    write_hex_sha256(&mut out, can_req)?;

    Ok(out)
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let date_key = hmac_sha256(["AWS4", secret].concat(), date);
    let date_region_key = hmac_sha256(date_key, region);
    let date_region_service_key = hmac_sha256(date_region_key, service);
    hmac_sha256(date_region_service_key, "aws4_request").to_vec()
}

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> GenericArray<u8, typenum::U32> {
    let mut mac = HmacSha256::new_from_slice(key.as_ref()).unwrap();
    mac.update(data.as_ref());
    mac.finalize().into_bytes()
}

fn write_hex_sha256(w: &mut impl Write, data: impl AsRef<[u8]>) -> io::Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    write_hex(w, hasher.finalize())
}

fn hex_sha256(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(hasher.finalize())
}

fn write_uri_escaped(w: &mut impl Write, v: &str, encode_slash: bool) -> io::Result<()> {
    fn is_valid_byte(b: u8, encode_slash: bool) -> bool {
        matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
            || (b == b'/' && !encode_slash)
    }

    let buf = v.as_bytes();
    let mut n = 0;
    for i in 0..buf.len() {
        if is_valid_byte(buf[i], encode_slash) {
            continue;
        }

        if n < i {
            w.write_all(&buf[n..i])?;
        }
        write!(w, "{}", percent_encode_byte(buf[i]))?;
        n = i + 1;
    }

    if n < buf.len() {
        w.write_all(&buf[n..])?;
    }
    Ok(())
}

fn write_hex(w: &mut impl Write, data: impl AsRef<[u8]>) -> io::Result<()> {
    for &b in data.as_ref() {
        w.write_all(&hex_for_byte(b))?;
    }
    Ok(())
}

fn hex_encode(input: impl AsRef<[u8]>) -> String {
    let input = input.as_ref();
    let mut out = vec![0; input.len() * 2];
    for (i, &b) in input.iter().enumerate() {
        let i = 2 * i;
        [out[i], out[i + 1]] = hex_for_byte(b);
    }
    unsafe { std::string::String::from_utf8_unchecked(out) }
}

#[inline(always)]
fn hex_for_byte(b: u8) -> [u8; 2] {
    static HEX: &[u8; 16] = b"0123456789abcdef";
    [HEX[(b >> 4) as usize], HEX[(b & 0x0F) as usize]]
}

#[cfg(test)]
mod tests {
    use jiff::fmt::rfc2822;
    use reqwest::Method;
    use url::Url;

    use super::*;

    static ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    static SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    #[test]
    fn test_get_signed_headers_dupes() {
        let url = Url::parse("https://test.com/test.txt").expect("no url error");
        let mut req = Request::new_test(Method::GET, url);
        let headers = req.headers_mut();
        headers.append("x-key", HeaderValue::from_static("value1"));
        headers.append("x-key", HeaderValue::from_static("value2"));

        let out = get_signed_headers(&req);
        assert_eq!(
            vec![
                ("host", "test.com".to_string()),
                ("x-key", "value1,value2".to_string())
            ],
            out
        );
    }

    #[test]
    fn test_get_query_params() {
        let raw = "q=2&q=1&key2=val2&key1=val1&key1=val12";
        let params = get_query_params(raw.as_bytes());
        assert_eq!(
            vec![
                (Cow::Borrowed("key1"), Cow::Borrowed("val1")),
                (Cow::Borrowed("key1"), Cow::Borrowed("val12")),
                (Cow::Borrowed("key2"), Cow::Borrowed("val2")),
                (Cow::Borrowed("q"), Cow::Borrowed("1")),
                (Cow::Borrowed("q"), Cow::Borrowed("2"))
            ],
            params
        );
    }

    #[test]
    fn test_sign_get_object() {
        let url =
            Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").expect("no url error");
        let mut req = Request::new_test(Method::GET, url);
        let headers = req.headers_mut();
        headers.insert("range", HeaderValue::from_static("bytes=0-9"));

        let now = rfc2822::parse("Fri, 24 May 2013 00:00:00 GMT").unwrap();
        sign(&mut req, ACCESS_KEY, SECRET_KEY, "us-east-1", "s3", &now).expect("no signing error");

        let auth = req
            .headers()
            .get("authorization")
            .expect("auth header exists")
            .to_str()
            .expect("no str err");
        assert_eq!("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", auth);
    }

    #[test]
    fn test_sign_put_object() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test$file.text")
            .expect("no url error");
        let mut req = Request::new_test(Method::PUT, url);
        let headers = req.headers_mut();
        headers.insert(
            "date",
            HeaderValue::from_static("Fri, 24 May 2013 00:00:00 GMT"),
        );
        headers.insert(
            "x-amz-storage-class",
            HeaderValue::from_static("REDUCED_REDUNDANCY"),
        );
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static(
                "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
            ),
        );

        let now = rfc2822::parse("Fri, 24 May 2013 00:00:00 GMT").unwrap();
        sign(&mut req, ACCESS_KEY, SECRET_KEY, "us-east-1", "s3", &now).expect("no signing error");

        let auth = req
            .headers()
            .get("authorization")
            .expect("auth header exists")
            .to_str()
            .expect("no str err");
        assert_eq!("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd", auth);
    }

    #[test]
    fn test_sign_get_bucket_lifecycle() {
        let url =
            Url::parse("https://examplebucket.s3.amazonaws.com?lifecycle").expect("no url error");
        let mut req = Request::new_test(Method::GET, url);

        let now = rfc2822::parse("Fri, 24 May 2013 00:00:00 GMT").unwrap();
        sign(&mut req, ACCESS_KEY, SECRET_KEY, "us-east-1", "s3", &now).expect("no signing error");

        let auth = req
            .headers()
            .get("authorization")
            .expect("auth header exists")
            .to_str()
            .expect("no str err");
        assert_eq!("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", auth);
    }

    #[test]
    fn test_sign_list_objects() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com?max-keys=2&prefix=J")
            .expect("no url error");
        let mut req = Request::new_test(Method::GET, url);

        let now = rfc2822::parse("Fri, 24 May 2013 00:00:00 GMT").unwrap();
        sign(&mut req, ACCESS_KEY, SECRET_KEY, "us-east-1", "s3", &now).expect("no signing error");

        let auth = req
            .headers()
            .get("authorization")
            .expect("auth header exists")
            .to_str()
            .expect("no str err");
        assert_eq!("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", auth);
    }
}
