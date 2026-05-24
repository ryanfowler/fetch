#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Unknown,
    Css,
    Csv,
    Grpc,
    Html,
    Image,
    Json,
    Markdown,
    MsgPack,
    Ndjson,
    Protobuf,
    Sse,
    Xml,
    Yaml,
}

pub fn get_content_type(content_type: Option<&str>) -> (ContentType, String) {
    let Some(raw) = content_type else {
        return (ContentType::Unknown, String::new());
    };
    if raw.is_empty() {
        return (ContentType::Unknown, String::new());
    }

    let Ok(parsed) = raw.parse::<mime::Mime>() else {
        return (ContentType::Unknown, String::new());
    };
    let charset = parsed
        .get_param(mime::CHARSET)
        .map(|value| value.as_str().to_string())
        .unwrap_or_default();

    let typ = parsed.type_().as_str();
    let subtype = parsed.subtype().as_str();

    let detected = match typ {
        "image" => ContentType::Image,
        "application" => {
            if subtype == "grpc" || subtype.starts_with("grpc+") {
                ContentType::Grpc
            } else {
                match subtype {
                    "csv" => ContentType::Csv,
                    "json" => ContentType::Json,
                    "msgpack" | "x-msgpack" | "vnd.msgpack" => ContentType::MsgPack,
                    "x-ndjson" | "ndjson" | "x-jsonl" | "jsonl" | "x-jsonlines" => {
                        ContentType::Ndjson
                    }
                    "protobuf" | "x-protobuf" | "x-google-protobuf" | "vnd.google.protobuf" => {
                        ContentType::Protobuf
                    }
                    "xml" => ContentType::Xml,
                    "yaml" | "x-yaml" => ContentType::Yaml,
                    _ if subtype.ends_with("+json") || subtype.ends_with("-json") => {
                        ContentType::Json
                    }
                    _ if subtype.ends_with("+proto") => ContentType::Protobuf,
                    _ if subtype.ends_with("+xml") => ContentType::Xml,
                    _ if subtype.ends_with("+yaml") => ContentType::Yaml,
                    _ => ContentType::Unknown,
                }
            }
        }
        "text" => match subtype {
            "css" => ContentType::Css,
            "csv" => ContentType::Csv,
            "html" => ContentType::Html,
            "markdown" | "x-markdown" => ContentType::Markdown,
            "event-stream" => ContentType::Sse,
            "xml" => ContentType::Xml,
            "yaml" | "x-yaml" => ContentType::Yaml,
            _ => ContentType::Unknown,
        },
        _ => ContentType::Unknown,
    };

    (detected, charset)
}

const PREFIX_XML_DECL: &[u8] = b"?xml";
const PREFIX_DOCTYPE: &[u8] = b"!doctype";
const PREFIX_HTML: &[u8] = b"html";

const HTML_TAGS: &[&[u8]] = &[
    b"html",
    b"head",
    b"body",
    b"div",
    b"span",
    b"p",
    b"a",
    b"table",
    b"tr",
    b"td",
    b"th",
    b"ul",
    b"ol",
    b"li",
    b"form",
    b"input",
    b"button",
    b"script",
    b"style",
    b"link",
    b"meta",
    b"title",
    b"section",
    b"article",
    b"nav",
    b"header",
    b"footer",
    b"main",
    b"aside",
    b"h1",
    b"h2",
    b"h3",
    b"h4",
    b"h5",
    b"h6",
    b"img",
    b"br",
    b"hr",
    b"pre",
    b"code",
    b"blockquote",
];

pub fn sniff_content_type(buf: &[u8]) -> ContentType {
    let b = trim_bom_and_space(buf);
    if b.is_empty() {
        return ContentType::Unknown;
    }

    match b[0] {
        b'{' | b'[' => ContentType::Json,
        b'<' => sniff_markup(b),
        b'-' if b.len() >= 3 && b[1] == b'-' && b[2] == b'-' => ContentType::Yaml,
        _ if is_image(buf) => ContentType::Image,
        _ => ContentType::Unknown,
    }
}

fn sniff_markup(b: &[u8]) -> ContentType {
    let rest = &b[1..];

    if has_prefix_fold(rest, PREFIX_XML_DECL) {
        return ContentType::Xml;
    }

    if !rest.is_empty() && (rest[0] == b'!' || rest[0] == b'?') {
        if has_prefix_fold(rest, PREFIX_DOCTYPE) {
            let after = trim_ascii_space(&rest[PREFIX_DOCTYPE.len()..]);
            if has_prefix_fold(after, PREFIX_HTML) {
                return ContentType::Html;
            }
            return ContentType::Xml;
        }
        return ContentType::Xml;
    }

    if !rest.is_empty() && is_letter(rest[0]) {
        return sniff_tag(rest);
    }

    ContentType::Unknown
}

fn sniff_tag(b: &[u8]) -> ContentType {
    if is_html_tag(b) {
        ContentType::Html
    } else {
        ContentType::Xml
    }
}

fn is_html_tag(b: &[u8]) -> bool {
    HTML_TAGS.iter().any(|tag| {
        if !has_prefix_fold(b, tag) {
            return false;
        }
        if b.len() == tag.len() {
            return true;
        }
        matches!(b[tag.len()], b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/')
    })
}

fn has_prefix_fold(b: &[u8], prefix: &[u8]) -> bool {
    b.len() >= prefix.len() && b[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn is_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

fn trim_bom_and_space(mut b: &[u8]) -> &[u8] {
    if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        b = &b[3..];
    }
    trim_ascii_space(b)
}

fn trim_ascii_space(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end]
}

fn is_image(buf: &[u8]) -> bool {
    buf.starts_with(b"\x89PNG\r\n\x1a\n")
        || buf.starts_with(b"\xff\xd8\xff")
        || buf.starts_with(b"GIF87a")
        || buf.starts_with(b"GIF89a")
        || buf.starts_with(b"BM")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_content_type() {
        let tests: &[(&str, &[u8], ContentType)] = &[
            ("json object", br#"{"key": "value"}"#, ContentType::Json),
            ("json array", b"[1, 2, 3]", ContentType::Json),
            (
                "json with whitespace",
                b"  \n  { \"key\": 1 }",
                ContentType::Json,
            ),
            (
                "json with bom",
                b"\xEF\xBB\xBF{\"key\": 1}",
                ContentType::Json,
            ),
            (
                "json array with bom and whitespace",
                b"\xEF\xBB\xBF  [1]",
                ContentType::Json,
            ),
            (
                "xml declaration",
                br#"<?xml version="1.0"?><root/>"#,
                ContentType::Xml,
            ),
            ("xml element", b"<root><child/></root>", ContentType::Xml),
            (
                "xml with whitespace",
                b"  \n  <?xml version=\"1.0\"?>",
                ContentType::Xml,
            ),
            ("xml comment", b"<!-- comment --><root/>", ContentType::Xml),
            ("xml cdata", b"<![CDATA[data]]>", ContentType::Xml),
            (
                "xml doctype",
                br#"<!DOCTYPE note SYSTEM "note.dtd">"#,
                ContentType::Xml,
            ),
            (
                "xml unknown element",
                b"<catalog><book/></catalog>",
                ContentType::Xml,
            ),
            (
                "html doctype",
                b"<!DOCTYPE html><html></html>",
                ContentType::Html,
            ),
            (
                "html doctype lowercase",
                b"<!doctype html><html></html>",
                ContentType::Html,
            ),
            ("html tag", b"<html><body></body></html>", ContentType::Html),
            (
                "head tag",
                b"<head><title>test</title></head>",
                ContentType::Html,
            ),
            ("body tag", b"<body>content</body>", ContentType::Html),
            (
                "div tag",
                br#"<div class="test">content</div>"#,
                ContentType::Html,
            ),
            ("p tag", b"<p>paragraph</p>", ContentType::Html),
            ("span tag", b"<span>text</span>", ContentType::Html),
            (
                "section tag",
                b"<section>content</section>",
                ContentType::Html,
            ),
            (
                "article tag",
                b"<article>content</article>",
                ContentType::Html,
            ),
            (
                "html with bom",
                b"\xEF\xBB\xBF<!doctype html>",
                ContentType::Html,
            ),
            ("h1 tag", b"<h1>heading</h1>", ContentType::Html),
            (
                "table tag",
                b"<table><tr><td>cell</td></tr></table>",
                ContentType::Html,
            ),
            ("nav tag", b"<nav>navigation</nav>", ContentType::Html),
            ("html self-closing", b"<br/>", ContentType::Html),
            (
                "html tag with attributes",
                br#"<div id="main">"#,
                ContentType::Html,
            ),
            ("yaml document start", b"---\nkey: value", ContentType::Yaml),
            (
                "yaml with whitespace",
                b"  \n  ---\nkey: value",
                ContentType::Yaml,
            ),
            (
                "yaml with bom",
                b"\xEF\xBB\xBF---\nkey: value",
                ContentType::Yaml,
            ),
            ("png image", b"\x89PNG\r\n\x1a\n", ContentType::Image),
            ("jpeg image", b"\xff\xd8\xff\xe0", ContentType::Image),
            ("gif image", b"GIF89a", ContentType::Image),
            (
                "bmp image",
                b"BM\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                ContentType::Image,
            ),
            ("empty", b"", ContentType::Unknown),
            ("plain text", b"hello world", ContentType::Unknown),
            ("csv-like", b"name,age\nalice,30", ContentType::Unknown),
            ("number", b"12345", ContentType::Unknown),
            ("whitespace only", b"   \n\t  ", ContentType::Unknown),
            ("single dash", b"-", ContentType::Unknown),
            ("two dashes", b"--", ContentType::Unknown),
        ];

        for (name, input, want) in tests {
            assert_eq!(sniff_content_type(input), *want, "{name}");
        }
    }

    #[test]
    fn test_is_html_tag() {
        let tests: &[(&str, &[u8], bool)] = &[
            ("html", b"html>", true),
            ("HTML uppercase", b"HTML>", true),
            ("div with space", br#"div class="x">"#, true),
            ("body end", b"body>", true),
            ("custom tag", b"mycomponent>", false),
            ("partial match", b"divider>", false),
            ("h1", b"h1>", true),
            ("h1 with space", br#"h1 id="x">"#, true),
            ("a tag", br#"a href="/">"#, true),
            ("img self-close", b"img/>", true),
            ("br", b"br>", true),
        ];

        for (name, input, want) in tests {
            assert_eq!(is_html_tag(input), *want, "{name}");
        }
    }

    #[test]
    fn test_is_letter() {
        let tests = [
            (b'a', true),
            (b'z', true),
            (b'A', true),
            (b'Z', true),
            (b'm', true),
            (b'0', false),
            (b'!', false),
            (b' ', false),
            (b'<', false),
        ];

        for (c, want) in tests {
            assert_eq!(is_letter(c), want, "{}", c as char);
        }
    }

    #[test]
    fn test_get_content_type() {
        let tests = [
            (
                "json with charset",
                Some("application/json; charset=utf-8"),
                ContentType::Json,
                "utf-8",
            ),
            (
                "html with charset",
                Some("text/html; charset=iso-8859-1"),
                ContentType::Html,
                "iso-8859-1",
            ),
            (
                "json without charset",
                Some("application/json"),
                ContentType::Json,
                "",
            ),
            ("empty content type", None, ContentType::Unknown, ""),
            (
                "xml with charset",
                Some("text/xml; charset=windows-1252"),
                ContentType::Xml,
                "windows-1252",
            ),
            (
                "csv with charset",
                Some("text/csv; charset=shift_jis"),
                ContentType::Csv,
                "shift_jis",
            ),
            (
                "grpc json",
                Some("application/grpc+json"),
                ContentType::Grpc,
                "",
            ),
            (
                "grpc with charset",
                Some("application/grpc+proto; charset=utf-8"),
                ContentType::Grpc,
                "utf-8",
            ),
        ];

        for (name, content_type, want_type, want_charset) in tests {
            let (got_type, got_charset) = get_content_type(content_type);
            assert_eq!(got_type, want_type, "{name}");
            assert_eq!(got_charset, want_charset, "{name}");
        }
    }
}
