use std::borrow::Cow;
use std::path::Path;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MimePolicy {
    pub formatter: ContentType,
    pub extension: Option<&'static str>,
    pub request_content_type: Option<&'static str>,
}

impl MimePolicy {
    const UNKNOWN: Self = Self {
        formatter: ContentType::Unknown,
        extension: None,
        request_content_type: None,
    };

    const fn new(
        formatter: ContentType,
        extension: Option<&'static str>,
        request_content_type: Option<&'static str>,
    ) -> Self {
        Self {
            formatter,
            extension,
            request_content_type,
        }
    }
}

struct MimeRule {
    typ: &'static str,
    subtype: &'static str,
    formatter: ContentType,
    extension: Option<&'static str>,
    request_content_type: &'static str,
    request_extensions: &'static [&'static str],
}

impl MimeRule {
    fn policy(&self) -> MimePolicy {
        MimePolicy::new(
            self.formatter,
            self.extension,
            Some(self.request_content_type),
        )
    }
}

macro_rules! mime_rules {
    ($(($typ:literal, $subtype:literal, $formatter:ident, $extension:expr, $request_content_type:literal, [$($request_extension:literal),* $(,)?])),+ $(,)?) => {
        &[
            $(MimeRule {
                typ: $typ,
                subtype: $subtype,
                formatter: ContentType::$formatter,
                extension: $extension,
                request_content_type: $request_content_type,
                request_extensions: &[$($request_extension),*],
            },)+
        ]
    };
}

#[rustfmt::skip]
const MIME_RULES: &[MimeRule] = mime_rules![
    ("image", "jpeg", Image, Some(".jpg"), "image/jpeg", ["jpg", "jpeg"]),
    ("image", "png", Image, Some(".png"), "image/png", ["png"]),
    ("image", "gif", Image, Some(".gif"), "image/gif", ["gif"]),
    ("image", "webp", Image, Some(".webp"), "image/webp", ["webp"]),
    ("image", "avif", Image, Some(".avif"), "image/avif", ["avif"]),
    ("image", "heif", Image, Some(".heif"), "image/heif", ["heic", "heif"]),
    ("image", "jxl", Image, Some(".jxl"), "image/jxl", ["jxl"]),
    ("image", "tiff", Image, Some(".tiff"), "image/tiff", ["tif", "tiff"]),
    ("image", "bmp", Image, Some(".bmp"), "image/bmp", ["bmp"]),
    ("image", "x-icon", Image, Some(".ico"), "image/x-icon", ["ico"]),
    ("image", "svg+xml", Image, Some(".svg"), "image/svg+xml", ["svg"]),
    ("image", "vnd.adobe.photoshop", Image, Some(".psd"), "image/vnd.adobe.photoshop", ["psd"]),
    ("image", "x-raw", Image, Some(".raw"), "image/x-raw", ["raw", "dng", "nef", "cr2", "arw"]),
    ("video", "mp4", Unknown, Some(".mp4"), "video/mp4", ["mp4"]),
    ("video", "x-m4v", Unknown, Some(".m4v"), "video/x-m4v", ["m4v"]),
    ("video", "webm", Unknown, Some(".webm"), "video/webm", ["webm"]),
    ("video", "quicktime", Unknown, Some(".mov"), "video/quicktime", ["mov"]),
    ("video", "x-matroska", Unknown, Some(".mkv"), "video/x-matroska", ["mkv"]),
    ("video", "x-msvideo", Unknown, Some(".avi"), "video/x-msvideo", ["avi"]),
    ("video", "x-ms-wmv", Unknown, Some(".wmv"), "video/x-ms-wmv", ["wmv"]),
    ("video", "x-flv", Unknown, Some(".flv"), "video/x-flv", ["flv"]),
    ("video", "mpeg", Unknown, Some(".mpeg"), "video/mpeg", ["mpeg", "mpg"]),
    ("video", "ogg", Unknown, Some(".ogv"), "video/ogg", ["ogv"]),
    ("audio", "mpeg", Unknown, Some(".mp3"), "audio/mpeg", ["mp3"]),
    ("audio", "mp4", Unknown, Some(".m4a"), "audio/mp4", ["m4a"]),
    ("audio", "aac", Unknown, Some(".aac"), "audio/aac", ["aac"]),
    ("audio", "wav", Unknown, Some(".wav"), "audio/wav", ["wav"]),
    ("audio", "flac", Unknown, Some(".flac"), "audio/flac", ["flac"]),
    ("audio", "ogg", Unknown, Some(".ogg"), "audio/ogg", ["ogg"]),
    ("audio", "opus", Unknown, Some(".opus"), "audio/opus", ["opus"]),
    ("audio", "aiff", Unknown, Some(".aiff"), "audio/aiff", ["aiff", "aif"]),
    ("audio", "midi", Unknown, Some(".midi"), "audio/midi", ["mid", "midi"]),
    ("application", "pdf", Unknown, Some(".pdf"), "application/pdf", ["pdf"]),
    ("text", "plain", Unknown, Some(".txt"), "text/plain; charset=utf-8", ["txt", "text"]),
    ("text", "html", Html, Some(".html"), "text/html; charset=utf-8", ["html", "htm"]),
    ("text", "css", Css, Some(".css"), "text/css; charset=utf-8", ["css"]),
    ("text", "csv", Csv, Some(".csv"), "text/csv; charset=utf-8", ["csv"]),
    ("application", "csv", Csv, Some(".csv"), "application/csv", []),
    ("application", "json", Json, Some(".json"), "application/json", ["json"]),
    ("application", "x-ndjson", Ndjson, Some(".ndjson"), "application/x-ndjson", ["ndjson"]),
    ("application", "ndjson", Ndjson, Some(".ndjson"), "application/ndjson", []),
    ("application", "x-jsonl", Ndjson, Some(".jsonl"), "application/x-jsonl", ["jsonl"]),
    ("application", "jsonl", Ndjson, Some(".jsonl"), "application/jsonl", []),
    ("application", "x-jsonlines", Ndjson, Some(".jsonl"), "application/x-jsonlines", []),
    ("application", "xml", Xml, Some(".xml"), "application/xml", ["xml"]),
    ("text", "xml", Xml, Some(".xml"), "text/xml", []),
    ("application", "yaml", Yaml, Some(".yaml"), "application/yaml", ["yaml", "yml"]),
    ("application", "x-yaml", Yaml, Some(".yaml"), "application/x-yaml", []),
    ("text", "yaml", Yaml, Some(".yaml"), "text/yaml", []),
    ("text", "x-yaml", Yaml, Some(".yaml"), "text/x-yaml", []),
    ("text", "markdown", Markdown, Some(".md"), "text/markdown; charset=utf-8", ["md"]),
    ("text", "x-markdown", Markdown, Some(".md"), "text/x-markdown; charset=utf-8", []),
    ("text", "event-stream", Sse, Some(".sse"), "text/event-stream", ["sse"]),
    ("application", "msgpack", MsgPack, Some(".msgpack"), "application/msgpack", ["msgpack", "mpack"]),
    ("application", "x-msgpack", MsgPack, Some(".msgpack"), "application/x-msgpack", []),
    ("application", "vnd.msgpack", MsgPack, Some(".msgpack"), "application/vnd.msgpack", []),
    ("application", "protobuf", Protobuf, Some(".pb"), "application/protobuf", ["pb", "protobuf"]),
    ("application", "x-protobuf", Protobuf, Some(".pb"), "application/x-protobuf", []),
    ("application", "x-google-protobuf", Protobuf, Some(".pb"), "application/x-google-protobuf", []),
    ("application", "vnd.google.protobuf", Protobuf, Some(".pb"), "application/vnd.google.protobuf", []),
    ("application", "rtf", Unknown, Some(".rtf"), "application/rtf", ["rtf"]),
    ("application", "msword", Unknown, Some(".doc"), "application/msword", ["doc"]),
    ("application", "vnd.openxmlformats-officedocument.wordprocessingml.document", Unknown, Some(".docx"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ["docx"]),
    ("application", "vnd.ms-excel", Unknown, Some(".xls"), "application/vnd.ms-excel", ["xls"]),
    ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet", Unknown, Some(".xlsx"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ["xlsx"]),
    ("application", "vnd.ms-powerpoint", Unknown, Some(".ppt"), "application/vnd.ms-powerpoint", ["ppt"]),
    ("application", "vnd.openxmlformats-officedocument.presentationml.presentation", Unknown, Some(".pptx"), "application/vnd.openxmlformats-officedocument.presentationml.presentation", ["pptx"]),
    ("font", "woff", Unknown, Some(".woff"), "font/woff", ["woff"]),
    ("font", "woff2", Unknown, Some(".woff2"), "font/woff2", ["woff2"]),
    ("font", "ttf", Unknown, Some(".ttf"), "font/ttf", ["ttf"]),
    ("font", "otf", Unknown, Some(".otf"), "font/otf", ["otf"]),
    ("application", "vnd.ms-fontobject", Unknown, Some(".eot"), "application/vnd.ms-fontobject", ["eot"]),
    ("application", "zip", Unknown, Some(".zip"), "application/zip", ["zip"]),
    ("application", "x-tar", Unknown, Some(".tar"), "application/x-tar", ["tar"]),
    ("application", "gzip", Unknown, Some(".gz"), "application/gzip", ["gz", "tgz"]),
    ("application", "x-bzip2", Unknown, Some(".bz2"), "application/x-bzip2", ["bz2"]),
    ("application", "x-xz", Unknown, Some(".xz"), "application/x-xz", ["xz"]),
    ("application", "x-7z-compressed", Unknown, Some(".7z"), "application/x-7z-compressed", ["7z"]),
    ("application", "vnd.rar", Unknown, Some(".rar"), "application/vnd.rar", ["rar"]),
    ("application", "vnd.microsoft.portable-executable", Unknown, Some(".exe"), "application/vnd.microsoft.portable-executable", ["exe"]),
    ("application", "x-msi", Unknown, Some(".msi"), "application/x-msi", ["msi"]),
    ("application", "vnd.debian.binary-package", Unknown, Some(".deb"), "application/vnd.debian.binary-package", ["deb"]),
    ("application", "x-rpm", Unknown, Some(".rpm"), "application/x-rpm", ["rpm"]),
    ("application", "javascript", Unknown, Some(".js"), "application/javascript", ["js", "mjs"]),
    ("application", "typescript", Unknown, Some(".ts"), "application/typescript", ["ts"]),
    ("text", "x-go", Unknown, Some(".go"), "text/x-go; charset=utf-8", ["go"]),
    ("text", "x-rust", Unknown, Some(".rs"), "text/x-rust; charset=utf-8", ["rs"]),
    ("text", "x-python", Unknown, Some(".py"), "text/x-python; charset=utf-8", ["py"]),
    ("application", "x-sh", Unknown, Some(".sh"), "application/x-sh", ["sh"]),
];

pub fn get_content_type(content_type: Option<&str>) -> (ContentType, String) {
    let (policy, charset) = get_mime_policy(content_type);
    (policy.formatter, charset)
}

pub fn get_mime_policy(content_type: Option<&str>) -> (MimePolicy, String) {
    let Some(raw) = content_type else {
        return (MimePolicy::UNKNOWN, String::new());
    };
    if raw.is_empty() {
        return (MimePolicy::UNKNOWN, String::new());
    }

    let Ok(parsed) = raw.parse::<mime::Mime>() else {
        return (MimePolicy::UNKNOWN, String::new());
    };
    let charset = parsed
        .get_param(mime::CHARSET)
        .map(|value| value.as_str().to_string())
        .unwrap_or_default();

    let typ = parsed.type_().as_str();
    let subtype = parsed.subtype();
    let suffix = parsed.suffix();
    let subtype = if let Some(suffix) = suffix {
        Cow::Owned(format!("{}+{}", subtype.as_str(), suffix.as_str()))
    } else {
        Cow::Borrowed(subtype.as_str())
    };
    (policy_for_parts(typ, subtype.as_ref()), charset)
}

pub fn extension_for_content_type(content_type: Option<&str>) -> Option<&'static str> {
    get_mime_policy(content_type).0.extension
}

pub fn request_content_type_for_path(path: &Path) -> Option<&'static str> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(request_content_type_for_extension)
}

pub fn request_content_type_for_extension(extension: &str) -> Option<&'static str> {
    let extension = extension.strip_prefix('.').unwrap_or(extension);
    MIME_RULES
        .iter()
        .find(|rule| {
            rule.request_extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
        .map(|rule| rule.request_content_type)
}

fn policy_for_parts(typ: &str, subtype: &str) -> MimePolicy {
    if let Some(rule) = MIME_RULES
        .iter()
        .find(|rule| rule.typ == typ && rule.subtype == subtype)
    {
        return rule.policy();
    }

    match typ {
        "image" => MimePolicy::new(ContentType::Image, None, None),
        "application" => {
            if subtype == "grpc" || subtype.starts_with("grpc+") {
                MimePolicy::new(ContentType::Grpc, None, None)
            } else if subtype.ends_with("+json") || subtype.ends_with("-json") {
                MimePolicy::new(ContentType::Json, Some(".json"), None)
            } else if subtype.ends_with("+proto") {
                MimePolicy::new(ContentType::Protobuf, Some(".pb"), None)
            } else if subtype.ends_with("+xml") {
                MimePolicy::new(ContentType::Xml, Some(".xml"), None)
            } else if subtype.ends_with("+yaml") {
                MimePolicy::new(ContentType::Yaml, Some(".yaml"), None)
            } else {
                MimePolicy::UNKNOWN
            }
        }
        _ => MimePolicy::UNKNOWN,
    }
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

    #[test]
    fn mime_policy_maps_formatter_extension_and_request_default() {
        let (policy, charset) = get_mime_policy(Some("application/json; charset=utf-8"));
        assert_eq!(policy.formatter, ContentType::Json);
        assert_eq!(policy.extension, Some(".json"));
        assert_eq!(policy.request_content_type, Some("application/json"));
        assert_eq!(charset, "utf-8");

        let (policy, charset) = get_mime_policy(Some("application/vnd.api+json; charset=utf-16"));
        assert_eq!(policy.formatter, ContentType::Json);
        assert_eq!(policy.extension, Some(".json"));
        assert_eq!(policy.request_content_type, None);
        assert_eq!(charset, "utf-16");

        let (policy, charset) = get_mime_policy(Some("image/png"));
        assert_eq!(policy.formatter, ContentType::Image);
        assert_eq!(policy.extension, Some(".png"));
        assert_eq!(policy.request_content_type, Some("image/png"));
        assert_eq!(charset, "");
    }

    #[test]
    fn request_content_type_uses_central_extension_policy() {
        assert_eq!(
            request_content_type_for_extension(".JSON"),
            Some("application/json")
        );
        assert_eq!(
            request_content_type_for_path(Path::new("archive.tgz")),
            Some("application/gzip")
        );
        assert_eq!(
            request_content_type_for_path(Path::new("notes.text")),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(request_content_type_for_path(Path::new("payload")), None);
    }
}
