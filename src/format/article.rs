use legible::{Article, Options};

const MAX_ARTICLE_ELEMENTS: usize = 500_000;

pub fn extract_markdown(html: &str, url: &str) -> Result<Vec<u8>, String> {
    let options = Options::new().max_elems_to_parse(MAX_ARTICLE_ELEMENTS);
    let article = legible::parse(html, Some(url), Some(options))
        .map_err(|err| format!("failed to extract readable article: {err}"))?;
    let markdown = htmd::convert(&article.content)
        .map_err(|err| format!("failed to convert extracted article to Markdown: {err}"))?;
    Ok(render_document(&article, url, &markdown).into_bytes())
}

pub fn add_url_frontmatter(markdown: &str, url: &str) -> Vec<u8> {
    let mut out = String::from("---\n");
    push_string(&mut out, "url", url);
    out.push_str("---\n\n");
    out.push_str(markdown);
    if !markdown.ends_with('\n') {
        out.push('\n');
    }
    out.into_bytes()
}

fn render_document(article: &Article, url: &str, markdown: &str) -> String {
    let mut out = String::from("---\n");
    push_string(&mut out, "title", &article.title);
    push_optional_string(&mut out, "byline", article.byline.as_deref());
    push_optional_string(&mut out, "site_name", article.site_name.as_deref());
    push_optional_string(
        &mut out,
        "published_time",
        article.published_time.as_deref(),
    );
    push_optional_string(&mut out, "lang", article.lang.as_deref());
    push_optional_string(&mut out, "dir", article.dir.as_deref());
    out.push_str(&format!("length: {}\n", article.length));
    push_optional_string(&mut out, "excerpt", article.excerpt.as_deref());
    push_string(&mut out, "url", url);
    out.push_str("---\n\n");
    out.push_str(markdown.trim());
    out.push('\n');
    out
}

fn push_optional_string(out: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        push_string(out, key, value);
    }
}

fn push_string(out: &mut String, key: &str, value: &str) {
    let value = serde_json::to_string(value).expect("strings always serialize as JSON");
    out.push_str(key);
    out.push_str(": ");
    out.push_str(&value);
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_article_as_markdown_with_safe_frontmatter() {
        let html = r#"<!doctype html>
<html lang="en" dir="ltr"><head>
<title>An &quot;Quoted&quot; Article</title>
<meta property="og:site_name" content="Example News">
<meta name="author" content="Jane Smith">
<meta name="description" content="A summary: with punctuation">
</head><body>
<nav>Navigation that should be removed</nav>
<article><h1>An Article</h1><p>This is a sufficiently substantial article paragraph with readable content for extraction. It contains enough prose to be selected as the primary document content.</p><p><a href="relative">Related reading</a></p></article>
</body></html>"#;

        let output = extract_markdown(html, "https://example.com/posts/one").unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.starts_with("---\n"));
        assert!(output.contains("title: \"An "));
        assert!(output.contains("byline: \"Jane Smith\""));
        assert!(output.contains("site_name: \"Example News\""));
        assert!(output.contains("lang: \"en\""));
        assert!(output.contains("url: \"https://example.com/posts/one\""));
        assert!(output.contains("primary document content"), "{output}");
        assert!(
            output.contains("https://example.com/posts/relative"),
            "{output}"
        );
        assert!(!output.contains("Navigation that should be removed"));
        assert!(output.ends_with('\n'));
        assert!(!output.ends_with("\n\n"));
    }

    #[test]
    fn markdown_frontmatter_preserves_the_document() {
        let output = add_url_frontmatter(
            "# Existing Markdown\n\nBody with *formatting*.\n",
            "https://example.com/readme.md",
        );
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "---\nurl: \"https://example.com/readme.md\"\n---\n\n# Existing Markdown\n\nBody with *formatting*.\n"
        );
    }

    #[test]
    fn frontmatter_quotes_multiline_values() {
        let article = Article {
            title: "title: ---\nnext".to_string(),
            byline: None,
            dir: None,
            lang: None,
            content: String::new(),
            text_content: String::new(),
            length: 0,
            excerpt: None,
            site_name: None,
            published_time: None,
        };

        let output = render_document(&article, "https://example.com/?a=1&b=2", "Body");
        assert!(output.contains(r#"title: "title: ---\nnext""#));
        assert!(!output.contains("byline:"));
        assert_eq!(output.matches("---\n").count(), 2);
        assert!(output.ends_with("Body\n"));
    }
}
