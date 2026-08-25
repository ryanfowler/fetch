# Article extraction

Use `--article` to turn a readable HTML page into Markdown with YAML
frontmatter:

```sh
fetch --article https://example.com/story
fetch --article --pager off --color off --format off https://example.com/story >story.md
```

`fetch` accepts `text/html` and `application/xhtml+xml`. It decodes the response
before extraction, resolves links against the final URL after redirects, and
uses the readability extractor with a maximum of 500,000 DOM elements. It does
not execute JavaScript. Pages that require client-side rendering need a browser.

The decoded article body is limited to 16 MiB. The limit applies when the
`Content-Length` header is missing as well. A response over the limit fails
without an unbounded allocation.

## Markdown responses

`text/markdown` and `text/x-markdown` responses pass through unchanged except
for a `url` frontmatter field. Unsupported content types produce an article-mode
error instead of silently returning unrelated content.

## Frontmatter

When metadata exists, fields are emitted in this order:

```yaml
---
title: "Example story"
byline: "Author"
site_name: "Example"
published_time: "2026-01-01T00:00:00Z"
lang: "en"
dir: "ltr"
length: 1234
excerpt: "A short summary."
url: "https://example.com/story"
---
```

Only available fields are emitted. String values use JSON string quoting, which
is a safe YAML scalar. `length` is numeric. Markdown pass-through emits only
`url`.

Terminal output may use the normal formatter and color. On a terminal,
article images are fetched and rendered with the configured image policy. Use
`--image off` to disable this behavior. Article images are not fetched for
output files, pipes, or clipboard destinations, which receive raw, uncolored
Markdown. Image fetches are bounded and failed images fall back to their alt
text and URL.

Article mode cannot be combined with WebSockets, gRPC, DNS/TLS inspection,
`--discard`, `--remote-name`, or `--remote-header-name`.
