# HTTP recipes

## Read and parse

Keep diagnostics separate from a machine-readable body:

```sh
fetch --pager off --color off --format off https://api.example.com/items >items.json
```

Check the exit status before trusting the file; 4xx/5xx are failures by default.
Use `--ignore-status` only when the caller intentionally handles error bodies.

## Build requests

```sh
fetch --dry-run -vv -j @request.json https://api.example.com/items
fetch -j @request.json https://api.example.com/items
fetch --method PATCH -j @patch.json https://api.example.com/items/42
fetch -H 'Accept: application/json' https://api.example.com/items
```

Body-producing options infer `POST`; an explicit `--method` wins. Dry-run any
uncertain mutation and ask before destructive POST/PATCH/PUT/DELETE operations.
Avoid retries for unsafe methods unless duplicate effects are acceptable.

## Authentication

Prefer credentials already supplied through fetch configuration, a named session,
or environment-backed tooling. Basic, Digest, Bearer, and AWS SigV4 are supported;
consult `fetch --help` for the applicable flags rather than guessing credentials.
Avoid literal secrets in shell arguments because process listings and shell
history may expose them. Never echo credentials, and redact auth headers, cookies,
API keys, certificates, and signed query parameters from reports.

## Output and inspection

```sh
fetch --pager off --color off -v https://example.com
fetch --timing --discard https://example.com
fetch --pager off -o archive.zip https://example.com/archive.zip
```

Use `-o FILE` for binary or large output, `--discard` when the body is irrelevant,
and `--image off` for predictable terminal behavior. The body is stdout; metadata
and errors are stderr. Do not use `2>&1` when parsing the body.

To preserve the final HTTP exchange for debugging without changing normal output,
write a HAR 1.2 sidecar:

```sh
fetch --har request.har https://example.com
fetch -o response.bin --har request.har https://example.com/download
```

Only the final exchange after redirects, retries, or authentication challenges is
recorded. `--har` honors `--clobber`; its path cannot be stdout or the response
output path. Request and response body capture is limited to 16 MiB, after which
the body is omitted from the HAR. WebSocket, inspection, gRPC discovery, and
`--dry-run` modes are unsupported.

HAR files may contain credentials, authorization headers, cookies, and request and
response bodies. Treat them as sensitive: do not commit or share them without
reviewing and redacting their contents.

## Translate curl

```sh
fetch --from-curl 'curl -H "Accept: application/json" https://example.com'
fetch --dry-run --from-curl 'curl -X PUT --data @data.json https://example.com/item/1'
```

Translation can reject unsupported semantic curl flags. Inspect state-changing
translations with `--dry-run` before executing them.
