# fetch documentation

`fetch` is a Go HTTP(S) client. This index groups the user and maintainer
reference by task.

## Start here

- [Getting started](getting-started.md)
- [CLI reference](cli-reference.md)
- [Configuration](configuration.md)
- [Request bodies](request-bodies.md)
- [Output formatting and paging](output-formatting.md)
- [Resource limits and safety](limits.md)

## Features

- [Authentication](authentication.md)
- [Article extraction](article.md)
- [HAR recording](har.md)
- [DNS, proxy, HTTP versions, and TLS/ECH](advanced-features.md)
- [Encrypted ClientHello](ech.md)
- [WebSockets](websocket.md)
- [gRPC](grpc.md)
- [Image rendering](image-rendering.md)
- [Self-update and installation](updates.md)
- [Agent Skill](agent-skill.md)
- [Shell completion](completions.md)
- [Troubleshooting](troubleshooting.md)

## Maintainer reference

- [Go migration note](migration-go.md)
- [Release qualification](release-qualification.md)
- [Qualification report](release-qualification-report.md)
- [Repository maintainer guide](../AGENTS.md)

The CLI reference is embedded in the Go binary and is rendered by
`fetch -v --help`. Keep that file synchronized with the option registry and
with the guides listed above.
