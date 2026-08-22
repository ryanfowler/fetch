# Agent Skill

`fetch` includes a portable Agent Skill for agents that need HTTP, DNS/TLS,
gRPC, article, and WebSocket workflows.

## Print and install

```sh
fetch --skill
fetch --install-skill                 # generic Agents location
fetch --install-skill codex --scope user
fetch --install-skill all --scope project
fetch --uninstall-skill pi --scope user
```

Supported agents are `auto`, `agents`, `codex`, `claude`, `gemini`, `pi`, and
`all`. `auto` selects the generic Agents location. `all` means exactly those
five known locations; it does not scan the home directory. User scope uses the
user home directory. Project scope uses the current working directory.

Use `--dry-run` to display destinations without writing. Use `--force` only when
a managed installation has changed and you have reviewed the displayed paths.
Interactive installs and removals ask for confirmation. Noninteractive forced
actions must specify `--force`.

## Managed files and safety

The embedded bundle contains `SKILL.md`, references, and evaluation fixtures.
Installation is offline. Each installation has a `.fetch-skill.json` manifest
with file paths, sizes, and SHA-256 digests. Modified or unknown files refuse
replacement or removal unless `--force` is supplied. An unrecognized directory
is never recursively removed just because it is named `fetch`.

Destination components are checked for symlinks, writes use private directories
and atomic operations, and concurrent operations use a per-destination lock.
The command does not edit agent settings, shell profiles, plugin registries, or
other configuration.

The skill documents the Go implementation's 16 MiB article and HAR limits,
streaming and replayable request bodies, DNS/TLS diagnostics, gRPC reflection,
WebSocket message modes, raw output, automatic HTTP/3, and ECH caveats. Treat
its examples and evaluation fixtures as versioned product documentation.
