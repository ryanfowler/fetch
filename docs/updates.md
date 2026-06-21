# Updates

`fetch` can update its own binary from the project's GitHub releases. Use
`fetch --update` for an explicit update check, or set `auto-update` in the
configuration file to run update checks in the background.

## Manual Updates

```sh
fetch --update
```

`--update` checks the latest release, downloads the release artifact for the
current operating system and CPU architecture, verifies it, and replaces the
currently running `fetch` executable in place.

The update command prints status to stderr. On success, it reports the old and
new versions and, when possible, a GitHub compare URL for the changelog.

## Dry Run

Use `--dry-run` to check whether an update is available without downloading or
installing the release artifact:

```sh
fetch --update --dry-run
```

Dry-run mode still performs the same executable permission preflight and latest
release lookup as a normal update. If the latest release matches your current
version, it reports that `fetch` is already up to date. If a newer release is
available, it reports the version change and exits without downloading the
archive or modifying the binary.

## Update Source

By default, self-updates read release metadata from:

```text
https://api.github.com/repos/ryanfowler/fetch/releases/latest
```

The release metadata points to the platform artifact and checksum sidecar on
GitHub Releases. `fetch` selects an artifact named like:

```text
fetch-<version>-<os>-<arch>.tar.gz
fetch-<version>-windows-<arch>.zip
```

The updater uses Go-style platform names for compatibility with the release
artifacts, such as `darwin`, `linux`, `windows`, `amd64`, and `arm64`.

The request URL argument is not used as an update source, and there is no
configuration option for selecting an alternate update channel.

Self-update URLs must use HTTPS. Redirects are followed, but redirect targets
must also use HTTPS.

## Verification

Before replacing the executable, `fetch` downloads the matching
`<artifact>.sha256` sidecar, parses the leading SHA-256 digest, hashes the
downloaded artifact as it streams, and compares the two digests. A mismatch
aborts the update before installation.

The updater also bounds the release metadata, checksum file, artifact download,
archive entry count, and unpacked data size, and refuses archive paths that
would escape the temporary unpack directory.

## Permissions

Self-update replaces the executable returned by the operating system as the
current `fetch` binary. The process must be able to write in that executable's
directory.

On Unix-like systems, `fetch` checks directory write access before contacting
the update source. If `fetch` was installed into a root-owned or package-manager
managed directory, run the update with appropriate permissions or update through
the package manager instead. On Windows, replacement errors are reported if the
binary cannot be moved into place.

Temporary unpack directories are created under the system temp directory as
`fetch-update-*` and are removed after the update attempt. On Unix-like systems,
these directories are created with private `0700` permissions.

## Automatic Updates

Enable background update checks in the configuration file:

```ini
# Check at most once every 24 hours
auto-update = true

# Check at most once every 12 hours
auto-update = 12h

# Disable automatic updates
auto-update = false
```

`true` uses a 24 hour interval. Custom intervals require units, including
values such as `30m`, `1.5h`, `4h`, and `1d`. `false`, `off`, `no`, `never`,
and `0` disable automatic updates.

Automatic updates run after configuration has been loaded and validated, and
only for normal request/inspection commands. Metadata commands such as
`fetch --help`, `fetch --version`, and `fetch --buildinfo` do not start
background updates.

When an automatic update is due, `fetch` starts a detached child process with:

```text
--update --timeout=300 --silent
```

The parent command continues without waiting, and the child process has stdin,
stdout, and stderr detached. The explicit config path from `--config` is passed
to the child; otherwise the child uses normal config discovery. Background
update failures are not reported by the parent command.

## Cache and Lock Files

Automatic update scheduling and update locking use the user cache directory:

| Platform             | Directory                                        |
| -------------------- | ------------------------------------------------ |
| macOS                | `$HOME/Library/Caches/fetch`                     |
| Linux and other Unix | `$XDG_CACHE_HOME/fetch`, or `$HOME/.cache/fetch` |
| Windows              | `%LOCALAPPDATA%\fetch`                           |

Files in this directory include:

| File or directory | Purpose                                                                   |
| ----------------- | ------------------------------------------------------------------------- |
| `metadata.json`   | Stores the last update attempt timestamp for auto-update interval checks. |
| `.update-lock`    | Advisory lock that prevents concurrent update attempts.                   |
| `http3/`          | Bounded per-origin cache for learned HTTP/3 alternatives.                 |

Manual and automatic update attempts both refresh `metadata.json`, including
`fetch --update --dry-run`.

Explicit `fetch --update` waits for the update lock, up to the shorter of the
request timeout and 30 seconds. Background auto-update checks use a nonblocking
lock attempt; if another update is running, the background check is skipped.

## Proxy and Timeout Behavior

Self-update downloads use the same HTTP transport as normal requests. Proxy
configuration from `--proxy`, the configuration file, and standard proxy
environment variables applies to update metadata, checksum, and artifact
requests. `NO_PROXY` is honored by the transport.

`--timeout` and `--connect-timeout` also apply to explicit update requests:

```sh
fetch --update --timeout 120 --connect-timeout 10
```

Each update network operation uses the configured timeout budget, and redirects
share the budget of the request that encountered them. Automatic updates set
`--timeout=300` for the child process so background checks cannot run
indefinitely.

## See Also

- [Configuration](configuration.md) - Configure `auto-update`, proxies, and timeouts
- [CLI Reference](cli-reference.md) - Command-line option reference
- [Getting Started](getting-started.md) - Installation and first-run basics
