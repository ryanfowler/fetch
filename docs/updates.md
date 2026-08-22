# Updates and installation

`fetch` ships as statically built Go binaries for Linux, macOS, and Windows on
amd64 and arm64. Unix release archives have lowercase SHA-256 sidecars.

## Install

For macOS and Linux, the installer downloads the matching Go archive, verifies
its sidecar before extraction, validates `fetch --version`, and atomically
renames a staged executable:

```sh
curl -fsSL https://raw.githubusercontent.com/ryanfowler/fetch/main/install.sh | bash
```

Set `FETCH_INSTALL_DIR` to choose an installation directory. The installer
rejects target symlinks and directories, archives with unexpected entries, and
partial or invalid binaries. It uses `/usr/local/bin` when writable and then
`~/.local/bin`. Windows users can use a release archive or `fetch --update`.

To build from source:

```sh
go install github.com/ryanfowler/fetch@latest
```

The installer never uses Cargo or a Rust toolchain.

## Manual update

```sh
fetch --check-update
fetch --update
fetch --update --dry-run
```

`--check-update` reports the latest release. `--update` downloads the matching
archive and requires a SHA-256 sidecar. Metadata is limited to 1 MiB, checksum
sidecars to 1 KiB, and archives to 128 MiB. Archive contents are bounded to
128 entries and 512 MiB unpacked data. The archive is not opened until checksum
verification succeeds.

Update requests inherit only operational proxy, DNS, CA, connect-timeout, and
request-timeout settings. They do not inherit origin headers, cookies, sessions,
credentials, `--insecure`, client certificates, Unix sockets, or forced HTTP
versions. Redirects remain HTTPS-only and are limited to 10.

Dry-run downloads bounded release metadata and the checksum sidecar to validate
asset selection and checksum availability. It does not download the executable
archive, replace the binary, or update the automatic-check timestamp.

## Automatic checks

Set an interval in the configuration file:

```ini
auto-update = 12h
```

`true` means 24 hours and `false` disables checks. A normal validated request
may start one detached, silent updater child when the interval is due. Help,
version, build information, completion, skill management, dry-run, and updater
children do not start automatic checks. Automatic failures do not change the
requested fetch result. Metadata is advisory and stored in the platform user
cache with bounded, atomic, symlink-safe writes.
