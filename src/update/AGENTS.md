# Update development notes

Applies to `src/update/` and its submodules. Installer behavior is also covered by `tests/install.rs` and `tests/update.rs`.

- Metadata, artifact, checksum, and redirect URLs require HTTPS except for explicit internal test overrides.
- Update networking must not inherit origin-specific TLS versions, client authentication, insecure mode, or Unix-socket settings. It may retain proxy, DNS, timeout, verbosity, and custom-CA settings.
- Stream artifacts while hashing them; do not buffer complete downloads in memory.
- Preserve archive path validation and the existing streaming tar / temporary zip behavior.
- Use `fileutil::FileLock`, atomic replacement, and parent-directory synchronization where supported.
- Background checks remain nonblocking.
- Keep installer completion setup opt-in and never edit shell startup files automatically.
