# Update maintainer guidance

Treat release metadata, URLs, checksums, archives, and filenames as hostile.
Verify the mandatory SHA-256 sidecar before opening an archive. Keep metadata,
archive entries, unpacked bytes, redirects, subprocesses, and timeouts bounded.
Stage on the destination filesystem and replace atomically without following
symlinks. Automatic updates must remain nonfatal and noninteractive; explicit
updates must preserve the original executable on every failure. Test with local
release fixtures and never mutate a developer's installed binary.
