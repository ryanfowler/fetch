# Resolver maintainer guidance

Keep wire parsing, owner/CNAME authorization, HTTPS/SVCB validation, and
transport policy in this package. Every network transport must use the bounded
wire codec and the caller's timeout budget. Do not authorize records from an
unrelated owner or fall back from an authenticated resolver failure. Preserve
resolver provenance and first-success address-family preference. Add parser and
fuzz tests before changing security-sensitive behavior; run `go test -race
./internal/resolver` for concurrency changes.
