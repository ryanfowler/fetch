# Integration test guidance

Use local deterministic fixtures. Isolate HOME, config, cache, temp, session,
proxy, and updater paths. Give every socket and child process an explicit
deadline, drain stdout and stderr concurrently, and keep listeners open until
the child is ready. Assert both stdout and stderr destinations. Do not use the
user's installed executable or credentials. Keep platform-specific tests behind
narrow build constraints and run `go test -v -parallel 8 ./integration`.
