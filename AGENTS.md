# Notes for agents

- Go, standard library only (no third-party modules). Keep it that way unless asked: the image is `scratch` + one static binary.
- Layout: `main.go` (listeners), `internal/config` (noggin.cfg parser + `GOVERNER_*` precedence), `internal/ipa` (JSON-RPC client), `internal/store` (one JSON state file), `internal/mail`, `internal/web` (handlers, embedded templates/CSS).
- noggin integration is only through its public surfaces: `BASSET_URL` hook payload (noggin/signals.py), the `/register/spamcheck-hook` callback, stage-user `fasstatusnote`, `TEMPLATES_CUSTOM_DIRECTORIES`. Checked against noggin 1.11.0; re-check those files when noggin changes.
- IPA is the source of truth for users and groups; the store only keeps tokens, group requests, blocklist and the activity log. "Managed" groups = members of the container group; every group-management action must verify that membership first.
- Two listeners on purpose: the website (behind the proxy) and the hook (private). Never mount the hook on the UI mux.
- Tests use an in-memory fake IPA (`internal/web/web_test.go`); there's no live-IPA test. Run `gofmt -l .`, `go vet ./...`, `go test -race ./...` before pushing.
- The name is spelled "governer" (owner's choice): keep the spelling in env vars and paths.
