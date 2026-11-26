# noggin-governer

Adds administrative controls to [noggin](https://github.com/fedora-infra/noggin) based workflows.

It runs as a small sidecar container next to noggin (a ~10 MB static binary on `scratch`) and gives a
group of FreeIPA users, the *approvers*, a website for:

- **Account approval.** Every noggin registration waits until an approver accepts it. Approvers keep a
  blocklist of email addresses and domains whose registrations are denied automatically.
- **Group requests.** Any FreeIPA user can ask for a group. On approval, a noggin-visible (FAS) group is
  created, the requester becomes its owner (member manager), and the approver group co-manages it.
- **Group management.** Approvers can change the owner of, rename or delete the groups created this way.

noggin itself is not modified. Approval uses noggin's spam-check hook (`BASSET_URL`), and the governer
talks to FreeIPA through its JSON-RPC API using the settings it reads from noggin's own config file.

## Enable it from noggin's config

Add these lines to `noggin.cfg` and restart noggin:

```python
# --- noggin-governer ---
# Send every new registration to the governer (its hook port, not the public site).
BASSET_URL = "http://<governer-host>:8081/basset"
# New stage users start "waiting", so nobody can activate before approval.
USER_DEFAULTS = {"locale": "en-US", "timezone": "UTC", "status_note": "spamcheck_awaiting"}
# How long (minutes) an approval can take and still use noggin's own validation email. Later approvals still
# work: the registrant is emailed a link to finish instead.
SPAMCHECK_TOKEN_EXPIRATION = 20160

# Settings for the governer itself (it reads this same file). Only the URL is required.
GOVERNER_PUBLIC_URL = "https://acctman.example.org"
# GOVERNER_APPROVER_GROUP = "self-service-managers"        # who may approve
# GOVERNER_GROUP_MANAGER_GROUP = "self-service-managers"   # co-manager of every created group
# GOVERNER_MANAGED_GROUPS_GROUP = "self-service-managed-groups"  # holds every created group
```

Then mount the same file into the governer container at `/etc/noggin/noggin.cfg`. The governer reuses
noggin's `FREEIPA_SERVERS`, `FREEIPA_CACERT`, `FREEIPA_ADMIN_USER`/`FREEIPA_ADMIN_PASSWORD`,
`SECRET_KEY` and `MAIL_*` settings, so there is no second config file to maintain. Anything can also be set,
or overridden, with an environment variable of the same name (`GOVERNER_*`; see [Settings](#settings)).

## Run it next to noggin

```sh
podman run -d --name noggin-governer \
  -v /path/to/noggin.cfg:/etc/noggin/noggin.cfg:ro \
  -v /etc/ipa/ca.crt:/etc/ipa/ca.crt:ro \
  -v noggin-governer-data:/data:U \
  -p 8090:8080 -p 8091:8081 \
  ghcr.io/specnet-io/noggin-governer:latest
```

Mount the CA at the path `FREEIPA_CACERT` names (noggin's container path). Or as a Quadlet unit:

```ini
[Container]
ContainerName=noggin-governer
Image=ghcr.io/specnet-io/noggin-governer:0.1.0
Volume=/opt/noggin-configs/noggin.cfg:/etc/noggin/noggin.cfg:ro
Volume=/etc/ipa/ca.crt:/etc/ipa/ca.crt:ro
Volume=noggin-governer-data:/data:U
PublishPort=8090:8080
PublishPort=8091:8081
Environment=GOVERNER_TRUSTED_PROXIES=10.0.0.41
HealthCmd=/noggin-governer healthcheck

[Install]
WantedBy=multi-user.target
```

- Put **port 8080** (the website) behind your TLS reverse proxy, e.g. `acctman.example.org`.
- Keep **port 8081** (the noggin hook) private: only noggin needs it. Don't route it through the proxy.
- `/data` holds a single `state.json` (pending tokens, group requests, blocklist, activity log). Back it up.

## FreeIPA setup

1. Create the approver group and add the people who approve requests:
   ```sh
   ipa group-add self-service-managers --desc="Approve noggin registrations and group requests"
   ipa group-add-member self-service-managers --users=alice
   ```
   The manager group (same group by default) must exist before the first group request is approved. The
   container group `self-service-managed-groups` is created automatically (non-POSIX, no privileges).
2. The service account (noggin's `FREEIPA_ADMIN_USER`, or `GOVERNER_IPA_USER`) needs to read, change and
   delete stage users, and add, change and delete groups, their members and their member managers. noggin's
   recommended `User Administrator` role includes the stage-user and group privileges. If IPA refuses an
   action, the error is shown on the page; grant the missing permission to that account's role.
3. Groups must be visible to noggin, so the FreeIPA FAS plugin (`freeipa-fas`) must be installed, as noggin
   already requires.

Approvers and requesters sign in with their FreeIPA username and password (append the one-time code if they
use OTP). Signing in to noggin and to the governer are separate.

## Add a "Request a group" button to noggin

noggin has no plugin system, but it loads custom templates. Copy
[`contrib/noggin-templates/after-navbar.html`](contrib/noggin-templates/after-navbar.html) into a directory
listed in noggin's `TEMPLATES_CUSTOM_DIRECTORIES`:

```python
TEMPLATES_CUSTOM_DIRECTORIES = ["/etc/noggin/templates"]
```

Signed-in users then see a **Request a new group** button under noggin's navigation bar, linking to
`GOVERNER_PUBLIC_URL/request-group`. It appears only when `GOVERNER_PUBLIC_URL` is set in `noggin.cfg`.

## Settings

Each setting is read, in order, from the environment variable, the same key in `noggin.cfg`, the noggin
setting in the last column, and the default.

| Variable | Default | Reused noggin setting | Meaning |
|---|---|---|---|
| `GOVERNER_NOGGIN_CONFIG` | `/etc/noggin/noggin.cfg` | | Path of noggin's config inside the container (environment only) |
| `GOVERNER_PUBLIC_URL` | | | This site's public URL; used in email links |
| `GOVERNER_APPROVER_GROUP` | `self-service-managers` | | IPA group whose members (direct or nested) approve |
| `GOVERNER_GROUP_MANAGER_GROUP` | approver group | | Group added as member manager of every created group |
| `GOVERNER_MANAGED_GROUPS_GROUP` | `self-service-managed-groups` | | Group that contains every created group |
| `GOVERNER_IPA_SERVERS` | | `FREEIPA_SERVERS` | Comma-separated IPA servers |
| `GOVERNER_IPA_CACERT` | | `FREEIPA_CACERT` | CA certificate file for IPA |
| `GOVERNER_IPA_USER` / `GOVERNER_IPA_PASSWORD` | | `FREEIPA_ADMIN_USER` / `FREEIPA_ADMIN_PASSWORD` | Service account |
| `GOVERNER_SECRET_KEY` | | `SECRET_KEY` | Session signing secret (32+ characters); a key is derived from it |
| `GOVERNER_MAIL_SERVER` / `GOVERNER_MAIL_PORT` | `25` | `MAIL_SERVER` / `MAIL_PORT` | SMTP relay (no auth) for notifications |
| `GOVERNER_MAIL_SENDER` | | `MAIL_DEFAULT_SENDER` | From address |
| `GOVERNER_MAIL_ENABLED` | on if a server is set | | Turn email off with `false` |
| `GOVERNER_NOGGIN_URL` | from the callback URL | | noggin's public URL, for "finish registration" links |
| `GOVERNER_NOGGIN_CALLBACK_URL` | from noggin | | Override noggin's `/register/spamcheck-hook` URL |
| `GOVERNER_TRUSTED_PROXIES` | | | IPs/CIDRs allowed to set `X-Forwarded-For` (logging, rate limits) |
| `GOVERNER_LISTEN` / `GOVERNER_HOOK_LISTEN` | `:8080` / `:8081` | | Website / noggin hook listeners |
| `GOVERNER_DATA_DIR` | `/data` | | State directory |
| `GOVERNER_INSECURE_COOKIES` | `false` | | Allow plain-HTTP sessions (local testing only) |

On start-up, and as a banner for approvers, the governer warns if noggin's config would let registrations
skip approval (no `BASSET_URL`, or `USER_DEFAULTS` still `active`).

## How a registration flows

1. Someone registers in noggin. noggin creates a stage user and posts it to `BASSET_URL`.
2. The governer checks the stage user exists, applies the blocklist (match: delete it), otherwise holds it
   (`fasstatusnote = spamcheck_manual`) and emails the approvers. noggin shows its "please wait" page.
3. An approver clicks **Approve**: the governer calls noggin's spam-check callback with `active`, and noggin
   emails the registrant the usual validation link. If the token has expired, the governer marks the stage user
   active and emails the registrant a link to noggin's confirmation page instead.
   **Deny** deletes the stage user, optionally blocking the address or its domain.

## Development

```sh
go test ./...
go build -o noggin-governer .
GOVERNER_NOGGIN_CONFIG=./noggin.cfg GOVERNER_INSECURE_COOKIES=true GOVERNER_DATA_DIR=./data ./noggin-governer
```

Pull requests run formatting, `go vet`, tests (with the race detector), `govulncheck` and a container build
([`ci.yml`](.github/workflows/ci.yml)). Releases are cut by hand: **Actions → Release → Run workflow**
with a version such as `v0.1.0` ([`release.yml`](.github/workflows/release.yml)). That tests, pushes
`ghcr.io/specnet-io/noggin-governer:<version>` (plus `:<major>.<minor>` and `:latest`, for amd64 and arm64),
then tags the commit and publishes the GitHub release.

## License

MIT
