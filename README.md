# caddy-est-issuer

A [Caddy](https://caddyserver.com) certificate issuer that obtains and renews TLS
certificates over **EST** (Enrollment over Secure Transport, [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030))
instead of ACME.

Caddy is the EST *client* here. The certificate authority is any external RFC 7030 server.

## Why

Caddy's automatic HTTPS assumes ACME, which assumes the CA can reach your server to
validate a challenge. Inside an enterprise network that assumption usually fails: inbound
traffic to the host is not whitelisted, so HTTP-01 and TLS-ALPN-01 cannot complete, and
DNS-01 requires handing a DNS credential to every host.

EST inverts the direction. Enrolment is client-initiated and outbound only, and the client
authenticates with credentials it already holds - HTTP Basic for the first enrolment, then
the certificate itself for every renewal. Nothing has to reach in.

## Status

Working and tested end to end against a live EST server, but young. Known gaps are listed
under [Limitations](#limitations).

## Install

Caddy modules are compiled in - there is no plugin directory. Each
[GitHub release](https://github.com/MinhPho/caddy-est-issuer/releases) includes Caddy with
this module linked in for Linux on amd64 and arm64. The asset name records the Caddy
version and this module's Git revision.

Download the binary and its checksum with the GitHub CLI. Change `release` and use
`arm64` instead of `amd64` when appropriate:

```sh
release=vX.Y.Z
gh release download "$release" --repo MinhPho/caddy-est-issuer \
  --pattern 'caddy-v*-est-*-linux-amd64' \
  --pattern 'caddy-v*-est-*-linux-amd64.sha256'
sha256sum --check caddy-v*-est-*-linux-amd64.sha256
gh attestation verify caddy-v*-est-*-linux-amd64 \
  --repo MinhPho/caddy-est-issuer
sudo install -m 0755 caddy-v*-est-*-linux-amd64 /usr/local/bin/caddy
```

The checksum detects a damaged download. The attestation verifies that GitHub Actions
built that exact file from this repository. Install only after both checks pass.

To build for another platform or choose a different Caddy version, use
[xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/MinhPho/caddy-est-issuer
```

Confirm the module is present:

```sh
./caddy list-modules | grep tls.issuance.est
```

## Compatibility

Tracks the Caddy v2 line, and is built and tested against the version pinned as
`CADDY_VERSION` in the Makefile.

A Caddy module is compiled into the binary, so the Caddy version that matters is the one you
build with, not the one this repository pins. Name it explicitly to keep a build
reproducible:

```sh
xcaddy build v2.11.4 --with github.com/MinhPho/caddy-est-issuer
```

The only interfaces this module implements are `certmagic.Issuer`, `caddytls.ConfigSetter`
and Caddy's module, provisioner and validator interfaces, all stable across v2, so a new
Caddy release normally needs no change here. The Go toolchain is the one pinned in
`go.mod`.

## Configure

### Caddyfile

```caddyfile
www.example.com {
    tls {
        issuer est {
            server https://pki.example.com:8443
            label tlsserver
            username est-client
            password {env.EST_PASSWORD}
            trusted_ca_file /etc/caddy/est-ca.pem
            client_certificate_file /etc/caddy/est-client.pem
            client_key_file /etc/caddy/est-client-key.pem
        }
    }
    respond "hello"
}
```

| Option | Meaning |
| --- | --- |
| `server` | Base URL of the EST server. Required. |
| `label` | EST label, appended to the well-known path. Some CAs call this the EST alias. |
| `username`, `password` | HTTP Basic credentials for `/simpleenroll`. |
| `trusted_ca_file` | PEM bundle used to verify the EST server's own TLS certificate. Defaults to the system trust store. |
| `client_certificate_file`, `client_key_file` | Client certificate presented when the request has none of its own, which is every request but a renewal. Must be set together. |
| `insecure_skip_verify` | Disables verification of the EST server's TLS certificate. Lab bootstrapping only. |

Keep the password out of the config file: `{env.EST_PASSWORD}` reads it from the
environment, which pairs with a systemd `EnvironmentFile`.

### JSON

The module ID is `tls.issuance.est` and the field names match the table above:

```json
{
  "module": "est",
  "server": "https://pki.example.com:8443",
  "label": "tlsserver",
  "username": "est-client",
  "password": "{env.EST_PASSWORD}"
}
```

## How enrolment and renewal are chosen

CertMagic has no separate renewal entry point - it calls `Issue` for the first issuance and
for every renewal alike. EST does distinguish the two, and a CA may authorise them
differently, so the certificate CertMagic already holds decides which call this is: names
it has a certificate for go to `/simplereenroll`, everything else to `/simpleenroll`.

A re-enrolment authenticates with the certificate it is replacing, read from CertMagic's
storage along with its key, which is what RFC 7030 section 4.2.2 expects. Nothing needs to
be configured for this, and the decision survives a restart because it is not held in
memory. If storage cannot be read, the issuance falls back to `/simpleenroll` rather than
failing.

An EST server may answer `/simpleenroll` with the leaf certificate alone. A TLS server that
presents only a leaf gives clients no path to a trusted root, so the missing issuers are
taken from `/cacerts` (fetched once and cached) and the self-signed root is dropped from
what is served.

## Limitations

- `/serverkeygen` and `/csrattrs` are not implemented. A TLS server generates and keeps its
  own private key, and the CSR is built by CertMagic.
- **A certificate issued outside Caddy cannot seed a renewal.** The first issuance for a
  name is always an enrolment, because the renewal identity comes from CertMagic's own
  storage.

## Development

```sh
make                  # list targets
make hooks            # install the git hooks that gate a commit and a push
make check            # the fast gate - lint, build, unit tests
make push-check       # everything CI runs, before the push leaves the machine
make lab              # a local EST server on https://127.0.0.1:8443
make test-integration
make caddy-verify     # build a Caddy binary and assert the module registered
```

`push-check` is what the `pre-push` hook runs, and CI runs the same targets on every pull
request. Two of them, `test-race` and `build-all`, mirror what Caddy's package registry
rebuilds a listed plugin with, so a portability break surfaces here rather than as the
plugin dropping off the download page.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention and the release process.

The lab is a reference EST server with a transient CA, so a clean checkout can run the
integration tests without a licence or a credential. See [lab/README.md](lab/README.md).
To run them against a real EST server instead:

```sh
EST_LAB_SERVER=https://pki.example.com:8443 make test-integration
```

### Releasing

Move the `Unreleased` entries in [CHANGELOG.md](CHANGELOG.md) into a dated section, then
rehearse the release before tagging, since a tag cannot be moved once the Go module proxy
has served it:

```sh
make release-check VERSION=0.1.0
make release-notes VERSION=0.1.0
```

Pushing the matching `v0.1.0` tag runs the same checks and creates the GitHub release with
Linux amd64 and arm64 Caddy binaries, checksums and build-provenance attestations.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
