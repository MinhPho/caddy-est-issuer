# caddy-est-issuer

A [Caddy](https://caddyserver.com) certificate issuer that obtains and renews TLS
certificates over **EST** (Enrollment over Secure Transport, [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030))
instead of ACME.

Caddy is the EST *client* here. The certificate authority is any external RFC 7030 server.

## Why

Caddy's automatic HTTPS assumes ACME, which assumes the CA can reach your server to
validate a challenge. Inside an enterprise or factory network that assumption usually
fails: inbound traffic to the host is not whitelisted, so HTTP-01 and TLS-ALPN-01 cannot
complete, and DNS-01 requires handing a DNS credential to every host.

EST inverts the direction. Enrolment is client-initiated and outbound only, and the client
authenticates with credentials it already holds - HTTP Basic for the first enrolment, then
the certificate itself for every renewal. Nothing has to reach in.

> This is the opposite direction from [hslatman/caddy-est](https://github.com/hslatman/caddy-est),
> which makes Caddy serve the EST protocol to other clients.

## Status

Working and tested end to end against a live EST server, but young. Known gaps are listed
under [Limitations](#limitations).

## Install

Caddy modules are compiled in - there is no plugin directory. Build a Caddy binary with
[xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/MinhPho/caddy-est-issuer
```

Confirm the module is present:

```sh
./caddy list-modules | grep tls.issuance.est
```

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
| `client_certificate_file`, `client_key_file` | Client certificate presented to `/simplereenroll`. Must be set together. |
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
differently, so this issuer tracks which SAN sets it has already enrolled and sends those
to `/simplereenroll`. Re-enrolment authenticates with the client certificate, so it is only
attempted when one is configured.

An EST server may answer `/simpleenroll` with the leaf certificate alone. A TLS server that
presents only a leaf gives clients no path to a trusted root, so the missing issuers are
taken from `/cacerts` (fetched once and cached) and the self-signed root is dropped from
what is served.

## Limitations

- **Enrolment tracking is per process.** The first issuance after a Caddy restart goes to
  `/simpleenroll` even for a name Caddy already holds a certificate for. Servers that
  reject a duplicate enrolment will refuse it.
- **The re-enrolment certificate is a configured file**, not the certificate CertMagic
  currently holds. Rotating it is the deployment's job today.
- `/serverkeygen` and `/csrattrs` are not implemented. A TLS server generates and keeps its
  own private key, and the CSR is built by CertMagic.

## Development

```sh
make                  # list targets
make check            # lint, build, unit tests - what CI runs
make vuln             # check dependencies against the Go vulnerability database
make lab              # a local EST server on https://127.0.0.1:8443
make test-integration
make caddy-verify     # build a Caddy binary and assert the module registered
```

The lab is a reference EST server with a transient CA, so a clean checkout can run the
integration tests without a licence or a credential. See [lab/README.md](lab/README.md).
To run them against a real EST server instead:

```sh
EST_LAB_SERVER=https://pki.example.com:8443 make test-integration
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
