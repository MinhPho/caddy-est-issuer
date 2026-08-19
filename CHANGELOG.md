# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is below 1.0.0, the Caddyfile and JSON configuration surface may change
between minor versions. Any such change is listed under Changed with the migration.

## [Unreleased]

### Changed

- Release binaries are built from the tagged module as the Go proxy serves it, rather than
  from the working tree, and are named after the tag instead of the commit. With the pinned
  toolchain, `make caddy-release MODULE_VERSION=<tag>` reproduces the published bytes from
  any machine that sees the same module, so a downstream build can be checked against the
  published checksums and attestation.

## [0.1.1] - 2026-08-19

### Added

- GitHub releases now include Caddy with `tls.issuance.est` linked in for Linux amd64 and
  arm64, SHA-256 checksums and GitHub build-provenance attestations.

### Fixed

- Request bodies are now sent as RFC 2045 base64, wrapped at 76 characters with CRLF line
  ends, as RFC 7030 section 4.2.1 specifies. A single unbroken line was accepted by the lab
  server but rejected as a corrupt PKCS#10 by servers built on OpenSSL's base64 BIO, Cisco's
  libest among them.

## [0.1.0] - 2026-08-06

### Added

- EST certificate issuer registered as the Caddy module `tls.issuance.est`, configurable
  from a Caddyfile block or from JSON.
- Enrolment over `/simpleenroll` and renewal over `/simplereenroll`, chosen from the
  certificate CertMagic holds, so the choice is correct across a restart.
- Renewal authenticated by the certificate being replaced, read from CertMagic's storage
  along with its key, so nothing has to be configured or rotated for renewal to work.
- HTTP Basic authentication for enrolment, with the password readable from a Caddy
  placeholder such as `{env.EST_PASSWORD}`, and an optional client certificate for CAs that
  authenticate enrolment with TLS.
- Chain completion from `/cacerts` when the server returns only the leaf, with the
  self-signed root dropped from what is presented to clients.
- A configurable trust anchor for the EST server's own TLS certificate, and an
  `insecure_skip_verify` escape hatch for lab bootstrapping.
- An integration suite that runs against a live EST server, and a local lab that needs no
  licence, credential or configuration.
