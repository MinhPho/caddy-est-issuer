# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is below 1.0.0, the Caddyfile and JSON configuration surface may change
between minor versions. Any such change is listed under Changed with the migration.

## [Unreleased]

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
