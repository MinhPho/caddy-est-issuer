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
- Enrolment over `/simpleenroll` and renewal over `/simplereenroll`, chosen automatically:
  a name set this process has already enrolled is renewed rather than re-enrolled.
- HTTP Basic authentication for enrolment and client-certificate authentication for
  renewal, with the password readable from a Caddy placeholder such as `{env.EST_PASSWORD}`.
- Chain completion from `/cacerts` when the server returns only the leaf, with the
  self-signed root dropped from what is presented to clients.
- A configurable trust anchor for the EST server's own TLS certificate, and an
  `insecure_skip_verify` escape hatch for lab bootstrapping.
- An integration suite that runs against a live EST server, and a local lab that needs no
  licence, credential or configuration.
