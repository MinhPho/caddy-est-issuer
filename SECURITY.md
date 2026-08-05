# Security policy

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/MinhPho/caddy-est-issuer/security/advisories/new).
Please do not open a public issue for a security problem.

Include what you did, what happened, and what you expected. A failing test or a minimal
Caddyfile is the fastest possible report.

Expect an acknowledgement within a week. This is a single-maintainer project, so a fix may
take longer than that; you will be told where it stands rather than left waiting.

## Supported versions

While the version is below 1.0.0, only the latest release receives fixes. Older tags are
not patched.

## Scope

This module obtains and renews the certificates a Caddy server presents, and handles the
credentials that authorise enrolment. Findings of the following kinds are in scope:

- Enrolment or renewal succeeding without the authentication the configuration requires.
- A certificate being accepted whose chain does not verify, or a chain being presented that
  misrepresents its issuer.
- Configured credentials being written to logs, error messages or storage.
- The EST server's TLS certificate not being verified when `insecure_skip_verify` is off.

Out of scope: anything requiring `insecure_skip_verify` to be enabled, which the
documentation states is for lab use only; the behaviour of the certificate authority
itself; and vulnerabilities in Caddy or CertMagic, which belong to those projects.
