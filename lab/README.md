# Local EST lab

`make lab` runs a reference EST server (MIT licensed) on `https://127.0.0.1:8443`. Started
without a configuration file it generates a random, transient CA, so the lab needs no setup,
no licence and no credentials, and a clean checkout can run the integration tests
immediately.

```sh
make lab               # foreground; leave it running
make test-integration
```

The transient CA is regenerated on every start, so certificates issued by one run are
worthless to the next. That is deliberate: nothing durable is produced, and there is no
state to clean up.

## Why a reference server and not a production CA

Production CAs commonly gate EST behind a paid edition or a licence agreement, and the ones
that do ship it need an issuing CA, a profile and an enrolment credential configured before
they will answer a single request. Depending on one would mean the integration tests could
not run from a clean checkout, could not run in CI, and would fail for reasons belonging to
the CA rather than to this module.

A reference implementation with a transient CA keeps the enrolment path covered on every
pull request. It is the wire protocol that is being tested, and RFC 7030 is the same
protocol on both.

To run the same tests against a real CA:

```sh
EST_LAB_SERVER=https://pki.example.com:8443 make test-integration
```

Many CAs expose EST under a label or alias. Include it in the issuer's `label` option, which
is appended to the well-known path.
