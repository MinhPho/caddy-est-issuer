# Contributing

## Setup

You need [Go](https://go.dev/dl/) as pinned in `go.mod`, and
[prek](https://prek.j178.dev) to run the git hooks.

```sh
git clone https://github.com/MinhPho/caddy-est-issuer.git
cd caddy-est-issuer
make hooks
```

`make hooks` installs three git shims. They are where the quality gate lives, so a break
is caught before it leaves your machine rather than a quarter of an hour later in CI:

| Shim | Runs |
| --- | --- |
| `pre-commit` | gitleaks, actionlint, gofmt, and file hygiene over the staged files |
| `commit-msg` | the Conventional Commits format |
| `pre-push` | `make push-check` - lint, build, unit tests, govulncheck, the race detector, and a build for every platform |

Everything a hook runs is a make target, and CI runs the same targets. Nothing exists only
in the pipeline.

Run the hooks over the whole tree at any time:

```sh
prek run --all-files
```

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/), enforced by the `commit-msg`
hook, because the changelog is written from these subjects:

```text
<type>(<scope>): <description>
```

Types in use here: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`,
`chore`. Scope is optional. Describe the behaviour change, not the edit - `fix(est): send
the client certificate on a re-enrolment`, not `update client.go`.

## Pull requests

Fork, branch, and open a pull request against `main`. CI runs the unit tests, the
integration suite against a live EST server, and a check that the module registers in a
real Caddy binary.

Before you open it:

```sh
make push-check
```

Keep a pull request to one change. Add tests in the same commit as the behaviour they
cover, and add a `CHANGELOG.md` entry under `Unreleased` for anything a user of the module
would notice.

## Releases

Maintainer only. Move the `Unreleased` entries into a dated section, rehearse, then tag:

```sh
make release-check VERSION=0.1.0
make release-notes VERSION=0.1.0
```

Pushing the matching `v0.1.0` tag runs the same gate again and creates the GitHub release.
A tag is the one irreversible step in this project: the Go module proxy serves it
permanently and it cannot be moved, which is why the tag namespace is protected against
deletion and force-update.
