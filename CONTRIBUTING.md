# Contributing to vulnsuite

Thanks for helping make scanner validation reproducible. This repository holds
the engine and CLI; vulnerable-target **templates** are contributed to
[ruzfi/vulnsuite-templates](https://github.com/ruzfi/vulnsuite-templates)
(see its own CONTRIBUTING.md).

## Development

```bash
git clone https://github.com/ruzfi/vulnsuite && cd vulnsuite
make build          # ./bin/vulnsuite
make test           # unit tests, no Docker needed
make e2e            # end-to-end against your local Docker daemon
make lint           # gofmt + go vet
```

Go 1.24 or newer. The only runtime dependency is a Docker-compatible daemon.
The module depends on `github.com/goccy/go-yaml` and the official Moby SDK
(`github.com/moby/moby/client` + `api`); please don't add more without a
discussion. Anything that needs a different backend implements
`engine.Engine` (see `pkg/engine/moby` and the dependency-free
`pkg/engine/docker` for two examples).

Layout:

```
cmd/vulnsuite      main
internal/cli       commands (stdlib flag; one file per command group)
internal/e2e       end-to-end test (VULNSUITE_E2E=1)
pkg/contract       the template contract: types, strict decoding, content hashing
pkg/loader         template discovery and loading
pkg/validator      semantic lint
pkg/builder        content-addressed image builds (overlay / source / build) and publishing
pkg/runner         exposure modes, readiness, verification, fleet management
pkg/probes         raw-socket HTTP / TCP / exec verify probes
pkg/engine         the container engine interface; moby/ (official SDK, default) and docker/ (built-in API client)
                   implementations; engines/ picks one; registryauth/ credentials; enginetest/ fake
pkg/templates      templates directory resolution and update-templates
pkg/scanners       links targets to scanner templates (detected_by), nuclei-templates index
schemas/           JSON schema of the contract (kept in sync with pkg/contract)
```

## Branches

- `main` is protected and holds the released, CI-green state. **Do not push to
  `main` directly** — it only advances through reviewed, squash-merged pull
  requests.
- `dev` is the integration branch. **Base all work on `dev`.** Branch from it,
  and open your pull request against `dev`, not `main`.
- Maintainers promote `dev` to `main` for releases.

```bash
git switch dev && git pull
git switch -c feat/my-change      # or fix/..., docs/...
# ...work, commit...
git push -u origin feat/my-change # then open a PR targeting `dev`
```

## Pull requests
All pull requests target the `dev` branch (see **Branches** above); `main` is updated only by maintainers at release time.


1. Open an issue first for anything bigger than a bug fix, so the design can be
   discussed before the code.
2. Add or update tests. `pkg/engine/enginetest` lets builder/runner/CLI
   behaviour be tested without a daemon; `internal/e2e` covers the real thing.
3. Keep `go vet` and `gofmt` clean; CI runs both plus the unit tests on Linux,
   macOS and Windows.
4. If you change the contract (`pkg/contract`), update
   `schemas/contract.schema.json` and `docs/CONTRACT.md` in the same PR, and
   keep every template in vulnsuite-templates loading (`vulnsuite validate`).
5. One logical change per PR; PRs are squash-merged with the PR title as the
   commit message, so the title must follow Conventional Commits (below).

## Commit messages: Conventional Commits

All commits and PR titles follow
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<optional scope>)!: <description>

[optional body]

[optional footer(s)]
```

Types we use:

| Type | Use for |
| --- | --- |
| `feat` | a new capability (a command, a flag, a new probe kind, a new base kind) |
| `fix` | a bug fix |
| `perf` | a performance improvement with no behaviour change |
| `refactor` | code change that neither fixes a bug nor adds a feature |
| `docs` | documentation only |
| `test` | adding or correcting tests |
| `build` | build system, dependencies, release tooling |
| `ci` | CI configuration |
| `chore` | maintenance that touches none of the above |

Scopes are package or area names: `builder`, `runner`, `probes`, `engine`,
`moby`, `cli`, `contract`, `loader`, `validator`, `templates`, `schema`.

A breaking change (anything that stops an existing template from loading or
changes CLI behaviour incompatibly) carries `!` after the type/scope **and** a
`BREAKING CHANGE:` footer. Examples:

```
feat(builder): push immutable and moving tags with -push
fix(probes): decode chunked bodies before matching
perf(builder): resolve image states in parallel
docs: document exposure modes on Docker Desktop
feat(contract)!: drop a deprecated apiVersion alias

BREAKING CHANGE: templates must declare apiVersion: vulnsuite/v1.
```

The description is imperative, lower-case, no trailing period, at most 72
characters. Reference issues in the footer (`Refs: #12`, `Closes: #34`).

## Releases

Versions follow SemVer and are cut from `main` with a `vX.Y.Z` tag; the
changelog is generated from the Conventional Commit history. Binaries for
Linux, macOS and Windows are attached to the GitHub release.

## Code of conduct

Be kind, assume good faith, and remember that the targets in this ecosystem
are deliberately vulnerable: never point a published image at a network you
do not own.
