<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/wordmark-on-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/wordmark-on-light.svg">
    <img src=".github/assets/wordmark-on-light.svg" alt="vulnsuite" width="420">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/ruzfi/vulnsuite/actions/workflows/ci.yml"><img src="https://github.com/ruzfi/vulnsuite/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/ruzfi/vulnsuite/releases/latest"><img src="https://img.shields.io/github/v/release/ruzfi/vulnsuite" alt="Latest release"></a>
  <a href="https://pkg.go.dev/github.com/ruzfi/vulnsuite"><img src="https://pkg.go.dev/badge/github.com/ruzfi/vulnsuite.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/ruzfi/vulnsuite" alt="License"></a>
</p>

**Build vulnerable systems on purpose.** Point vulnsuite at a
template and it builds a reproducible, content-addressed Docker image of a
vulnerable system (and of its patched twin), runs it in a known state, and
proves that state with an independent verify probe — so you can validate any
scanner, exploit, or detection rule against ground truth instead of guesswork.

The scanner is **not** part of vulnsuite. You bring your own.

> [!WARNING]
> vulnsuite runs software that is vulnerable on purpose. Use a machine and a
> network you can afford to lose: targets stay on an internal Docker network
> unless you expose them, `-no-egress` cuts their route off the host, and
> `-expose host` publishes on `127.0.0.1` by default. Read the
> [security model](SECURITY.md) before running templates you did not write.

## Install

```bash
go install github.com/ruzfi/vulnsuite/cmd/vulnsuite@latest
# or grab a release binary from GitHub Releases
```

Requirements: a reachable Docker daemon (`DOCKER_HOST` is honoured). `git` is
needed only for templates with a `source` base or a `patch`.

## Quickstart

```bash
vulnsuite update-templates                       # fetch ruzfi/vulnsuite-templates
vulnsuite run -t apache-httpd-2.4.49-cve-2021-41773 -expose host -detach
#   verify: ok -- confirmed vulnerable
#   Scan these with your probe:
#     apache-httpd-2.4.49-cve-2021-41773 [vulnerable]   http://127.0.0.1:49152
vulnsuite targets -file targets.txt              # the live URLs, right port per target
nuclei -l targets.txt                            # or any scanner you want to validate
vulnsuite stop                                   # tear everything down
```

Swap in `run patched` to bring up the fixed twin and check that the scanner
stays quiet. `vulnsuite list` shows what else is in the catalog.

## Why

Validating a vulnerability scanner means answering, for every template it
ships: *does it fire on a system that is really vulnerable, and stay quiet on
the same system once it is fixed?* Doing that by hand — finding the right
version, building it, breaking it, un-breaking it — does not scale past a
handful of CVEs. vulnsuite turns that work into a template anyone can
contribute once and everyone can run anywhere with Docker.

- **Templates are a portable contract.** One folder per target, a
  `contract.yaml` plus the files it references. Nix-inspired: the base is
  pinned (an image digest, or a source repo at a commit) and each state is
  reached by a config overlay and/or a patch. Templates sharing a base reuse
  one build.
- **Images are content-addressed.** A built image is tagged by a hash of its
  inputs. Identical inputs never rebuild. `vulnsuite build -push` publishes
  immutable `:<state>-<hash>` and moving `:<state>` tags to any registry.
- **Every run is verified.** A state's `verify` probes are written from the
  advisory, not copied from a scanner's matcher. A target that does not pass
  its own probe is not handed to you.
- **Fleet-friendly.** Run many targets at once, each with its own IP on an
  internal network; `vulnsuite targets` prints the exact URLs with the right
  ports so you scan those instead of sweeping a subnet.
- **Single static binary.** Talks to the daemon through the official Moby
  SDK (`github.com/moby/moby/client`), with a built-in dependency-free
  Engine API client as an alternative (`-engine api`). Works with Docker
  Engine, Docker Desktop, OrbStack, Colima and Podman's Docker-compatible
  socket; `DOCKER_HOST` and the usual `DOCKER_*` variables are honoured.

## A template

Community templates live in [ruzfi/vulnsuite-templates](https://github.com/ruzfi/vulnsuite-templates),
one folder per target:

```yaml
apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: apache-httpd-2.4.49-cve-2021-41773
  summary: Apache httpd 2.4.49 path traversal via an aliased directory.
  vuln_refs: [CVE-2021-41773]
  severity: high
  references: [https://httpd.apache.org/security/vulnerabilities_24.html]
base:
  kind: image                 # or: source (repo + commit), build (local Dockerfile)
  image: httpd:2.4.49
  digest: sha256:...          # pin it -> reproducible on any device
service:
  ports: [ { container: 80, protocol: http } ]
  healthcheck: { http: { path: /, status: 200 }, timeout: 60s }
states:
  vulnerable:
    overlay: [ { src: files/vuln/httpd.conf, dest: /usr/local/apache2/conf/httpd.conf } ]
    verify:  [ { http: { raw_path: "/icons/.%2e/%2e%2e/etc/passwd", status: 200, body_matches: "root:.*:0:0:" } } ]
  patched:
    overlay: [ { src: files/fixed/httpd.conf, dest: /usr/local/apache2/conf/httpd.conf } ]
    verify:  [ { http: { raw_path: "/icons/.%2e/%2e%2e/etc/passwd", status_in: [403, 404] } } ]
```

Four ways a state reaches its image, cheapest first:

| Kind | How | When |
| --- | --- | --- |
| `image` | run a prebuilt image as-is | pure version CVE (vulnerable vs patched = two tags) |
| `overlay` | image + config files baked into a tiny generated Dockerfile | the flaw is a config toggle |
| `source` | clone a repo at a pinned commit, apply a patch, build | RC / unreleased vulnerable revisions |
| `build` | a Dockerfile + source inside the template | no public image reproduces it (simulations, devices) |

The full field reference is [docs/CONTRACT.md](docs/CONTRACT.md); the JSON
schema for editors and CI is [schemas/contract.schema.json](schemas/contract.schema.json).

## Commands

| Command | What it does |
| --- | --- |
| `list` (`ls`, `search`) | list and filter templates by class, CVE, KEV, product surface, year |
| `info` (`show`) | a template's states, build kinds, probes and the scanner templates that detect it |
| `validate` | structure and semantic lint for template contracts |
| `build` | build (or pull) images, content-addressed, in parallel; `-push` publishes them |
| `run` | build if needed, run targets in a state and verify them |
| `stamp` | run every state of a target and record `metadata.verified_on` when all verify ok |
| `ps` | running targets (id, state, ip) |
| `targets` | scannable URLs of the running targets, right port per template |
| `stop` (`down`) | tear down targets, their sidecars and sidecar networks |
| `images` | list or remove locally built images |
| `host` (`doctor`) | what the daemon's machine offers targets: arch, CPU flags, `/dev/kvm`, kernel, amd64 emulation |
| `update-templates` (`ut`) | fetch or update the community templates |

`vulnsuite help <command>` prints every flag. The full reference is
[docs/USAGE.md](docs/USAGE.md):

- [Selectors, states and global flags](docs/USAGE.md#commands)
- [Templates directory and `update-templates`](docs/USAGE.md#templates-directory-and-update-templates)
- [Finding the right target](docs/USAGE.md#finding-the-right-target): filters by ref, class, category, CVE, KEV, year
- [Variant groups](docs/USAGE.md#variant-groups-and--variants), and [filters, `-f` files and suites as selectors](docs/USAGE.md#standing-up-a-set-filters-and-suites-as-selectors)
- [Building images](docs/USAGE.md#building-images), pushing them and registry credentials
- [Running and verifying](docs/USAGE.md#running-and-verifying), and [`-json -summary` results for pipelines](docs/USAGE.md#results-for-pipelines--json--summary)
- [Exposure modes](docs/USAGE.md#exposure-modes--how-your-scanner-reaches-the-target): `internal`, `host`, `macvlan`, sidecars, remote daemons
- [Scanning the fleet](docs/USAGE.md#scanning-the-fleet-nuclei-or-anything-else) and [which scanner template finds a target](docs/USAGE.md#which-scanner-template-finds-this-target)
- [Fidelity and host requirements](docs/USAGE.md#fidelity-and-host-requirements), and [container hardening](docs/USAGE.md#container-hardening)

## Automating the whole loop

Everything vulnsuite does is scriptable, which is the point: a target is only
useful as ground truth if a machine can stand it up, prove it, scan it and
tear it down without a human in the loop.

- Every command takes `-json` and returns structured output (progress goes
  to stderr; empty results are `[]`), and exits non-zero when a target fails
  to build, start or verify. Flag mistakes exit 2. `-q` silences progress,
  never a command's output (`vulnsuite -q targets` still prints the URLs).
- `vulnsuite run -detach -targets-file` plus `vulnsuite targets` give a
  scanner exactly the URLs to hit; `vulnsuite stop` cleans up.
- The Go packages (`loader`, `builder`, `runner`, `probes`) are importable,
  so a pipeline can drive targets directly and read verify results as values
  instead of parsing text.
- Built images are content-addressed and can be pushed to a registry, so CI
  can pre-build once and run many validation jobs against the same immutable
  image.

A typical end-to-end use: for every scanner template you ship, bring up the
matching target **vulnerable**, run the scanner and expect a hit; bring it up
**patched**, run the scanner and expect silence. A template that fires on
patched is a false positive you just caught before a customer did; one that
is silent on vulnerable is a false negative. Run that nightly against the
scanner's current template set and regressions surface the day they land.
vulnsuite gives that loop its ground truth; the scoring and reporting on top
is a few dozen lines in whatever language your pipeline speaks.

## Using vulnsuite as a library

Every package under `pkg/` is importable: `loader` finds and parses
templates, `validator` lints them, `builder` and `runner` do the work on any
`engine.Engine` (`engine/moby` wraps the official SDK, `engine/docker` is the
built-in client, `engines.New` picks one), and `engine/enginetest` is an
in-memory engine for tests.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```go
store := loader.New("/path/to/vulnsuite-templates")
c, _ := store.LoadSelector("grafana-8.3.0-cve-2021-43798")
eng, _ := engines.New("sdk", "")
h, _ := runner.New(eng).Run(ctx, c, "vulnerable", runner.DefaultExposure(), runner.Options{Verify: true})
fmt.Println(h.ScannerTarget(), *h.VerifyOK)
```

## Background

This started as a practical frustration with doing that validation by hand,
one machine at a time, for hundreds of CVEs. Nuclei had already shown that *detection* scales when it is
written as a small, portable, community-maintained template. The obvious
question was: why not the same thing for *deployment*? A nuclei-style template
that, instead of describing how to find a vulnerability, describes how to
build and run it. That question is this project.

vulnsuite was designed and written with the help of AI, as a deliberate
experiment in **collaborative intelligence**: the problem, the constraints and
every design decision (the contract format, pinning, content-addressed builds,
independent verification, the exposure modes) came from hands-on scanner
validation work; the implementation, the tests and much of the documentation
were produced together with an AI assistant and reviewed line by line. The
templates repository carries an authoring guide ([SKILL.md](https://github.com/ruzfi/vulnsuite-templates/blob/main/SKILL.md))
written so that the same collaboration works for contributors: hand an
assistant a CVE or a scanner template and the guide, and it can draft a
validated target for you to review. We think that is how a catalog of
thousands of reproducible targets actually gets built.

## Prior art and neighbours

- **[nuclei](https://github.com/projectdiscovery/nuclei)** is the model for
  the template-driven, community-maintained approach, and the scanner most
  people will validate first. vulnsuite is its mirror image: nuclei templates
  say how to detect, vulnsuite templates say how to deploy.
- **[pocsuite3](https://github.com/knownsec/pocsuite3)** (Knownsec 404) is a
  PoC and exploit framework. It can start a Docker environment declared in a
  PoC (`--docker-start`) so you have something to test against, but that is
  a convenience inside a scanner: a single unpinned image, no patched twin, no
  verification. vulnsuite is the other half of that picture, a dedicated,
  verified, reproducible target provisioner that frameworks like pocsuite3 or
  nuclei can be pointed at.
- **Vulhub, DVWA, Metasploitable, VulnHub** and similar collections provide
  vulnerable environments, usually as hand-written compose files or VM images,
  with no notion of a patched counterpart, a pinned base, or a probe that
  proves the state. Several of them are excellent sources for *authoring*
  vulnsuite templates.

## Contributing

Templates go to [vulnsuite-templates](https://github.com/ruzfi/vulnsuite-templates);
engine and CLI changes here. See [CONTRIBUTING.md](CONTRIBUTING.md) — commits
follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## License

MIT — see [LICENSE](LICENSE).
