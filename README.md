# vulnsuite

**Build vulnerable systems on purpose.** Point vulnsuite at a
template and it builds a reproducible, content-addressed Docker image of a
vulnerable system (and of its patched twin), runs it in a known state, and
proves that state with an independent verify probe — so you can validate any
scanner, exploit, or detection rule against ground truth instead of guesswork.

```
vulnsuite update-templates                       # fetch ruzfi/vulnsuite-templates
vulnsuite build -t web-servers                   # build every web-server target, 4 in parallel
vulnsuite run -t apache-httpd-2.4.49-cve-2021-41773 -expose host
#   verify: ok -- confirmed vulnerable
#   Scan these with your probe:
#     apache-httpd-2.4.49-cve-2021-41773 [vulnerable]   http://127.0.0.1:49152
```

The scanner is **not** part of vulnsuite. You bring your own.

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

## The idea

This started as a very practical frustration: validating a vulnerability
scanner means standing up the vulnerable system for each template it ships,
confirming the flaw is really there, then fixing it and confirming the scanner
goes quiet. Doing that by hand, one machine at a time, for hundreds of CVEs
does not scale. Nuclei had already shown that *detection* scales when it is
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

## Automating the whole loop

Everything vulnsuite does is scriptable, which is the point: a target is only
useful as ground truth if a machine can stand it up, prove it, scan it and
tear it down without a human in the loop.

- Every command takes `-json` and returns structured output (progress goes
  to stderr), and exits non-zero when a target fails to build, start or
  verify.
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

## Install

```bash
go install github.com/ruzfi/vulnsuite/cmd/vulnsuite@latest
# or grab a release binary from GitHub Releases
```

Requirements: a reachable Docker daemon (`DOCKER_HOST` is honoured). `git` is
needed only for templates with a `source` base or a `patch`.

## Templates

Community templates live in [ruzfi/vulnsuite-templates](https://github.com/ruzfi/vulnsuite-templates).
`vulnsuite update-templates` fetches them into `~/vulnsuite-templates`; the
templates directory is otherwise `-templates DIR`, `$VULNSUITE_TEMPLATES`, or
the repository you are standing in.

A template:

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

```
vulnsuite list [selector] [-group H] [-variants] [-ref ID]... [-class C]... [-category P] [-cve] [-kev] [-year Y]  filter templates
vulnsuite search ...                                alias for list
vulnsuite validate [-t SEL]... [-strict]            structure + semantic lint
vulnsuite build -t SEL... | -f FILE | <filter> | -all [-variants] [-j N] [-push -registry REG]
vulnsuite run [vulnerable|patched] -t SEL... | -f FILE | <filter> | -all [-variants] [-expose MODE] [-detach]
vulnsuite ps                                        running targets (id, state, ip)
vulnsuite targets [-file FILE] [-by auto|ip|alias|host]  scannable URLs, right port per template
vulnsuite stop [-t SEL]... [-prune-net]             tear down
vulnsuite images [-rm]                              locally built images
vulnsuite update-templates                          fetch / update the community templates
```

`-json` on any command gives machine-readable output (progress goes to stderr).
`-engine sdk|api` (or `$VULNSUITE_ENGINE`) picks the daemon client: the Moby
SDK by default, or the built-in API client.
A selector is a folder (`web-servers`), a contract file, or a template id (a
unique substring works: `-t grafana`).

### Variant groups and `-variants`

Templates that are the same vulnerability expressed differently — a canonical
reproduction plus, say, a WAF-evasion or chunked-encoding variant — can share a
`metadata.group` handle. One member is the **primary** (`primary: true`). A
selector that names a group resolves to its primary; `-variants` expands it to
every member:

```
vulnsuite run -t php2shell                 # just the primary
vulnsuite run -t php2shell -variants       # every member of the family
vulnsuite run -t php2shell-waf-evasion     # one exact variant (an id; -variants is a no-op)
vulnsuite list -group php2shell            # the whole family, one row per member
vulnsuite info php2shell                   # the family: primary + each variant
```

Resolution precedence: **exact id → exact group (→ its primary) → category folder
→ unique substring.** A lone target that sets a `group` is just a nickname for
its id (no `primary`/`variant` needed), so `-t php2shell` works without renaming
the target.

`-all` operates per family: by default it takes one target per group (the
primary) plus every ungrouped target; `-all -variants` is the full matrix. This
keeps `build -all` / `run -all` lean while `-all -variants` gives you everything.
`validate` always checks every member, with or without `-variants`, so a family's
rules (exactly one primary, unique variants) are enforced whole.

### Standing up a set: filters and suites as selectors

`run` and `build` take the same filters as `list` — `-class`, `-tag`,
`-category`/`-product`, `-cve`/`-no-cve`, `-year`, `-since`, `-fidelity`, `-ref`,
`-kev`/`-no-kev`. Every `-t`, every filter, and every line of a `-f` file selects
a set of targets; the run stands up their **union**, de-duplicated:

```
vulnsuite run -t sshole -t php2shell -class misconfig   # both group primaries + every misconfig
vulnsuite build -class exposure -no-cve                 # all exposures without a CVE
vulnsuite run -f targets.txt                            # a mixed file of selectors
```

Filters *within one line* combine with AND (`-category web-apps -class exposure`
is web-apps **and** exposure); separate selectors and filter lines union with OR.

A **`-f` file** lists one selector per line — an id, a group handle, a category, a
`suite:<name>`, or a filter line (begins with `-`). Blank lines and `#` comments
are ignored:

```
# my regression set
php2shell            # a group handle -> its primary
redis-unauth-access
-class misconfig     # a filter line: every misconfig
suite:web-basics     # pull in a named suite
```

A **suite** is a named selectors file (`<templates>/suites/<name>.txt`, same
format) reached explicitly with `-t suite:<name>` or a `suite:` line in a file —
never by a bare handle, so standing up a whole curated set is always deliberate.
A group handle inside a suite resolves to its primary, or to all members when you
pass `-variants`. Overlapping selectors never start the same target twice.

### Building images

`build` is the heart of vulnsuite: it resolves every requested state to an
image, in parallel, and skips anything whose content hash already exists.

```bash
vulnsuite build -all -j 8                      # everything, 8 at a time
vulnsuite build -t iot -state vulnerable        # one state for a category
vulnsuite build -t grafana -force -no-cache     # rebuild from scratch
vulnsuite build -all -push -registry ghcr.io/you/vulnsuite
```

Built images carry labels (`dev.vulnsuite.id`, `.state`, `.hash`,
`.vuln_refs`) and bake the state's environment in, so a published image is
self-contained: `docker run ghcr.io/you/vulnsuite/<id>:vulnerable` is the
vulnerable target, no vulnsuite needed.

### Running and verifying

```bash
vulnsuite run -t exposures -t redis-unauthenticated-access     # a category + one id
vulnsuite run -all -detach -targets-file targets.txt            # the fleet, in the background
vulnsuite run patched -t grafana -expose host -host-port 3000   # the fixed twin, on localhost:3000
```

Every run waits for the healthcheck, then executes the state's `verify`
probes and prints `verify: ok` (or exactly which assertion failed). Up to 10
targets run at once by default (`-max-concurrent`); a bigger batch starts as
many as fit and reports the rest.

### Exposure modes — how your scanner reaches the target

| Mode | What happens | Use when |
| --- | --- | --- |
| `internal` (default) | the target joins the `vulnsuite-net` Docker network; nothing is published on the host | your scanner runs as a container (`docker run --network vulnsuite-net ...`) or your host routes to container IPs (Linux, OrbStack) |
| `host` | the primary port is published on the host, by default on `127.0.0.1` (plus any `publish: true` ports); one host port per published port | the scanner is on the host or elsewhere on the network |
| `macvlan` | the target gets its own IP on the LAN via `-parent eth0` | the target must look like a separate device |

In `host` mode, `-bind <address>` chooses the address the port is published on
(default `127.0.0.1`). Pass the Docker daemon host's reachable address when the
daemon is not the machine running your scanner — it is the single flag that
makes a remote daemon usable. `vulnsuite targets` reports that bound address, so
the URLs it prints work from the scanner's machine; a port bound to all
interfaces (`-bind 0.0.0.0`) is reported as `127.0.0.1`.

A template may publish more than one port: the primary is always published, and
any port marked `publish: true` in the contract is published alongside it and
added to the scanner target lists. `-host-port` pins the primary's host port;
`-host-port-map container=host` pins an additional one (repeatable). Unpinned
published ports get free host ports, all reported by `ps`, `targets` and
`-targets-file`:

```bash
vulnsuite run -t <target> -expose host \
  -host-port 39841 -host-port-map 8091=39842 -detach
```

On Docker Desktop the host cannot reach container IPs; vulnsuite notices and
tells you to scan from a container or use `-expose host` instead of waiting
out the healthcheck. The same is true when the daemon is remote (`internal`
targets live on the daemon host's network, not yours) — there too, `-expose
host -bind <daemon address>` gives you a scannable URL.

### Scanning the fleet (Nuclei or anything else)

Don't sweep the subnet — ask vulnsuite for the live targets with their real ports:

```bash
vulnsuite run -t exposures -detach
vulnsuite targets -file targets.txt          # scheme://ip:port per running target
nuclei -l targets.txt
# or from inside the network:
docker run --rm --network vulnsuite-net -v $PWD:/w projectdiscovery/nuclei -l /w/targets.txt
```

Each template says whether a stock scanner can find it: `detection: scanner`
targets reproduce a named public template's fingerprint (`detected_by:
["nuclei:laravel-env"]`), `detection: custom-only` targets have no public
template and exist to test *your* detection.

## Which scanner template finds this target?

Every template can name the scanner templates that detect it, so deploying a
target also tells you what to point at it:

```yaml
metadata:
  detected_by: ["nuclei:CVE-2021-41773"]   # declared: from the upstream template's fingerprint
  detection: scanner                        # verified: fires on vulnerable, silent on patched
```

`vulnsuite info <id>` and every `vulnsuite run` print them. With a
nuclei-templates checkout on the machine (`$NUCLEI_TEMPLATES`,
`~/nuclei-templates`, or `-nuclei-templates DIR`) the ids are resolved to
files, templates matching the target's CVEs that nobody declared yet are
suggested, and `vulnsuite validate` warns about ids that don't exist:

```
$ vulnsuite info ssh-version-cve-2018-15473
...
scanner templates:
  none known. No scanner template is linked to this target, and the local
  nuclei-templates checkout has none for CVE-2018-15473.
  this is a detection gap: a target exists but nothing can find it. Write a
  nuclei template for it, verify it against both states, contribute it
  upstream (https://github.com/projectdiscovery/nuclei-templates), then add
  nuclei:<id> to detected_by in ssh-version-cve-2018-15473/contract.yaml
```

That last case is the point: a vulnsuite target with no scanner template is a
ready-made, verified test bed for writing one. The template catalog therefore
doubles as a to-do list for the detection ecosystem — `vulnsuite list` shows
the DETECTED BY column, and `custom-only` marks targets that exist purely to
test your own detection.

## Finding the right target

Classification is metadata, not folders (taxonomy v2). The top directory level
is a single axis — the **product surface** you scan (`web-apps`, `web-servers`,
`databases`, `network-services`, `iot`, `misc`) — and everything else is derived
from the contract, so `list` / `search` can filter by any of it and compose:

```bash
vulnsuite list --ref CVE-2026-109619            # the template(s) for a specific CVE/ref
vulnsuite search CVE-2026-109619                 # the same -- a bare ref works as a selector
vulnsuite list --class misconfig --kev          # misconfigs on the CISA KEV catalog
vulnsuite list --category web-apps --cve        # CVE-tracked web-app targets
vulnsuite search --class exposure --no-cve      # exposures without a CVE
vulnsuite list --year 2021                       # disclosed in 2021 (or CVE-id year)
vulnsuite list --since 2023-01-01                # disclosed on or after a date
```

- `--ref <id>` (repeatable, match any; case-insensitive): a specific `vuln_refs`
  id — `CVE-…`, `GHSA-…`, `GO-…` or a `VS-…` prefix id. Finds secondary refs
  that appear in no template id. A bare ref-shaped selector
  (`search CVE-2026-109619`) resolves against `vuln_refs` too when it matches no
  id/file/folder.
- `--class` (repeatable, match any): `vuln`, `misconfig`, `exposure`,
  `default-login`, `weak-crypto`.
- `--category` / `--product`: the product surface (top directory level).
- `--cve` / `--no-cve`: has (not) any `CVE-…` in `vuln_refs` (boolean; use
  `--ref` for a specific id).
- `--kev` / `--no-kev`: on (not on) the CISA **Known Exploited Vulnerabilities**
  catalog — derived by cross-referencing the target's CVEs. The catalog is read
  from the templates checkout's `data/cisa-kev.txt`; `--refresh-kev` fetches the
  live CISA feed and caches it at `~/.cache/vulnsuite/cisa-kev.json`. Offline
  with neither present, KEV shows as `?` and `--kev`/`--no-kev` are unavailable.
- `--year` / `--since`: from `metadata.disclosed`, falling back to the CVE-id
  year.

`list` surfaces CATEGORY, CLASS, CVE and KEV as columns.

## Fidelity and host requirements

Every target declares a **fidelity**: `real` runs the genuine affected software
(the default and strongly preferred); `simulated` is a stand-in, only for
bare-OS / device / protocol flaws with no reproducible image. `vulnsuite list
-fidelity real|simulated` filters them.

A target that only runs on a particular host declares a **`requires`** block
(host `arch`, `/dev/kvm`, container-host `host_os`). `vulnsuite run` and
`build` preflight it against the daemon's OS/arch and **skip with a reason**
rather than hanging -- so a KVM / Windows-VM target is skipped cleanly on an
Apple Silicon Mac -- or run cross-arch images under emulation (`--platform`).
`-ignore-requires` overrides; `list -arch <a>` hides targets that can't run on
that arch. See [docs/CONTRACT.md](docs/CONTRACT.md).

## Container hardening

The real isolation for a knowingly-vulnerable target is the no-egress internal
network (`-no-egress`) and a dedicated host — not stripping Linux
capabilities. Targets run with `no-new-privileges` and Docker's default
capability set (which already excludes `SYS_ADMIN`, `NET_ADMIN`,
`SYS_PTRACE`, ...); stock images need caps from that set just to boot. A
contract can tighten per target with `service.cap_drop: [ALL]`, `cap_add`,
`user`, or pass through `devices` (e.g. `/dev/kvm` for VM-backed targets).

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

## Contributing

Templates go to [vulnsuite-templates](https://github.com/ruzfi/vulnsuite-templates);
engine and CLI changes here. See [CONTRIBUTING.md](CONTRIBUTING.md) — commits
follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## License

MIT — see [LICENSE](LICENSE).
