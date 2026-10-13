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
vulnsuite list [selector] [-tag TAG]                templates, with state availability
vulnsuite validate [-t SEL]... [-strict]            structure + semantic lint
vulnsuite build -t SEL... | -all [-j N] [-push -registry REG]
vulnsuite run [vulnerable|patched] -t SEL... | -all [-expose MODE] [-detach]
vulnsuite ps                                        running targets (id, state, ip)
vulnsuite targets [-file FILE] [-by ip|alias|host]  scannable URLs, right port per template
vulnsuite stop [-t SEL]... [-prune-net]             tear down
vulnsuite images [-rm]                              locally built images
vulnsuite update-templates                          fetch / update the community templates
```

`-json` on any command gives machine-readable output (progress goes to stderr).
`-engine sdk|api` (or `$VULNSUITE_ENGINE`) picks the daemon client: the Moby
SDK by default, or the built-in API client.
A selector is a folder (`web-servers`), a contract file, or a template id (a
unique substring works: `-t grafana`).

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
| `host` | the port is published on `127.0.0.1` (or `-bind 0.0.0.0`); one host port per target | the scanner is on the host or elsewhere on the network |
| `macvlan` | the target gets its own IP on the LAN via `-parent eth0` | the target must look like a separate device |

On Docker Desktop the host cannot reach container IPs; vulnsuite notices and
tells you to scan from a container or use `-expose host` instead of waiting
out the healthcheck.

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
