# Using vulnsuite

The CLI reference: every command, how selectors and filters pick templates,
how images are built and published, and how a scanner reaches a running
target. For the template format see [CONTRACT.md](CONTRACT.md); for the
packages behind the CLI see [ARCHITECTURE.md](ARCHITECTURE.md).

- [Commands](#commands)
- [Templates directory and `update-templates`](#templates-directory-and-update-templates)
- [Finding the right target](#finding-the-right-target)
- [Variant groups and `-variants`](#variant-groups-and--variants)
- [Standing up a set: filters and suites as selectors](#standing-up-a-set-filters-and-suites-as-selectors)
- [Building images](#building-images)
- [Running and verifying](#running-and-verifying)
- [Results for pipelines: `-json -summary`](#results-for-pipelines--json--summary)
- [Exposure modes](#exposure-modes--how-your-scanner-reaches-the-target)
- [Scanning the fleet](#scanning-the-fleet-nuclei-or-anything-else)
- [Which scanner template finds this target?](#which-scanner-template-finds-this-target)
- [Fidelity and host requirements](#fidelity-and-host-requirements)
- [Container hardening](#container-hardening)

## Commands

```text
vulnsuite list [selector...] [filters] [-group H] [-variants]    list and filter templates (aliases: ls, search)
vulnsuite info <selector>                                        states, build kinds, probes, scanner templates (alias: show)
vulnsuite validate [-t SEL]... [-strict] [-allow-unpinned]       structure + semantic lint
vulnsuite build [vulnerable|patched] -t SEL... | -f FILE | <filters> | -all [-variants] [-j N] [-push -registry REG]
vulnsuite run [vulnerable|patched] -t SEL... | -f FILE | <filters> | -all [-variants] [-expose MODE] [-detach]
vulnsuite ps                                                     running targets (id, state, ip)
vulnsuite targets [-file FILE] [-by auto|ip|alias|host]          scannable URLs, right port per template
vulnsuite stop [-t SEL]... [-variants] [-prune-net]              tear down (targets, their sidecars and sidecar networks; alias: down)
vulnsuite images [-rm]                                           locally built images
vulnsuite update-templates [-repo OWNER/NAME] [-ref REF] [-force]  fetch / update the community templates (alias: ut)
vulnsuite version                                                version and templates checkout
```

`<filters>` is any of `-ref`, `-class`, `-category`/`-product`, `-tag`,
`-cve`/`-no-cve`, `-kev`/`-no-kev`, `-year`, `-since`, `-fidelity` and `-arch`
(see [Finding the right target](#finding-the-right-target)).
`vulnsuite help <command>` prints every flag of a command.

`-json` on any command gives machine-readable output (progress goes to stderr).
`-engine sdk|api` (or `$VULNSUITE_ENGINE`) picks the daemon client: the Moby
SDK by default, or the built-in API client. Both follow the docker CLI's
context (`DOCKER_CONTEXT`, else `currentContext` in `~/.docker/config.json`)
when `DOCKER_HOST` is unset, and speak TLS to a `tcp://` daemon with
`DOCKER_TLS_VERIFY` / `DOCKER_CERT_PATH` (`ca.pem`, `cert.pem`, `key.pem`).
A selector is a folder (`web-servers`), a contract file, or a template id (a
unique substring works: `-t grafana`). A bare name is always looked up in the
templates directory, so a file or folder called `grafana` in your working
directory never shadows it; to point at something on disk, write it as a path —
anything containing `/`, starting with `.` or `~`, or ending in `.yaml`/`.yml`
(`-t ./grafana`, `-t path/to/contract.yaml`).

`run` and `build` take a state, `vulnerable` or `patched`, anywhere among their
arguments, and flags may follow selectors: `vulnsuite run grafana patched
-detach` and `vulnsuite build patched -t grafana` both work (for `build` it is
shorthand for `-state`). A bare argument spelled like a state is always the
state; a template literally named `vulnerable` or `patched` is still reachable
with `-t`. After `--`, nothing is parsed as a flag.

## Templates directory and `update-templates`

The templates directory is `-templates DIR`, `$VULNSUITE_TEMPLATES`, the
templates repository you are standing in, or `~/vulnsuite-templates`.
`vulnsuite update-templates` fetches the templates into that same directory:

- a git checkout is pulled (`--ff-only`); `-ref BRANCH|TAG|COMMIT` fetches the
  ref from `origin` and checks it out detached (refused while tracked files have
  uncommitted changes). A later plain `update-templates` on such a detached
  checkout fetches `origin` and switches back to its default branch
  (`origin/HEAD`, else `main`), fast-forwarding it; it refuses instead while
  tracked files have uncommitted changes or the detached HEAD has commits no
  branch or tag keeps. A checkout is never replaced, so the update fails if
  `git` is not on `PATH`;
- anything else is replaced by the GitHub archive of `-ref` (default `main`),
  but only when the directory is missing, empty, or was installed by
  `update-templates` (it has a `.vulnsuite-templates-version` marker). Any other
  non-empty directory is refused unless you pass `-force`. The archive is
  refused, and the old directory kept, when it is over 256 MiB, expands past
  512 MiB or 50,000 entries, or holds no templates (a wrong `-repo`). The old
  directory is removed only once the new one is in place.

## Finding the right target

Classification is metadata, not folders. The top directory level
is a single axis — the **product surface** you scan (`web-apps`, `web-servers`,
`databases`, `network-services`, `iot`, `misc`) — and everything else is derived
from the contract, so `list` / `search` can filter by any of it and compose:

```bash
vulnsuite list -ref CVE-2026-109619            # the template(s) for a specific CVE/ref
vulnsuite search CVE-2026-109619                 # the same -- a bare ref works as a selector
vulnsuite list -class misconfig -kev          # misconfigs on the CISA KEV catalog
vulnsuite list -category web-apps -cve        # CVE-tracked web-app targets
vulnsuite search -class exposure -no-cve      # exposures without a CVE
vulnsuite list -year 2021                       # disclosed in 2021 (or CVE-id year)
vulnsuite list -since 2023-01-01                # disclosed on or after a date
```

- `-ref <id>` (repeatable, match any; case-insensitive): a specific `vuln_refs`
  id — `CVE-…`, `GHSA-…`, `GO-…` or a `VS-…` prefix id. Finds secondary refs
  that appear in no template id. A bare ref-shaped selector
  (`search CVE-2026-109619`) resolves against `vuln_refs` too when it matches no
  id/file/folder.
- `-class` (repeatable, match any): `vuln`, `misconfig`, `exposure`,
  `default-login`, `weak-crypto`.
- `-category` / `-product`: the product surface (top directory level).
- `-cve` / `-no-cve`: has (not) any `CVE-…` in `vuln_refs` (boolean; use
  `-ref` for a specific id).
- `-kev` / `-no-kev`: on (not on) the CISA **Known Exploited Vulnerabilities**
  catalog — derived by cross-referencing the target's CVEs. The catalog is read
  from the templates checkout's `data/cisa-kev.txt`; `-refresh-kev` fetches the
  live CISA feed and caches it as `vulnsuite/cisa-kev.json` in the user cache
  directory (`~/.cache` or `$XDG_CACHE_HOME` on Linux, `~/Library/Caches` on
  macOS, `%LocalAppData%` on Windows), which is used instead whenever it holds a newer catalog than the checkout
  (or the checkout's snapshot has no `# catalogVersion` header to date it). A
  cache that holds no CVE ids is ignored with a warning, and a failed cache
  write after `-refresh-kev` is reported. `list`
  prints the source and its age (`kev_source` in `-json`) and warns when the
  data is more than 30 days old. Offline with neither present, KEV shows as `?`
  and `-kev`/`-no-kev` are unavailable.
- `-year` / `-since`: from `metadata.disclosed`, falling back to the CVE-id
  year.

`list` surfaces CATEGORY, CLASS, CVE and KEV as columns.

## Variant groups and `-variants`

Templates that are the same vulnerability expressed differently — a canonical
reproduction plus, say, a WAF-evasion or chunked-encoding variant — can share a
`metadata.group` handle. One member is the **primary** (`primary: true`). A
selector that names a group resolves to its primary; `-variants` expands it to
every member:

```text
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
`run` and `build` apply the same per-template error checks (a probe regex that
does not compile, a missing referenced file, no ports...) before touching the
engine, and treat a template that fails them like one that fails to load; an
unpinned base is allowed there, as while authoring.

## Standing up a set: filters and suites as selectors

`run` and `build` take the same filters as `list` — `-class`, `-tag`,
`-category`/`-product`, `-cve`/`-no-cve`, `-year`, `-since`, `-fidelity`, `-ref`,
`-kev`/`-no-kev`. Every `-t`, every filter, and every line of a `-f` file selects
a set of targets; the run stands up their **union**, de-duplicated:

```text
vulnsuite run -t sshole -t php2shell -class misconfig   # both group primaries + every misconfig
vulnsuite build -class exposure -no-cve                 # all exposures without a CVE
vulnsuite run -f targets.txt                            # a mixed file of selectors
```

Filters *within one line* combine with AND (`-category web-apps -class exposure`
is web-apps **and** exposure); separate selectors and filter lines union with OR.
A filter selects every template that matches, variant-group members included —
it does not collapse groups the way `-all` does — and `list <filter>` shows
exactly the set that `run <filter>` / `build <filter>` will stand up. A
template that fails to load fails the `run` or `build` rather than being skipped;
`list` shows it as unloadable (in every listing, since it cannot be filtered)
and exits 1, and `stop -t` still stops its target by the id its contract
declares.
Filter values are checked up front, on `list`, `run` and `build` alike: `-fidelity`
must be `real` or `simulated`, `-year` a four-digit year and `-since` a
`YYYY-MM-DD` date, so a typo is a usage error (exit 2) rather than a filter
that silently matches nothing.

A **`-f` file** lists one selector per line — an id, a group handle, a category, a
`suite:<name>`, or a filter line (begins with `-`). Blank lines and `#` comments
are ignored:

```text
# my regression set
php2shell            # a group handle -> its primary
redis-unauth-access
-class misconfig     # a filter line: every misconfig
suite:web-basics     # pull in a named suite
```

A **suite** is a named selectors file (`<templates>/suites/<name>.txt`, same
format) reached explicitly with `-t suite:<name>` or a `suite:` line in a file —
never by a bare handle, so standing up a whole curated set is always deliberate.
A mistake in a `-f` or suite file — a selector that matches nothing, a bad
filter line — is reported as `file:line: ...`.
A group handle inside a suite resolves to its primary, or to all members when you
pass `-variants`. Overlapping selectors never start the same target twice.

## Building images

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

Push credentials come from `~/.docker/config.json` (or its credential
helpers), or from `VULNSUITE_REGISTRY_USER` / `VULNSUITE_REGISTRY_TOKEN`. The
env pair names no registry, so it is scoped: by default it is sent **only when
pushing** to `-registry`, never when pulling the base or sidecar images a
template names. Set `VULNSUITE_REGISTRY` (a host such as `ghcr.io`, or the
`-registry` prefix) to also use it for pulls from that registry; it is then
used for that registry only, pulls and pushes alike. `docker.io` (or a Hub
prefix such as `docker.io/you`) matches every Docker Hub reference, bare ones
like `nginx:1.25` included. The pair is never put in a build's registry
config.

## Running and verifying

```bash
vulnsuite run -t exposures -t redis-unauthenticated-access     # a category + one id
vulnsuite run -all -detach -targets-file targets.txt            # the fleet, in the background
vulnsuite run patched -t grafana -expose host -host-port 3000   # the fixed twin, on localhost:3000
```

Every run waits for the healthcheck, then executes the state's `verify`
probes and prints `verify: ok` (or exactly which assertion failed). Up to 10
targets run at once by default (`-max-concurrent`); a bigger batch starts as
many as fit and reports the rest.

## Results for pipelines: `-json -summary`

`run -json` prints the array of started targets and `build -json` the array
of build results. Add `-summary` to either one to get a single
document that also says what did not happen and why, so a pipeline can tell
skipped from failed from not selected:

```bash
vulnsuite -json run -all -detach -summary
# {"targets": [...handles...], "failed": [...], "skipped": [...]}
vulnsuite -json build -all -summary
# {"built": [...results...], "failed": [...results with "error"...], "skipped": [...]}
```

Each `skipped` / `failed` entry of `run` is `{id, state, reason, detail}`, and
each `skipped` entry of `build` has the same shape. `reason` is a stable code:

| reason | list | meaning |
| --- | --- | --- |
| `no-state` | skipped | the template has no such state |
| `requires` | skipped | the host does not meet `requires` (override: `-ignore-requires`) |
| `host-access` | skipped | needs host devices/capabilities (`-allow-host-access`) |
| `over-cap` | skipped | over the `-max-concurrent` cap |
| `cancelled` | skipped | interrupted before it started, or torn down by the interrupt |
| `aborted` | skipped | not attempted: the command stopped on another error (e.g. a load error) |
| `load` | failed | the template failed to load |
| `start` | failed | could not be built, pulled or started |
| `unhealthy` | failed | started but not ready, a seed failed, or verify failed (also in `targets`: it is running) |

The document is printed on failure and on Ctrl-C too, and the exit code is
unchanged: non-zero whenever anything failed or was interrupted. In `build`,
jobs an interrupt stopped before they started are counted (`N ok, M failed, K
cancelled before starting`); in the bare `-json` array they appear with an
`error`.

## Exposure modes — how your scanner reaches the target

| Mode | What happens | Use when |
| --- | --- | --- |
| `internal` (default) | the target joins the `vulnsuite-net` Docker network; nothing is published on the host | your scanner runs as a container (`docker run --network vulnsuite-net ...`) or your host routes to container IPs (Linux, OrbStack) |
| `host` | the primary port is published on the host, by default on `127.0.0.1` (plus any `publish: true` ports); one host port per published port | the scanner is on the host or elsewhere on the network |
| `macvlan` | the target gets its own IP on the LAN via `-parent eth0` | the target must look like a separate device |

**Names on the network.** A target is reachable on `vulnsuite-net` under a
per-state alias, `<id>-<state>` (e.g. `exposed-dotenv-file-vulnerable`), and
its container is `vulnsuite-<id>-<state>`. Both states of a template can run at
once and each name resolves to exactly one of them; `vulnsuite targets -by
alias` prints these aliases.

**Sidecars** (a database, a cache, a second cluster node) belong to one target
state. Each runs as `vulnsuite-<id>-<state>-<sidecar>` on a private network,
`vulnsuite-<id>-<state>-net`, shared only with its target, where it resolves
under its template name (e.g. `db`) in every exposure mode. Sidecars are not
on `vulnsuite-net` and are not scan targets. The private network follows
`-no-egress` in `internal` mode, is a plain bridge in `host` mode (the
target's ports are published from it), and has no egress in `macvlan` mode so
the target's traffic keeps leaving through its LAN address. `vulnsuite stop`
removes the sidecars and their network along with the target.

`vulnsuite ps`, `targets` and `stop` find containers by their
`dev.vulnsuite.*` labels: `stop -t foo` stops exactly template `foo` (never
`foo-bar`), and containers vulnsuite did not start are left alone.

**Ctrl-C.** Interrupting `run` while targets are starting stops the batch,
removes what it had started and exits non-zero (`interrupted`). Interrupting a
held batch tears it down; a removal that fails is reported and fails the
command. A second Ctrl-C during teardown exits at once (finish with
`vulnsuite stop`).

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
published ports get a free host port assigned by the Docker daemon (on its own
machine, so this works with a remote daemon too), all reported by `ps`, `targets` and
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

## Scanning the fleet (Nuclei or anything else)

Don't sweep the subnet — ask vulnsuite for the live targets with their real ports:

```bash
vulnsuite run -t exposures -detach
vulnsuite targets -file targets.txt          # scheme://ip:port per running target
nuclei -l targets.txt
# or from inside the network:
docker run --rm --network vulnsuite-net -v $PWD:/w projectdiscovery/nuclei -l /w/targets.txt
```

## Which scanner template finds this target?

Every template can name the scanner templates that detect it, so deploying a
target also tells you what to point at it:

```yaml
metadata:
  detected_by: ["nuclei:CVE-2021-41773"]   # declared: from the upstream template's fingerprint
  detection: scanner                        # verified: fires on vulnerable, silent on patched
```

`detection: scanner` targets reproduce a named public template's fingerprint;
`detection: custom-only` targets have no public template and exist to test
*your* detection.

`vulnsuite info <id>` and every `vulnsuite run` print the linked scanner templates. With a
nuclei-templates checkout on the machine (`$NUCLEI_TEMPLATES`,
`~/nuclei-templates`, or `-nuclei-templates DIR`) the ids are resolved to
files, templates matching the target's CVEs that nobody declared yet are
suggested, and `vulnsuite validate` warns about ids that don't exist:

```text
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

## Fidelity and host requirements

Every target declares a **fidelity**: `real` runs the genuine affected software
(the default and strongly preferred); `simulated` is a stand-in, only for
bare-OS / device / protocol flaws with no reproducible image. `vulnsuite list
-fidelity real|simulated` filters them.

A target that only runs on a particular host declares a **`requires`** block
(host `arch`, `/dev/kvm`, container-host `host_os`). `vulnsuite run` and
`build` preflight it against the daemon's OS/arch and **skip with a reason**
rather than hanging -- so a KVM / Windows-VM target is skipped cleanly on an
Apple Silicon Mac -- or run cross-arch images under emulation (`-platform`).
`-ignore-requires` overrides; `list -arch <a>` hides targets that can't run on
that arch. See [CONTRACT.md](CONTRACT.md).

## Container hardening

The real isolation for a knowingly-vulnerable target is the no-egress internal
network (`-no-egress`) and a dedicated host — not stripping Linux
capabilities. Targets run with `no-new-privileges` and Docker's default
capability set (which already excludes `SYS_ADMIN`, `NET_ADMIN`,
`SYS_PTRACE`, ...); stock images need caps from that set just to boot. A
contract can tighten per target with `service.cap_drop: [ALL]`, `cap_add`,
`user`, or pass through `devices` (e.g. `/dev/kvm` for VM-backed targets).
