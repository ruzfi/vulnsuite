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
vulnsuite list [selector...] [filters] [-variants] [-runnable]   list and filter templates (aliases: ls, search)
vulnsuite list -group H [filters] [-runnable]                    one variant group (no selectors alongside)
vulnsuite info <selector>                                        states, build kinds, probes, scanner templates (alias: show)
vulnsuite validate [-t SEL]... [-strict] [-allow-unpinned]       structure + semantic lint
vulnsuite build [vulnerable|patched] -t SEL... | -f FILE | <filters> | -all [-variants] [-j N] [-push -registry REG]
vulnsuite run [vulnerable|patched] -t SEL... | -f FILE | <filters> | -all [-variants] [-expose MODE] [-detach]
vulnsuite stamp -t SEL... | -f FILE | <filters> | -all [-dry-run]  run every state; record metadata.verified_on when all verify ok
vulnsuite ps                                                     running targets (id, state, ip)
vulnsuite targets [-file FILE] [-by auto|ip|alias|host]          scannable URLs, right port per template
vulnsuite stop [-t SEL]... [-variants] [-prune-net]              tear down (targets, their sidecars and sidecar networks; alias: down)
vulnsuite images [-rm]                                           locally built images
vulnsuite host [-no-pull]                                        what the daemon's machine offers: arch, CPU flags, /dev/kvm, kernel, amd64 (alias: doctor)
vulnsuite update-templates [-repo OWNER/NAME] [-ref REF] [-force]  fetch / update the community templates (alias: ut)
vulnsuite version                                                version and templates checkout
```

`<filters>` is any of `-ref`, `-class`, `-category`/`-product`, `-tag`,
`-cve`/`-no-cve`, `-kev`/`-no-kev`, `-verified`/`-unverified`, `-year`,
`-since`, `-fidelity` and `-arch` (see [Finding the right target](#finding-the-right-target)).
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
templates repository or `update-templates` install you are standing in (from
any subfolder: the git root, or the directory holding the
`.vulnsuite-templates-version` marker, is the templates root), or
`~/vulnsuite-templates`.
`vulnsuite update-templates` fetches the templates into that same directory:

- a git checkout is pulled (`--ff-only`); `-ref BRANCH|TAG|COMMIT` fetches the
  ref from `origin` and checks it out detached (refused while tracked files have
  uncommitted changes). A later plain `update-templates` on such a detached
  checkout fetches `origin` and switches back to its default branch
  (`origin/HEAD`, else `main`), fast-forwarding it; it refuses instead while
  tracked files have uncommitted changes or the detached HEAD has commits no
  branch or tag keeps. A checkout is never replaced, so the update fails if
  `git` is not on `PATH`. A checkout found from the working directory (not
  named with `-templates` or `$VULNSUITE_TEMPLATES`) is updated only when its
  `origin` is `ruzfi/vulnsuite-templates` or the `-repo` you pass (any URL
  form: https, ssh, `git@host:owner/name.git`); otherwise update-templates
  refuses and touches nothing, so running it inside an application
  repository that happens to hold a vulnsuite contract never pulls or checks
  out that repository. Name the checkout with `-templates DIR` to update it
  regardless. `-repo` on a checkout must name its `origin` (change the
  remote with `git remote set-url origin` instead);
- anything else is replaced by the GitHub archive of `-ref` (default `main`),
  but only when the directory is missing, empty, or was installed by
  `update-templates` (it has a `.vulnsuite-templates-version` marker). Any other
  non-empty directory is refused unless you pass `-force`; a subfolder of an
  archive install is refused even with `-force`. The archive is
  refused, and the old directory kept, when it is over 256 MiB, expands past
  512 MiB or 50,000 entries, or holds no templates (a wrong `-repo`). The old
  directory is removed only once the new one is in place; if it cannot be
  removed (e.g. a read-only file), the update still succeeds and a warning
  names the leftover `.<name>.old-*` directory to delete. When the templates
  directory is a symbolic link (`~/vulnsuite-templates -> /data/tpl`), the
  directory it points to is checked and replaced in place and the link is
  kept; a link that does not resolve to a directory is refused. An archive
  install never creates symlinks: it skips them and prints how many it skipped
  (and which), so a template that relies on a symlink in its build context
  works only from a git checkout.

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
- `-verified` / `-unverified`: `metadata.verification`. An unverified target
  is statically valid but nobody has run its states yet. `list` shows it in
  the VERIFIED column (`no`; a date is the last `stamp` run, `yes` a verified
  target with no recorded run) and as `verification`/`verified_on` in `-json`.
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
vulnsuite list -group php2shell            # the whole family, one row per member (no selectors alongside: a usage error)
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
`-kev`/`-no-kev`, `-verified`/`-unverified`. Every `-t`, every filter, and every line of a `-f` file selects
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
must be `real` or `simulated`, `-year` a four-digit year, `-since` a
`YYYY-MM-DD` date, `-arch` a GOARCH name (`amd64`, `arm64`, ...) and
`-category` a top-level folder of the templates directory that holds templates,
so a typo is a usage error (exit 2) rather than a filter that silently matches
nothing.

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
Every command that takes selectors resolves `suite:<name>` the same way:
`run`, `build`, `stamp`, `stop -t suite:<name>`, `validate -t suite:<name>`,
`list suite:<name>` and `info suite:<name>` (which lists the suite's targets,
or shows the one target a single-target suite selects).
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

`-registry` without `-push` is a usage error (it would do nothing), and a state
named twice in `-state` is built once.

A sidecar with a `build` (see [CONTRACT.md](CONTRACT.md#built-sidecars)) is
built together with each state that runs it, as
`vulnsuite/<id>:sidecar-<name>-<hash>`. Both states share that tag, so it is
built once and reused until its context changes; `build` lists it under the
state (`sidecar <name> built|reused <ref>`, and `sidecars` in `-json`).
Sidecars that run a prebuilt image are not touched by `build`: `run` pulls
them when it starts them. With `-push`, a built sidecar image is pushed next
to the state images, as `<registry>/<id>:sidecar-<name>` and
`<registry>/<id>:sidecar-<name>-<hash>`, once even when both states run it.

Built images carry labels (`dev.vulnsuite.id`, `.state`, `.hash`,
`.vuln_refs`) and bake the state's environment in, so a published image is
self-contained: `docker run ghcr.io/you/vulnsuite/<id>:vulnerable` is the
vulnerable target, no vulnsuite needed.

Push credentials come from `~/.docker/config.json` (its credential helpers,
or its `auths` entries in any form the docker CLI writes: `auth`, separate
`username`/`password`, or an `identitytoken` as `az acr login` stores), or from `VULNSUITE_REGISTRY_USER` / `VULNSUITE_REGISTRY_TOKEN`. The
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

A `requires` skip also says which requirement the host does not meet, so CI on
a mixed fleet can tell a hardware skip from a regression without parsing
`detail`: `cause` is a stable code and `missing` lists what the host lacks.
Other entries carry neither field.

```json
{"id": "win-rdp", "state": "vulnerable", "reason": "requires",
 "detail": "needs a [windows] container host; this host is linux",
 "cause": "host_os", "missing": ["windows"]}
```

| cause | missing | meaning |
| --- | --- | --- |
| `host_os` | the accepted OSes | the daemon OS is not in `requires.host_os` |
| `kvm` | `["kvm"]` | `requires.kvm` on a host that is not linux/amd64 |
| `arch` | the accepted arches | the host arch is not in `requires.arch` and `emulation` is off |
| `emulation` | the accepted arches | emulation is allowed, but the daemon (not linux) cannot emulate |
| `cpu_flags` | the flags the daemon lacks (all of them when its flags could not be read) | the daemon's machine lacks `requires.cpu_flags` |
| `probe` | (absent: `detail` is `requires.probe.reason` with the exit code and output) | `requires.probe` exited non-zero in the target's image |

The document is printed on failure and on Ctrl-C too, and the exit code is
unchanged: non-zero whenever anything failed or was interrupted. The same holds
for the bare `run -json` array: once the selection is resolved it is printed
on every way out but a usage error (`[]` when a template fails to load or
nothing came up), and `targets -json` prints `[]` when nothing is running,
like `ps -json`, still exiting non-zero. In `build`,
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
under its template name (e.g. `db`) in every exposure mode. A sidecar with a
`build` is built (or reused) with the target's image before anything starts,
and `run` prints its image next to the target's. Building it is not a pull,
so `-no-pull` does not skip it (as for a `build` base); prebuilt sidecar
images are fetched as before. Sidecars are not
on `vulnsuite-net` and are not scan targets. The private network follows
`-no-egress` in `internal` mode, is a plain bridge in `host` mode (the
target's ports are published from it), and has no egress in `macvlan` mode so
the target's traffic keeps leaving through its LAN address. `vulnsuite stop`
removes the sidecars and their network along with the target.

**The shared network is created once.** `vulnsuite-net` (or `-network NAME`)
is created by the first run and reused by later ones, with the settings it was
created with. A run whose flags don't match it fails instead of joining it: a
`-no-egress` run refuses a network that has egress, and a run without
`-no-egress` refuses an internal one. Stop the targets on it and remove it with
`vulnsuite stop -prune-net` (add `-network NAME` for another network), then run
again. The same goes for the macvlan network `vulnsuite-macvlan-<parent>`
when `-subnet` or `-gateway` differs from the existing one.

`-no-egress` applies only to `-expose internal`. `host` and `macvlan` give the
target a route off the host by design, so combining either with `-no-egress`
is a usage error (exit 2) instead of a run that silently keeps its egress.

`vulnsuite ps`, `targets` and `stop` find containers by their
`dev.vulnsuite.*` labels: `stop -t foo` stops exactly template `foo` (never
`foo-bar`), and containers vulnsuite did not start are left alone.
`stop -prune-net` also removes `vulnsuite-net`, which only makes sense when
stopping everything; with a selector it is a usage error. `run`
also records a target's published ports and their schemes on the container
(`dev.vulnsuite.ports`), so `targets` addresses it correctly even when its
template is outside the templates directory, was removed or changed by
`update-templates`, or now declares a different port. Containers started by an
older vulnsuite fall back to the template; if that is gone too, `targets` says
so and asks you to restart the target.

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

Flags that belong to another exposure mode are usage errors (exit 2) rather
than being ignored: `-bind` outside `host` mode, and `-parent`, `-ip`,
`-subnet` or `-gateway` outside `macvlan` mode.

A template may publish more than one port: the primary is always published, and
any port marked `publish: true` in the contract is published alongside it and
added to the scanner target lists. `-host-port` pins the primary's host port;
`-host-port-map container=host` pins an additional one (repeatable). Unpinned
published ports get a free host port assigned by the Docker daemon (on its own
machine, so this works with a remote daemon too), all reported by `ps`, `targets` and
`-targets-file`. A `-host-port-map` key that is not a port the target publishes
is a usage error:

```bash
vulnsuite run -t <target> -expose host \
  -host-port 39841 -host-port-map 8091=39842 -detach
```

On Docker Desktop the host cannot reach container IPs; vulnsuite notices and
tells you to scan from a container or use `-expose host`. The same is true when
the daemon is remote (`internal` targets live on the daemon host's network, not
yours) — there too, `-expose host -bind <daemon address>` gives you a scannable
URL. The healthcheck then runs inside the target (it checks that the port
listens, or, for an `http` healthcheck, asks `curl` when the image has it), so
seeds still wait for the service; an image without a shell is taken as ready
once it runs. A check that hangs (the exec times out) counts as not ready,
never as "no shell". `exec` and `sequence` verify probes still run, since they need
no network path: a failing one fails verify, and the network probes are
reported as skipped. A `sequence` reports each attempt (`hit`, `pass`, `not
reached` or `fail`) in its verify line and in `-json` under the probe's
`attempts`; see [`sequence`](CONTRACT.md#sequence).

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
`~/nuclei-templates`, or `-nuclei-templates DIR`; an explicit `DIR` that is
not a directory is a usage error, as is such a `validate -nmap-scripts DIR`,
rather than a silent fallback) the ids are resolved to
files, templates matching the target's CVEs that nobody declared yet are
suggested, and `vulnsuite validate` warns about ids that don't exist. The
checkout's index is cached in the user cache directory
(`vulnsuite/nuclei-index-*.json`) and rebuilt whenever a template file is
added, removed or changed (by path, size and modification time), so only the
first run after a `git pull` pays for indexing; `run -q`, which prints no
scanner lines, skips it:

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
(host `arch`, `/dev/kvm`, container-host `host_os`, `cpu_flags`, a generic `probe`). `vulnsuite run` and
`build` preflight it against the daemon's OS/arch and **skip with a reason**
rather than hanging -- so a KVM / Windows-VM target is skipped cleanly on an
Apple Silicon Mac -- or run cross-arch images under emulation (`-platform`).
A target with `cpu_flags` (e.g. AVX-512 VBMI) is skipped, naming the missing
flags, on a daemon without them; the flags are read from the daemon's machine
in a small pinned `busybox` container, only when a selected target sets them
(see [CONTRACT.md](CONTRACT.md#requires)). A `requires.probe` command runs in
the target's image once it is built or pulled and before anything starts; a
non-zero exit skips the target with the probe's reason, in `run` and `build`.
`-ignore-requires` overrides; `list -arch <a>` hides targets that can't run on
that arch, and `list` and `info` show each template's requires (the REQUIRES
column, `requires` in `list -json`). See [CONTRACT.md](CONTRACT.md).

To see what the current daemon offers, ask it:

```text
$ vulnsuite host
daemon       linux/arm64
engine       29.8.2 (api 1.56, linux/arm64)
kernel       7.2.12-orbstack-00394-gbecdd6130068
/dev/kvm     no
cpu flags    aes asimd ... (N)
amd64        emulated
probe image  busybox:1.37.0@sha256:a7dbc319...
```

The OS and arch come from the daemon's API; the kernel, `/dev/kvm` (a kvm
device registered with the daemon's kernel), and the CPU flags are read on the
daemon's machine in a short-lived pinned `busybox` container (no network, no
capabilities), the same way `requires.cpu_flags` is checked. `amd64` is
`native` on an amd64 daemon; elsewhere a linux/amd64 container is tried:
`emulated` when it runs (qemu or Rosetta), `unavailable` when it does not.
What cannot be read (offline and the probe image is not present, or with
`-no-pull`) is shown as `unknown` with the reason, and the command exits
non-zero. `host -json` prints the same as one object (`engine`, `os`, `arch`,
`kernel`, `kvm`, `cpu_flags`, `amd64`, `amd64_detail`, `probe_error`,
`probe_image`).

`list -runnable` lists only the templates whose `requires` this daemon meets,
by the same preflight `run` uses. It connects to the daemon (a plain `list`
does not), reads the CPU flags only if a listed template sets `cpu_flags`, and
does not evaluate `requires.probe` (that needs the target's image).

## Recording that a target was verified: `stamp`

A contract can pass `validate` and still never have run on a host that meets
its `requires` (an AVX-512 VBMI target, say, when no maintainer has such a
machine). Mark it `verification: unverified` in `metadata`: `validate` then
warns (`unverified-target`, an error under `-strict`), and `list -unverified`
finds it. In a suite file, a `-unverified` line keeps a `needs-validation`
suite in step with the corpus.

Whoever has a suitable host turns that into evidence with `stamp`:

```text
vulnsuite stamp -t java4shell            # one target (or a group, -f, a filter, -all)
vulnsuite stamp -unverified              # everything still waiting for a run
vulnsuite stamp -t java4shell -dry-run   # run and verify, write nothing
```

For each target, `stamp` runs every declared state in turn (build, start,
verify, tear down). Only when every state ends in `verify: ok` does it write
`metadata.verified_on` (date, vulnsuite version, the daemon's `os/arch`, the
emulated `platform` if any, the `requires.cpu_flags` it checked, the states)
and set `verification: verified`. Only those lines of the contract change (a
comment on the `verification:` line goes with it: it said why the target was
unverified).

As with `build` ("nothing to build"), a selection that matches no template
fails with `nothing to stamp` (exit 1) instead of succeeding having stamped
nothing.

The run proves the contract as it was loaded, so `stamp` checks the file again
before writing: if anything but `verification` and `verified_on` changed
during the run (an edited probe, a branch switch), it refuses with `the
contract changed since it was loaded`; run it again. Evidence written meanwhile
by another stamp (say, on a second host sharing the checkout) is kept and
merged, and a lock file next to the contract
(`.contract.yaml.stamp-lock`, removed afterwards) keeps two stamps from
writing at once. A symlinked contract is written through the link.

The image's platform is checked too: an image for another platform than the
daemon's, run under emulation even though no `requires` asked for it, is
recorded with its `platform`, not as a native run.

`verified_on` keeps one run per host and image platform. Stamping on another
host adds its run next to the ones already recorded, and stamping again on
the same host replaces only that host's run. Native `linux/arm64` and
`linux/amd64` emulated on an arm64 host count as different runs. A single run
is written as a mapping, which vulnsuite v0.5.0 also reads; runs on several
hosts become a list:

```yaml
verified_on:
  - date: "2026-10-02"
    vulnsuite: v0.6.0
    host: linux/arm64
    states: [vulnerable, patched]
  - date: "2026-11-21"
    vulnsuite: v0.6.0
    host: linux/amd64
    cpu_flags: [avx512vbmi]
    states: [vulnerable, patched]
```

`list` shows the date of the latest run; `info` lists every run, and
`list -json` gives `verified_on` the same shape as the contract (an object for
one run, an array for several). `list -json` and `info -json` also carry
`verified_runs`: the same runs, always an array (empty when none). When a stamp
turns a single run into a list it prints a note, since vulnsuite v0.5.0 and
older cannot read the list form. A
failing state leaves the file untouched and fails the command. A host that does
not meet `requires` skips the target. There is no `-ignore-requires`: the point
is evidence from a host that qualifies. Commit the stamped contract with the
run's output in the PR.

`stamp -json` prints one object per target: `id`, `path`, `outcome`
(`stamped`, `verified` under `-dry-run`, `failed` or `skipped`), `detail`,
`states` (`state`, `ok`, `detail`) and the `verified_on` it wrote.

## Container hardening

The real isolation for a knowingly-vulnerable target is the no-egress internal
network (`-no-egress`) and a dedicated host — not stripping Linux
capabilities. Targets and their sidecars run with `no-new-privileges` and Docker's default
capability set (which already excludes `SYS_ADMIN`, `NET_ADMIN`,
`SYS_PTRACE`, ...); stock images need caps from that set just to boot. A
contract can tighten per target with `service.cap_drop: [ALL]`, `cap_add`,
`user`, or pass through `devices` (e.g. `/dev/kvm` for VM-backed targets).
