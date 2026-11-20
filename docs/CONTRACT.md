# The target contract (`vulnsuite/v1`)

A template is a folder holding a `contract.yaml` (also accepted:
`contract.yml`, `template.yaml`) and the files it references. Everything is
relative to that folder, so a template is self-contained.

```
<category>/<id>/
  contract.yaml        required
  files/...            overlay files, patched sources, configs
  patches/...          git patches for source bases
  src/                 Dockerfile + source for a `build` base
```

Unknown fields are rejected, and so is a value of the wrong type: a quoted
number where an integer is expected (`container: "80"`), a number or `null`
where a string is expected (`summary: 123`, an `environment` value of `1`,
`true` or `null` -- quote it: `FOO: "1"`). A file must hold a single YAML
document. YAML anchors, aliases and merge keys (`<<: *base`) may be used; a
value reached through one must have the type required where it is used, and a
merged key must be a field of the mapping it is merged into. Each anchor name
may be defined once, before any alias to it, and the document with every alias
expanded may hold at most 100,000 nodes. A required string may not be empty
(`summary` may not be blank either): `base.image`, `base.repo`, `base.commit`,
a sidecar's `name` and `image` (or its `build.context`), a per-state sidecar `image`, and the `run` of a
`seed` step or an `exec` probe. A base key the base kind does not allow is
rejected even with an empty value (`context: ""` on an image base). The machine-readable form of this document is
[`schemas/contract.schema.json`](../schemas/contract.schema.json); the loader
enforces the same rules.

Discovery walks the templates tree and takes at most one contract per folder
(the first of `contract.yaml`, `contract.yml`, `template.yaml`). It never
enters dot-directories (`.git`, `.github`, ...) or `node_modules`, skips a
template's own `files/`, `patches/` and `src/` (only inside a folder that holds
a contract, so a category may be called `files`), and follows symlinked
directories once.

## Top level

| Field | Required | Value |
| --- | --- | --- |
| `apiVersion` | yes | `vulnsuite/v1` |
| `kind` | yes | `Target` |
| `metadata` | yes | identity and provenance |
| `base` | yes | the pinned foundation |
| `service` | yes | how the target is run |
| `states` | yes | `vulnerable` (required) and `patched` |

## `metadata`

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | `^[a-z0-9]+([.-][a-z0-9]+)*$`, 3-80 characters (a valid Docker repository name: no leading, trailing or doubled `.`/`-`); unique; `<product>-<version>-<cve>` by convention. The running container's network alias is `<id>-<state>` (one per state). |
| `summary` | yes | one line: what and how |
| `vuln_refs` | | `CVE-YYYY-NNNN` (4-7 digit sequence), `GHSA-...` (lower case), or `PREFIX-ID` for flaws without a CVE (community templates use `VS-...`). The prefix of a `PREFIX-ID` is 2-8 upper-case letters other than `CVE` and `GHSA`, so a malformed `CVE-21-41773` or `GHSA-ABCD-...` is an error, not a generic ref. |
| `cwe` | | `CWE-NN` |
| `severity` | | `info`, `low`, `medium`, `high`, `critical` |
| `class` | | non-empty list of finding class(es) (taxonomy v2), orthogonal to the product surface (the top directory level): `vuln` (a tracked software vulnerability, usually a CVE), `misconfig` (an insecure configuration), `exposure` (data/interface reachable that should not be), `default-login` (default/weak credentials), `weak-crypto`. One or more, unique. `vulnsuite list --class` filters on it. |
| `disclosed` | | optional public-disclosure date (`YYYY-MM-DD`, a real calendar date: `2021-13-45` and `2021-02-30` are rejected); drives `list --year`/`--since` and a timeline view, falling back to the CVE-id year when unset. |
| `group` | | variant-family handle (`^[a-z0-9]+(-[a-z0-9]+)*$`). Targets that share a `group` are variants of one vulnerability: `-t <group>` resolves to the group's **primary**, and `-variants` expands to every member. A lone target that sets a `group` is simply a nickname for its id (no `primary`/`variant` needed). A handle must not equal any target `id`. |
| `primary` | | `true` marks the canonical member of a group. Exactly one member of a multi-member group must set it; a single-member group's lone member is the primary implicitly. Without a `group` it has no effect (`primary-no-group` warning). |
| `variant` | | discriminator within a group (`^[a-z0-9]+(-[a-z0-9]+)*$`), e.g. `waf-evasion`; unique within the group. Every non-primary member of a multi-member group needs one. Requires `group`. |
| `tags` | | free-form; `vulnsuite list -tag` filters on them |
| `references` | | the advisory and the fix |
| `maintainer` | | who to ask |
| `added` | | ISO date the target was first added (`YYYY-MM-DD`). |
| `updated` | | ISO date of the last change to this target's metadata or states (`YYYY-MM-DD`); bump it whenever CVE facts, versions, or probes change. Defaults to `added` when never updated. |
| `fidelity` | | `real` = runs the genuine affected software (the default and strongly preferred); `simulated` = a hand-written stand-in that reproduces the behaviour. Only use `simulated` when no public image or buildable upstream source reproduces the flaw (bare-OS/device/protocol sims). |
| `detected_by` | | the scanner templates/scripts that detect this target, as `<scanner>:<id>`. Known scanners: `nuclei:` (template id, e.g. `nuclei:CVE-2021-41773`, `nuclei:laravel-env`) and `nmap:` (NSE script, e.g. `nmap:http-aspnet-debug`). Declaring one means "this should fire on vulnerable and stay silent on patched". A bare id (no `scanner:`) defaults to nuclei. |
| `verification` | | `verified` (the default): someone ran every state on a host that can run it and verify passed. `unverified`: the contract is statically sound but nobody has run it yet, e.g. it needs hardware no maintainer has. `validate` warns (`unverified-target`; an error under `-strict`) and still runs every other rule; `list -unverified` selects such targets, and works as a suite filter line. |
| `verified_on` | | evidence of the last run in which every listed state verified ok: `date` (`YYYY-MM-DD`), `vulnsuite` (version), `host` (the daemon's `os/arch`), optional `platform` (when the image ran under emulation) and `cpu_flags` (the `requires.cpu_flags` the host was checked to have), and `states`. Written by [`vulnsuite stamp`](USAGE.md#recording-that-a-target-was-verified-stamp), not by hand: a hand-edited stamp shows up in review as one with no run output behind it. |
| `detection` | | `scanner`: the `detected_by` entries are **verified** (you ran the scanner against both states); `custom-only`: no public scanner template exists, the target tests your own detection. Unset with `detected_by` present = declared, not yet verified. Unset with nothing declared = a detection gap (`validate` warns; write a template and contribute it upstream). |

## `base`

Exactly one of three shapes.

```yaml
base: { kind: image, image: httpd:2.4.49, digest: sha256:... }         # prebuilt image
base: { kind: source, repo: https://..., commit: abc123, dockerfile: Dockerfile, build_args: {} }
base: { kind: build, context: src, dockerfile: Dockerfile, build_args: {} }
```

- `image` must pin `digest` to be reproducible (`validate` errors otherwise;
  `-allow-unpinned` downgrades it while authoring). Get it with
  `docker manifest inspect <image> -v | grep -m1 digest` or `docker buildx imagetools inspect <image>`.
- `source` pins `commit` to a full 40-character (or 64-character SHA-256)
  commit id; a branch or tag is unpinned, an abbreviated id a `short-commit`
  warning. The state's `patch` is applied on top.
- Per-state `image` overrides and every sidecar image (`service.sidecars`
  and per-state `sidecars` overrides) must pin `digest` too
  (`unpinned-state-image`, `unpinned-sidecar`; `-allow-unpinned` downgrades
  them like the base).
- `build` points at a folder inside the template with a Dockerfile; it is
  self-contained and therefore always considered pinned. So is a sidecar
  with a `build` (see `service.sidecars`): it never raises `unpinned-sidecar`.

## `service`

| Field | Notes |
| --- | --- |
| `ports` | required; `{ container: 80, protocol: http }`. Protocols: `http`, `https`, `tcp`, `ssh`, `ftp`, `smtp`, `redis`, `mysql`, `postgres`. The first HTTP port (else the first port) is the **primary** port a scanner is pointed at, always published. Add `publish: true` to a secondary port to publish it too (host mode) and include it in scanner target lists; unmarked secondary ports stay internal. Container ports must be unique. |
| `command` | string or list; overrides the image command |
| `environment` | map; merged with the state's environment (state wins) |
| `healthcheck` | `{ http: { path, status }, timeout: 60s }` or `{ tcp: { port }, timeout }`; `timeout` is `<n>s|m|h`. When the target cannot be reached from the machine running vulnsuite, it is checked from inside the target: the port must be listening, and an `http` check uses `curl` if the image has it |
| `sidecars` | helper containers `{ name, image, digest, command, environment }` (names unique) started with each target state on a private network shared only with that state's target, reachable there by `name` in every exposure mode; each state gets its own sidecars (`command` sets the container command, e.g. a `server ...` arg list for a clustered node). Instead of `image`/`digest` a sidecar may have a `build: { context, dockerfile, build_args }` to run an image built from the template, e.g. a driver or fake-DNS sidecar that runs the template's own scripts: exactly one of `image` and `build` is set, and a `build` takes no `digest`. See **Built sidecars** below |
| `user` | run-as `uid` or `uid:gid` |
| `cap_add` / `cap_drop` | Linux capabilities, e.g. `cap_drop: [ALL]` then `cap_add: [CAP_NET_BIND_SERVICE]` |
| `sanitizer` | `{ log_dir: /var/log/asan }`: the directory a sanitizer-instrumented target writes its reports to, read by a `sequence`'s `expect_sanitizer` steps. An absolute, canonical plain path (the characters of `overlay[].dest`, no `..`, `.`, `//` or trailing `/`, not `/`). Point the runtime at it yourself (`ASAN_OPTIONS=...:log_path=/var/log/asan/asan`) and create it writable by every user in the image. Not part of the image hash |
| `devices` | host devices to pass through; only `/dev/kvm`, `/dev/net/tun`, `/dev/fuse`, `/dev/vhost-net`, `/dev/vhost-vsock`, `/dev/dri/cardN`, `/dev/dri/renderDN` (canonical spelling). `run` needs `-allow-host-access` |

## `requires`

What the container host must provide. The tooling preflights it against the
detected daemon (OS/arch) and either runs natively, runs under emulation, or
skips with a reason -- instead of hanging on a host that cannot run the target.

```yaml
requires:
  host_os: [linux]     # container-host OS(es); default [linux]
  arch: [amd64]        # host CPU arch(es) that run natively; empty = any
  emulation: false     # allow qemu when host arch is not in arch (default true)
  kvm: true            # needs /dev/kvm + nested virt (a linux/amd64 host)
  cpu_flags: [avx512f, avx512bw, avx512vbmi, bmi2]   # CPU features the daemon's machine must have
  probe:                # generic host check, run in the target's image
    run: "grep -qw avx512vbmi /proc/cpuinfo"
    reason: "needs AVX-512 VBMI"
    timeout: 30s        # optional, default 30s
```

Preflight decisions (`vulnsuite run` / `build`):

| Situation | Result |
| --- | --- |
| `arch` empty or includes the host arch | native |
| host arch not in `arch`, `emulation` true, linux host | emulated (`--platform linux/<arch>`, with a warning): images are pulled, built and run for that platform, sidecars included |
| host arch not in `arch`, `emulation` false | skip (reason) |
| `kvm: true` on a non-`linux/amd64` host | skip (reason) |
| `host_os` set and the daemon OS is not in it | skip (reason) |
| `cpu_flags` set, host arch not in `arch` | skip (reason): `cpu_flags` imply no emulation, since qemu does not provide them |
| `cpu_flags` set, native, the daemon lacks some | skip, naming them: `needs CPU flags [avx512vbmi]; daemon has avx512f,avx512bw,bmi2` |
| `cpu_flags` set, native, the daemon's flags cannot be read | skip (reason, with the error) |
| everything above met, `probe.run` exits non-zero | skip (`probe.reason`, with the exit code and output) |

`cpu_flags` are Linux's names from `/proc/cpuinfo` (the `flags` line on x86,
`Features` on arm64; lower-case letters, digits and `_`). The daemon's API does
not report them, so they are read on the **daemon's** machine, not the one
running vulnsuite (a VM or hypervisor in between can hide flags): a short-lived
container from a digest-pinned `busybox` image, with no network and no
capabilities, prints `/proc/cpuinfo`'s flag lines. This happens only when a
selected target sets `cpu_flags` and meets everything else, and at most once per
command. When the cores disagree (a hybrid CPU) only the flags every core has
count. If the flags cannot be read -- the probe image cannot be pulled (offline,
or `-no-pull` without it present), or the container fails -- they are
**unknown**: a warning names the error, and every target that sets `cpu_flags`
is skipped with that error as the reason. They are never assumed present.
`emulation: true` next to `cpu_flags` is ignored (`validate` warns:
`cpu-flags-with-emulation`).

`probe` is the escape hatch for what no dedicated field covers (a kernel
version, cgroup v2, a sysctl, a device). It needs the target's image, so it runs
after the image is built or pulled (for the target's platform, so under
emulation too) and **before any of the target starts** -- no container,
sidecar or network. It runs as `/bin/sh -c <run>` with the image's entrypoint
replaced, the service's `user` and environment, no network, no capabilities and
none of the service's devices. Exit 0 runs the target; a non-zero exit
**skips** it with `reason` (never fails it), in `run` and `build` alike (`build`
then neither counts nor pushes the image). A probe that cannot run at all -- the
image has no `/bin/sh`, or it outlives `timeout` (`<n>s|m|h`, default 30s) --
fails the target instead: that is a broken template, not a host that lacks
something. `run` probes each target as it reaches it; `build` probes each
state's image once it is built.

A skipped target is reported and the rest of the batch continues;
`-ignore-requires` runs it anyway (and does not run `probe`). `list -arch <a>` hides targets that cannot
run on that arch. The platform is decided per target, so a `build` of several
targets emulates only those that need it; an explicit `-platform` applies to
every target.

## `states`

`vulnerable` is required; `patched` is strongly recommended (without it a
scanner's discrimination cannot be checked). Each state:

| Field | Notes |
| --- | --- |
| `image` / `digest` | per-state image override — the cheapest "patched": a newer tag. `image` bases only: a `source` or `build` base builds every state from its own checkout or context, so a state `image` (or `digest`) there is a schema error; make the states differ with a `patch` or `overlay` |
| `patch` | a git patch applied to a `source` or `build` base |
| `overlay` | `[{ src, dest, mode }]` files from the template baked into the image (`image` base) or written into the build context (`source`/`build` base). `src` is relative to the template folder; `dest` is an absolute path in the image for an `image` base, or a path in the build context for a `source`/`build` base. `mode` (e.g. `"0755"`) is set on the file in the build context and kept by `COPY`, so it also works on a non-root or shell-less base. See **Paths** below. |
| `environment` | baked into built images and passed at run time. Names must match `^[A-Za-z_][A-Za-z0-9_.-]*$`; values may not contain newlines or other control characters (they become Dockerfile `ENV` lines; `$` is kept literally). |
| `command` | per-state command override |
| `sidecars` | per-state sidecar image overrides, `{ <name>: { image, digest } }` -- swap a sidecar to another version for this state (e.g. the fixed release on every node of a multi-node cluster, which will not form across mixed versions). A built sidecar may be overridden too: the state then runs the image instead of the build. There is no per-state `build` |
| `seed` | `[{ run: "..." }]` shell steps executed inside the container once it is ready (skipped if it never becomes ready). A step that exits non-zero stops the rest, fails verify and fails `run` |
| `verify` | probes that prove the state; when present, at least one |

How a state's image is produced (`vulnsuite list` shows it as KIND):

| Base | State has | Build kind | Image tag |
| --- | --- | --- | --- |
| `image` | nothing / `image` override | `image` (pull) | the pinned ref |
| `image` | `overlay` | `overlay` | `vulnsuite/<id>:<state>-<hash>` |
| `source` | anything | `source` | `vulnsuite/<id>:<state>-<hash>` |
| `build` | anything | `build` | `vulnsuite/<id>:<state>-<hash>` |

`<hash>` covers the base identity, the state's `image`/`digest` override
(what an overlay build starts `FROM`), the build context tree (every
directory, file and whether it is executable, a symlink by its link text;
`.git` excluded; other mode bits follow the umask and are left out so a
checkout gets the same tag on every machine), the patch,
every overlay's content, destination and `mode`, the environment and build
args. Identical inputs produce an identical tag and are never rebuilt. The
state image and `mode` enter the hash only when set, so templates that use
neither keep their tags. The platform is not part of the hash: an existing
image is reused only when it was built for the platform wanted now (the
emulation platform, else the daemon's own), otherwise it is rebuilt.

#### Built sidecars

```yaml
service:
  sidecars:
    - name: driver
      build: { context: sidecars/driver, dockerfile: Dockerfile, build_args: {} }
      command: ["sleep", "infinity"]
```

A sidecar with a `build` runs an image built from `build.context`, a folder
in the template, with `build.dockerfile` (default `Dockerfile`) inside it and
`build_args` passed to the build. The context follows the rules of
`base.context` (see **Paths**) and is sent the same way: `.dockerignore`
honoured, `.git` left out, symlinks never followed. Its name must match
`^[A-Za-z0-9][A-Za-z0-9_.-]*$` (at most 100 characters), as it is part of
the image tag:

`vulnsuite/<id>:sidecar-<name>-<hash>`

where `<hash>` covers the Dockerfile path, the context tree (hashed like a
`build` base's, the executable bit included) and the build args; the
sidecar's `command` and `environment` are applied when it runs and are not
part of it. The tag is the same for every state that runs the sidecar from
its build, so it is built once and never rebuilt while its inputs are
unchanged; as with a state's image, it is reused only when it was built for
the platform wanted now (the target's: under emulation the sidecar is built
and run for the emulation platform). Adding a built sidecar does not change
any state's image tag. `build` and `run` build it together with the state's
image, before anything starts; a state whose `sidecars` override swaps it for
an image runs that image and does not build it. `identical-states` treats a
built sidecar as the same image in both states unless one overrides it.

## `verify` probes

Exactly one kind per probe (`http`, `tcp`, `net`, `exec` or `sequence`). A probe `port` is
1-65535 and a `timeout` (seconds) is greater than 0; leave either out for the
default (an explicit `port: 0` or `timeout: 0` is rejected). Probes are independent of any scanner: they
demonstrate the *impact* from the advisory, not a matcher.

```yaml
- http:
    method: GET                   # default GET
    port: 9229                    # target a non-primary container port (default: the primary port)
    raw_path: "/a/..%2e/etc/passwd"   # sent verbatim (traversal payloads survive); or
    path: /api/debug/env          # an ordinary path (may include a query)
    headers: { X-Forwarded-For: "127.0.0.1" }
    body: "..."
    status: 200                   # or
    status_in: [403, 404]
    body_matches: "root:.*:0:0:"  # Go regexp, dot matches newline
    body_absent: "root:"
    header_matches: { Location: "^https?://evil" }
    header_absent: [Set-Cookie]
    timeout: 10                   # seconds
- tcp:
    port: 6379
    send: "PING\r\n"
    banner_matches: "\\+PONG"
    closed: true                  # instead: assert the port is NOT open (refused/unreachable is a pass)
- net:                            # scripted multi-step dialogue over one connection
    port: 21
    steps:
      - expect: "^220"            # read the banner
      - send: "SITE CPFR /etc/hostname\r\n"
        expect: "^350"
      - send: "SITE CPTO /tmp/canary\r\n"
        expect: "Copy successful" # each step: send?, then read and assert expect / expect_absent
- exec:
    run: "cat /etc/shadow"
    expect_exit: 0
    stdout_matches: "root:"
```

A port counts as open, for a `tcp` probe and for a `tcp` (or default)
healthcheck, only when something listens on it. A connection that is accepted
and then closed within 300ms without a byte counts as closed: in host exposure
mode the published port is held by Docker's port proxy, which accepts before the
service listens in the container. A server that greets the client, or one that
waits for the client to speak first, counts as open.

The `net` probe runs an ordered send/expect dialogue over a single TCP connection (optionally TLS), for multi-step protocols -- FTP SITE commands, SMTP, line protocols -- that a one-shot `tcp` probe cannot express. Each step optionally sends bytes, then reads the response and asserts `expect` (regex must match) and/or `expect_absent`. A response is read across TCP segments: reading stops once `expect` matches, after `read` bytes (default 4096), when the server closes, after 500ms without more data, or at the probe timeout. So a multi-line reply (`220-Welcome` then `220 ready`) is judged whole and none of it leaks into the next step. A `tcp` probe reads its banner the same way, up to `banner_matches`. The connection is TLS when `tls: true` is set or when the probed port is declared `protocol: https` (the primary port when `port` is left out); a dialogue with any other port, e.g. SMTP on 25 of an https target, stays plain.

HTTP probes are sent over a raw socket so the request line is exactly what the
template says. Chunked responses are decoded. A probe speaks the scheme of the
port it targets: TLS on a port declared `protocol: https`, plain HTTP on any
other (a probe `port` not declared in `service.ports` uses the primary port's
scheme). `https` ports skip certificate verification. A `status`-only
assertion on the vulnerable state is a `weak-verify` warning: assert the body
or a header.

### `sequence`

A `sequence` verifies a race-condition target: an ordered list of steps run as
one attempt, in which the core freezes and resumes the target (`docker pause`)
and reads the sanitizer reports and log lines written during the attempt.
Sidecars are never frozen, so a driver sidecar can act on the frozen target's
sockets. It is per state like any probe: patched writes its own sequence.
It runs through the engine only (exec, pause, archive reads, logs) and on the
private sidecar network, so a sequence without `http`, `tcp` or `net` steps
verifies in every exposure mode, internal mode on Docker Desktop and OrbStack
included.

```yaml
service:
  sidecars:
    - { name: driver, image: ..., digest: ..., command: ["sleep", "infinity"] }
  sanitizer: { log_dir: /var/log/asan }
states:
  vulnerable:
    verify:
      - sequence:
          attempts: 3               # 1-10, default 1: a budget for harness flakes
          min_hits: 1               # 1-attempts, default 1
          timeout: 60               # seconds for one attempt, default 60
          steps:
            - exec: { container: driver, run: "/trigger.py setup" }
            - freeze: {}
            - exec: { container: driver, run: "/trigger.py fire" }
            - resume: {}
            - expect_sanitizer: { kind: heap-use-after-free, frame: "ngx_resolver_process_a" }
  patched:
    verify:
      - sequence:
          attempts: 3
          steps:
            - exec: { container: driver, run: "/trigger.py setup" }
            - freeze: {}
            - exec: { container: driver, run: "/trigger.py fire" }
            - resume: {}
            - expect_sanitizer: none
            - expect_log: "writev\\(\\) failed .* while sending to client"
```

| Step | Meaning |
| --- | --- |
| `exec` | the `exec` probe (`run`, `expect_exit`, `stdout_matches`, `timeout`) plus an optional `container:`, a `service.sidecars` name to run it in; without it the command runs in the target. Only a sequence step takes `container` |
| `freeze` | pause the target container. No options: `freeze: {}` |
| `resume` | unpause it: `resume: {}` |
| `sleep` | `{ ms: 100 }`, a fixed wait of 1-10000 ms |
| `expect_sanitizer` | `none` (no report may be written during the attempt), or `{ kind, frame }`: a report of bug class `kind` (lower case, e.g. `heap-use-after-free`) whose first stack has a frame matching the Go regexp `frame` (optional). Needs `service.sanitizer.log_dir` |
| `expect_log` | a Go regexp that must match the target's container log written during the attempt, e.g. the positive control on patched showing the race was reached |
| `http`, `tcp`, `net` | the probes above, e.g. a readiness check; not while the target is frozen |

`validate` checks that every `freeze` has a matching `resume` and none is
nested, that nothing runs in the target (`exec` without `container`) or
connects to it (`http`, `tcp`, `net`) while it is frozen, that `container`
names a sidecar, and that the sequence asserts something: an
`expect_sanitizer`, an `expect_log`, or an `exec` with `expect_exit` or
`stdout_matches`.

#### How a sequence runs

Before the first attempt, when `service.sanitizer.log_dir` is set, `run`
stats it through the Docker archive API: it must be a directory with mode
`0777` or `1777`, otherwise verify fails with `sanitizer log_dir /var/log/asan
is not writable by every user (mode 0755)` (or `does not exist`). A report
the sanitizer cannot write is lost silently, so this is an error, not a
warning. An engine that cannot pause containers (for `freeze`/`resume`) or
read container files (for `log_dir`) fails verify with that reason; the
sequence is never skipped.

Each attempt records where the target's log ends and the size, time and
content of every file in `log_dir`, then runs the steps in order under the
attempt `timeout`:

| Step | At run time |
| --- | --- |
| `exec` | in the target, or in the sidecar `container` of the same state. Default `expect_exit` 0 and `timeout` 30 s, as for an `exec` probe |
| `freeze` / `resume` | `docker pause` / `unpause` of the target container, never a sidecar |
| `sleep` | waits, cut short by the attempt timeout |
| `http`, `tcp`, `net` | against the same address the other probes use. When this machine cannot reach the target (internal mode on Docker Desktop, macvlan, a remote daemon's loopback) the step cannot run and the attempt is not reached, with the same explanation as skipped network probes |
| `expect_sanitizer` | reads the files in `log_dir` that are new or changed since the attempt started (only the appended part of a file that grew; at most 1 MiB per file) and parses every `ERROR: <Name>Sanitizer: <description>` report in them. `kind` matches the report's `SUMMARY` class or a word of its description (`attempting double-free` is a `double-free`); `frame` must match a frame of the report's first stack (the faulting access, up to the first blank line), written as `func file:line`. A report is written after resume, so the step waits up to 5 s for a matching one; `none` watches the whole 5 s and fails on the first report |
| `expect_log` | the regexp (dot matches newline) against what the target logged since the attempt started, waiting up to 5 s for it |

Every attempt ends as exactly one of:

- **hit**: every assertion held, a positive `expect_sanitizer` among them;
- **pass**: every assertion held, and there is no positive `expect_sanitizer` (patched);
- **not reached**: an `exec`, `freeze`, `resume` or network step failed, an
  `expect_log` did not match, or the attempt timed out. The race was not shown
  to run, so the attempt counts toward neither side. An `exec` or network
  failure ends the attempt; later steps do not run;
- **fail**: an `expect_sanitizer` did not hold. A report during an attempt
  with `expect_sanitizer: none` is a fail even when the attempt was otherwise
  not reached.

A sequence with a positive `expect_sanitizer` passes once `min_hits` attempts
hit, and fails as soon as that can no longer happen. One without passes on its
first passing attempt and fails on its first failed one, so a sanitizer report
on patched in any attempt fails verify and `attempts` only absorbs harness
errors. When no attempt reached the race, verify fails with the last reason.
The detail lists every attempt:

```
sequence: 1/2 hits (min 1): #1 not reached: driver: exec "/trigger.py setup" -> exit 1 != 0; #2 hit: heap-use-after-free at ngx_resolver_process_a ngx_resolver.c:2142
```

`-json` carries the same per attempt in the probe's `attempts` (`attempt`,
`outcome` = `hit`, `pass`, `not_reached` or `fail`, `detail`, `restarted`,
`elapsed`).

The core guarantees:

- **A frozen target is always resumed**: after a failed step, on the attempt
  timeout, on Ctrl-C (the unpause runs on its own short-lived context), and at
  the end of the attempt even when its `resume` was never reached. A freeze
  lasts at most 30 s; past that the target is unpaused at once, even while a
  step is still running, and the attempt is not reached.
- **Restart between attempts**: when the target exited during an attempt (an
  ASan build with `halt_on_error=1` aborts after its report), it is started
  again and its healthcheck waited for before the next attempt; the attempt
  shows `(target restarted)`. A target that cannot be started again makes the
  remaining attempts not reached.
- **`vulnsuite stop` removes a paused target**: the daemon's forced remove
  takes a paused container, so a run that crashed mid-freeze leaves nothing
  frozen behind.

### Paths

Templates are untrusted input, so every file a template references must be its
own:

- `overlay[].src`, `patch`, `base.context`, `base.dockerfile` and a sidecar's
  `build.context` and `build.dockerfile` are relative paths inside the
  template folder (a `dockerfile` inside its context).
  Absolute paths (`/etc/x`, `C:/x`), `..` segments and control characters are
  schema errors. A symlink is allowed only when its target is inside the template
  folder too; one pointing elsewhere is refused at build time and reported by
  `validate` as `path-escapes-template`.
- The build context (`base.context`, or the `source` checkout) is sent as it
  is on disk: symlinks inside it travel as symlinks and are never followed
  (the daemon resolves them inside the context), every `.git` directory
  (nested ones too, like the content hash) is left out, and a
  `.dockerignore` at the context root is honoured with Docker's pattern rules.
  The Dockerfile and `.dockerignore` are always sent, as with `docker build`.
- `overlay[].dest` is a plain path: letters, digits and `. _ @ % + = : , / -`,
  no whitespace, quotes, `$` or control characters, no `..` segments, and not
  `/` itself. It names the file, so it may not end in `/` or `/.` (an `image`
  base would copy into that directory, a `source`/`build` base would write a
  file). For an `image` base it must be absolute.
- `overlay[].mode` is four octal digits starting with `0` (`"0755"`): plain
  permission bits only, no setuid, setgid or sticky bit. It is set on the file
  in the build context's tar header, never through a generated `RUN` line.

Probes run from the vulnsuite host against the container's IP (internal /
macvlan) or the published port (host). Where the host cannot route to
container IPs (Docker Desktop), verification is skipped with an explanation
rather than failed; use `-expose host` or scan from a container.

## Validation rules

`vulnsuite validate` reports, per template:

| Rule | Level | Meaning |
| --- | --- | --- |
| `unpinned-base` | error (warning with `-allow-unpinned`) | image has no digest / source has no commit, or a commit that is not a commit id (a branch or tag) |
| `unpinned-state-image` | error (warning with `-allow-unpinned`) | a state's `image` override has no digest |
| `unpinned-sidecar` | error (warning with `-allow-unpinned`) | a sidecar image, or a state's sidecar override, has no digest (a sidecar with a `build` is pinned by its content) |
| `short-commit` | warning | `base.commit` is an abbreviated commit id; use the full SHA |
| `missing-context`, `missing-dockerfile`, `missing-patch`, `missing-overlay` | error | a referenced file is not in the template (`missing-dockerfile`: the build context has no Dockerfile and a state does not overlay one). A sidecar's `build.context` and its Dockerfile are checked the same way, the message naming the sidecar |
| `path-escapes-template` | error | a referenced path resolves (through a symlink) outside the template folder (a sidecar's build context or Dockerfile included, named by the sidecar) |
| `patch-needs-source` | error | a patch on an `image` base |
| `empty-verify` | error | an http probe asserts nothing |
| `bad-regex`, `bad-timeout` | error | malformed values (`bad-regex` covers every regexp, a `sequence`'s `frame` and `expect_log` included) |
| `sequence-unbalanced-freeze` | error | a `sequence` has a `freeze` without a `resume`, a nested `freeze`, or a `resume` without a `freeze` |
| `exec-in-frozen-target` | error | an `exec` step without `container` (so in the target) between `freeze` and `resume` |
| `network-step-while-frozen` | error | an `http`, `tcp` or `net` step between `freeze` and `resume` (it would block on the frozen target) |
| `unknown-sidecar` | error | an `exec` step's `container` names no `service.sidecars` entry |
| `sanitizer-without-log-dir` | error | an `expect_sanitizer` step without `service.sanitizer.log_dir` |
| `sequence-no-assertion` | error | a `sequence` with no `expect_sanitizer`, `expect_log`, or `exec` with `expect_exit`/`stdout_matches` |
| `race-no-positive-control` | warning | a `sequence` with `expect_sanitizer: none` and no `expect_log`: a clean result may only mean the race was never reached |
| `sanitizer-log-path` | warning | with `service.sanitizer.log_dir` set, `ASAN_OPTIONS` in `service.environment` or a state's `environment` has a `log_path` whose reports do not land directly in `log_dir` |
| `duplicate-id` | error | two templates share an id |
| `group-no-primary`, `group-multiple-primaries` | error | a multi-member group has zero or more than one `primary` |
| `group-duplicate-variant`, `group-variant-missing` | error | two members share a `variant`, or a non-primary member has none |
| `group-id-collision` | error | a group handle equals a template `id` |
| `group-multi-category` | warning | a group spans more than one product surface |
| `group-divergent-refs` | warning | members of a group cite differing `vuln_refs` |
| `no-ports` | error | `service` declares no ports |
| `undeclared-port` | warning | `healthcheck.tcp.port` or a verify probe's (or `sequence` step's) `port` is not declared in `service.ports` (usually a typo; a `tcp` probe with `closed: true` is exempt) |
| `shadowed-contract` | warning | the template folder holds a second contract file (`contract.yaml`, `contract.yml`, `template.yaml`); only the first is loaded |
| `no-patched`, `no-verify`, `weak-verify`, `identical-states` | warning | the template proves less than it could (`identical-states`: vulnerable and patched have the same image, build inputs, command, sidecar images and seed) |
| `source-no-diff` | warning | a source base with a `patched` state where no state has a patch or overlay, so both build the same commit |
| `no-healthcheck`, `no-vuln-ref`, `no-references`, `scanner-unnamed` | warning | missing provenance |
| `no-detected-by` | warning | no scanner template linked and `detection` unset |
| `fidelity-unset` | warning | metadata.fidelity is not set (real or simulated) |
| `unverified-target` | warning | `verification: unverified`: nobody has run the target's states yet (`vulnsuite stamp` records a run) |
| `verified-no-evidence` | warning | `verification: verified` is set, `requires` needs specific hardware (`cpu_flags` or `probe`), and `verified_on` records no run |
| `verified-on-stale` | warning | `verified_on` names a state the template no longer declares, or misses a `requires.cpu_flags` entry added since the run |
| `simulated-on-image-base` | warning | fidelity: simulated but the base is a prebuilt image |
| `kvm-without-requires` | warning | service.devices has /dev/kvm but requires.kvm is not set |
| `cpu-flags-with-emulation` | warning | requires.emulation is true but requires.cpu_flags is set, which rules emulation out |
| `host-device-access` | warning | `service.devices` passes a host device through; `run` needs `-allow-host-access` |
| `elevated-capability` | warning | `cap_add` adds a capability that can escape the container; `run` needs `-allow-host-access` |
| `primary-no-group` | warning | `primary: true` is set without a `group` |
| `unknown-scanner` | warning | a `detected_by` entry names a scanner other than `nuclei` or `nmap` |
| `unknown-scanner-template`, `undeclared-scanner-template` | warning | with a nuclei-templates checkout: a declared id does not exist / a template for the target's CVE is not declared |

`-strict` turns warnings into failures (use it in CI).
