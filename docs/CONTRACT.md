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

Unknown fields are rejected. The machine-readable form of this document is
[`schemas/contract.schema.json`](../schemas/contract.schema.json).

## Top level

| Field | Required | Value |
| --- | --- | --- |
| `apiVersion` | yes | `vulnsuite/v1` (`range.legacy/v2` loads with a warning) |
| `kind` | yes | `Target` |
| `metadata` | yes | identity and provenance |
| `base` | yes | the pinned foundation |
| `service` | yes | how the target is run |
| `states` | yes | `vulnerable` (required) and `patched` |

## `metadata`

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | `^[a-z0-9][a-z0-9.-]{2,79}$`; unique; `<product>-<version>-<cve>` by convention. Also the container's network alias. |
| `summary` | yes | one line: what and how |
| `vuln_refs` | | `CVE-YYYY-NNNN`, `GHSA-...`, or `PREFIX-ID` for flaws without a CVE (community templates use `VS-...`) |
| `cwe` | | `CWE-NN` |
| `severity` | | `info`, `low`, `medium`, `high`, `critical` |
| `tags` | | free-form; `vulnsuite list -tag` filters on them |
| `references` | | the advisory and the fix |
| `maintainer` | | who to ask |
| `added` | | `YYYY-MM-DD` |
| `fidelity` | | `real` = runs the genuine affected software (the default and strongly preferred); `simulated` = a hand-written stand-in that reproduces the behaviour. Only use `simulated` when no public image or buildable upstream source reproduces the flaw (bare-OS/device/protocol sims). |
| `detected_by` | | the scanner templates/scripts that detect this target, as `<scanner>:<id>`. Known scanners: `nuclei:` (template id, e.g. `nuclei:CVE-2021-41773`, `nuclei:laravel-env`) and `nmap:` (NSE script, e.g. `nmap:http-aspnet-debug`). Declaring one means "this should fire on vulnerable and stay silent on patched". A bare id (no `scanner:`) defaults to nuclei. |
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
- `source` pins `commit`; the state's `patch` is applied on top.
- `build` points at a folder inside the template with a Dockerfile; it is
  self-contained and therefore always considered pinned.

## `service`

| Field | Notes |
| --- | --- |
| `ports` | required; `{ container: 80, protocol: http }`. Protocols: `http`, `https`, `tcp`, `ssh`, `ftp`, `smtp`, `redis`, `mysql`, `postgres`. The first HTTP port (else the first port) is the one a scanner is pointed at. |
| `command` | string or list; overrides the image command |
| `environment` | map; merged with the state's environment (state wins) |
| `healthcheck` | `{ http: { path, status }, timeout: 60s }` or `{ tcp: { port }, timeout }`; `timeout` is `<n>s|m|h` |
| `sidecars` | helper containers `{ name, image, digest, command, environment }` started on the same network, reachable by `name` (`command` sets the container command, e.g. a `server ...` arg list for a clustered node) |
| `user` | run-as `uid` or `uid:gid` |
| `cap_add` / `cap_drop` | Linux capabilities, e.g. `cap_drop: [ALL]` then `cap_add: [CAP_NET_BIND_SERVICE]` |
| `devices` | host devices to pass through, e.g. `/dev/kvm` |

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
```

Preflight decisions (`vulnsuite run` / `build`):

| Situation | Result |
| --- | --- |
| `arch` empty or includes the host arch | native |
| host arch not in `arch`, `emulation` true, linux host | emulated (`--platform linux/<arch>`, with a warning) |
| host arch not in `arch`, `emulation` false | skip (reason) |
| `kvm: true` on a non-`linux/amd64` host | skip (reason) |
| `host_os` set and the daemon OS is not in it | skip (reason) |

A skipped target is reported and the rest of the batch continues;
`-ignore-requires` runs it anyway. `list -arch <a>` hides targets that cannot
run on that arch.

## `states`

`vulnerable` is required; `patched` is strongly recommended (without it a
scanner's discrimination cannot be checked). Each state:

| Field | Notes |
| --- | --- |
| `image` / `digest` | per-state image override — the cheapest "patched": a newer tag |
| `patch` | a git patch applied to a `source` or `build` base |
| `overlay` | `[{ src, dest, mode }]` files from the template baked into the image (`image` base) or written into the build context (`source`/`build` base) |
| `environment` | baked into built images and passed at run time |
| `command` | per-state command override |
| `sidecars` | per-state sidecar image overrides, `{ <name>: { image, digest } }` -- swap a sidecar to another version for this state (e.g. the fixed release on every node of a multi-node cluster, which will not form across mixed versions) |
| `seed` | `[{ run: "..." }]` shell steps executed inside the container once it is up |
| `verify` | probes that prove the state |

How a state's image is produced (`vulnsuite list` shows it as KIND):

| Base | State has | Build kind | Image tag |
| --- | --- | --- | --- |
| `image` | nothing / `image` override | `image` (pull) | the pinned ref |
| `image` | `overlay` | `overlay` | `vulnsuite/<id>:<state>-<hash>` |
| `source` | anything | `source` | `vulnsuite/<id>:<state>-<hash>` |
| `build` | anything | `build` | `vulnsuite/<id>:<state>-<hash>` |

`<hash>` covers the base identity, the build context tree, the patch, every
overlay's content and destination, the environment and build args. Identical
inputs produce an identical tag and are never rebuilt.

## `verify` probes

Exactly one kind per probe. Probes are independent of any scanner: they
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

The `net` probe runs an ordered send/expect dialogue over a single TCP connection (optionally TLS), for multi-step protocols -- FTP SITE commands, SMTP, line protocols -- that a one-shot `tcp` probe cannot express. Each step optionally sends bytes, then reads the response and asserts `expect` (regex must match) and/or `expect_absent`.

HTTP probes are sent over a raw socket so the request line is exactly what the
template says. Chunked responses are decoded. `https` ports skip certificate
verification. A `status`-only assertion on the vulnerable state is a
`weak-verify` warning: assert the body or a header.

Probes run from the vulnsuite host against the container's IP (internal /
macvlan) or the published port (host). Where the host cannot route to
container IPs (Docker Desktop), verification is skipped with an explanation
rather than failed; use `-expose host` or scan from a container.

## Validation rules

`vulnsuite validate` reports, per template:

| Rule | Level | Meaning |
| --- | --- | --- |
| `unpinned-base` | error (warning with `-allow-unpinned`) | image has no digest / source has no commit |
| `missing-context`, `missing-dockerfile`, `missing-patch`, `missing-overlay` | error | a referenced file is not in the template |
| `patch-needs-source` | error | a patch on an `image` base |
| `empty-verify` | error | an http probe asserts nothing |
| `bad-regex`, `bad-timeout` | error | malformed values |
| `duplicate-id` | error | two templates share an id |
| `no-patched`, `no-verify`, `weak-verify`, `identical-states` | warning | the template proves less than it could |
| `source-no-diff` | warning | a source base where states have no patch/image difference |
| `no-healthcheck`, `no-vuln-ref`, `no-references`, `scanner-unnamed` | warning | missing provenance |
| `no-detected-by` | warning | no scanner template linked and `detection` unset |
| `fidelity-unset` | warning | metadata.fidelity is not set (real or simulated) |
| `simulated-on-image-base` | warning | fidelity: simulated but the base is a prebuilt image |
| `kvm-without-requires` | warning | service.devices has /dev/kvm but requires.kvm is not set |
| `unknown-scanner-template`, `undeclared-scanner-template` | warning | with a nuclei-templates checkout: a declared id does not exist / a template for the target's CVE is not declared |
| `legacy-apiversion` | warning | `range.legacy/v2` |

`-strict` turns warnings into failures (use it in CI).
