# Architecture

vulnsuite is a small pipeline: **template → contract → image → container → verified target**.

```
               loader            builder                 runner               probes
contract.yaml ───────► Contract ─────────► image ref ────────────► container ──────────► verify: ok
                         │                   │                        │
                     validator          content hash            exposure mode
                     (semantic lint)   (reuse / publish)      (internal/host/macvlan)
                                             │                        │
                                             └──────── engine.Engine ─┘
                                                  (Docker Engine API over the socket)
```

## Packages

| Package | Responsibility |
| --- | --- |
| `pkg/contract` | The data model. `Parse` does strict YAML decoding and the structural checks that mirror the JSON schema. `ContentHash` / `ImageTag` give every state a content-addressed identity. No I/O beyond reading overlay files for hashing. |
| `pkg/loader` | Finds contracts under a root and resolves selectors (folder, file, id, unique substring). Sets `Folder`/`SourcePath` on loaded contracts. |
| `pkg/validator` | Semantic lint: is the template *wrong* rather than malformed (unpinned base, missing files, identical states, weak probes, ...). Pure functions over contracts. |
| `pkg/engine` | The `Engine` interface the rest of the system builds and runs on. `engine/docker` implements it against the Docker Engine HTTP API with `net/http` only; `engine/enginetest` is an in-memory fake for tests. |
| `pkg/builder` | Turns a (contract, state) into a local image: pull for `image` kinds, a generated overlay Dockerfile for `overlay`, a git checkout + patch for `source`, the template's own context for `build`. Builds are tar streams in memory; `ResolveAll` runs them in parallel with a bounded worker pool. `Publish` tags and pushes to a registry. |
| `pkg/runner` | Starts a resolved image with the hardening baseline and the chosen exposure, waits for readiness, runs the state's probes, and manages the fleet (`Running`, `StopAll`). Stateless: the fleet is discovered by container name prefix and labels, so there is no bookkeeping file to drift. |
| `pkg/probes` | Raw-socket HTTP, TCP and exec probes plus readiness helpers. Deliberately not `net/http` on the client side so encoded traversal payloads reach the wire unchanged. |
| `pkg/templates` | Where the templates directory is, and `update-templates` (git pull, or a GitHub archive download). |
| `internal/cli` | The commands. A tiny subcommand layer over `flag`; every command gets the global flags; `-json` output is on stdout with progress on stderr. |

## Design decisions

**Content-addressed images.** `vulnsuite/<id>:<state>-<hash>` where the hash
covers every input that influences the image. This gives free reuse across
runs and across templates sharing a base, makes `-push` produce immutable
tags, and lets the validator detect states that are accidentally identical.
The state name is not in the hash on purpose.

**No Docker SDK dependency.** The official Go SDK pulls in a very large
module graph. The handful of Engine API endpoints we need (build, pull, push,
tag, create/start/remove/inspect/exec, networks) are a few hundred lines over
the unix socket, keep the binary small, and run anywhere the socket exists.
Everything goes through `engine.Engine`, so swapping in the SDK, Podman's
native API or a remote builder is a contained change.

**The engine decides what "unreachable" means.** On Docker Desktop the host
cannot route to bridge IPs, on Linux and OrbStack it can. Rather than
hard-coding an OS check, the runner classifies the first connection attempt:
*refused* means routable but not up yet (keep waiting), a timeout / no route
means unreachable (skip verification with an explanation instead of waiting
out the healthcheck).

**State environment is baked into built images.** So a published image is a
complete vulnerable (or patched) target on its own; the runner also passes
the environment at run time for `image` kinds, which are never rebuilt.

**Hardening baseline, not paranoia.** `no-new-privileges` plus Docker's
default capability set. `cap-drop ALL` breaks stock server images on boot;
the isolation that matters for a knowingly-vulnerable target is the network
(`-no-egress`) and the host it runs on. Templates can tighten per target.

**Verification is independent of detection.** A template's `verify` is
written from the advisory; the scanner's matcher is never copied. That is
what makes a vulnsuite target ground truth for the scanner rather than a
mirror of it.

## Testing

- Unit tests run without Docker: `pkg/contract`, `pkg/loader`, `pkg/validator`
  against the fixtures in `testdata/templates`; `pkg/probes` against raw TCP
  listeners; `pkg/builder`, `pkg/runner`, `internal/cli` against
  `enginetest.Fake`.
- `internal/e2e` (`VULNSUITE_E2E=1 go test ./internal/e2e/`) compiles a static
  Go HTTP server, builds it `FROM scratch` through the real engine, runs both
  states in host and internal exposure, verifies them, builds an overlay on
  top, and tears down. No registry access is needed.
