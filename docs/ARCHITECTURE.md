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
                                            (engine/moby: official SDK, default)
                                            (engine/docker: built-in API client)
```

## Packages

| Package | Responsibility |
| --- | --- |
| `pkg/contract` | The data model. `Parse` does strict YAML decoding and the structural checks that mirror the JSON schema. `ContentHash` / `ImageTag` give every state a content-addressed identity. No I/O beyond reading overlay files for hashing. |
| `pkg/loader` | Finds contracts under a root and resolves selectors (folder, file, id, unique substring; only path-shaped selectors — containing a separator, starting with `.`/`~`, or ending in `.yaml`/`.yml` — are read from the working directory). Sets `Folder`/`SourcePath` on loaded contracts. |
| `pkg/validator` | Semantic lint: is the template *wrong* rather than malformed (unpinned base, missing files, identical states, weak probes, ...). Pure functions over contracts. |
| `pkg/engine` | The `Engine` interface the rest of the system builds and runs on. `engine/moby` implements it with the official Moby SDK (`github.com/moby/moby/client`, the default); `engine/docker` implements the same thing against the Engine HTTP API with `net/http` only; `engine/engines` picks one by name; `engine/registryauth` resolves registry credentials for both; `engine/enginetest` is an in-memory fake for tests. |
| `pkg/builder` | Turns a (contract, state) into a local image: pull for `image` kinds, a generated overlay Dockerfile for `overlay`, a git checkout + patch for `source`, the template's own context for `build`. Build contexts are streamed to the daemon as tar (never held in memory whole), honouring `.dockerignore`; `ResolveAll` runs them in parallel with a bounded worker pool. `Publish` tags and pushes to a registry. |
| `pkg/runner` | Starts a resolved image with the hardening baseline and the chosen exposure, waits for readiness, runs the state's probes, and manages the fleet (`Running`, `StopAll`). Stateless: the fleet is discovered by the `dev.vulnsuite.*` container labels (id, state, role, network), so there is no bookkeeping file to drift. Each target state gets its own sidecars on a private network. |
| `pkg/probes` | Raw-socket HTTP, TCP and exec probes plus readiness helpers. Deliberately not `net/http` on the client side so encoded traversal payloads reach the wire unchanged. |
| `pkg/templates` | Where the templates directory is, and `update-templates` (git pull, or a GitHub archive download). |
| `internal/cli` | The commands. A tiny subcommand layer over `flag`; every command gets the global flags; `-json` output is on stdout with progress on stderr. |

## Design decisions

**Content-addressed images.** `vulnsuite/<id>:<state>-<hash>` where the hash
covers every input that influences the image. This gives free reuse across
runs and across templates sharing a base, makes `-push` produce immutable
tags, and lets the validator detect states that are accidentally identical.
The state name is not in the hash on purpose.

**Two engine clients behind one interface.** The default is the official
Moby SDK (`github.com/moby/moby/client`, the modern, modular successor of
`github.com/docker/docker/client`): API-version negotiation, `DOCKER_HOST` /
TLS handling and error typing come for free and track the daemon.
`engine/docker` is a few hundred lines over the unix socket with `net/http`
only (it resolves `DOCKER_HOST`, `DOCKER_TLS_VERIFY` / `DOCKER_CERT_PATH` and
docker contexts itself, the way the docker CLI does), kept as a fallback (`-engine api`) and as proof that the interface is
small: everything the builder and runner need is build, pull, push, tag,
create/start/remove/inspect/exec/logs/wait and networks. Both run the same
end-to-end test. Podman's native API or a remote builder would be a third
implementation, not a change to the callers.

**The engine decides what "unreachable" means.** On Docker Desktop the host
cannot route to bridge IPs, on Linux and OrbStack it can. Rather than
hard-coding an OS check, the runner classifies the first connection attempt:
*refused* means routable but not up yet (keep waiting), a timeout / no route
means unreachable. Then the healthcheck runs inside the target through the
engine's exec (a listening socket in `/proc/net/tcp`, or `curl` for an `http`
healthcheck), and so do the `exec` verify probes; the network probes are
skipped with an explanation.

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
- `pkg/engine/conformance` runs one table of behaviour cases against all
  three engines (`engine/moby` and `engine/docker` against a shared httptest
  Engine API stub, the fake directly), so the fake the other tests rely on
  cannot drift from the real clients. A case one engine is known to fail is
  skipped for it with a message naming the pull request that fixes it.
- `internal/e2e` (`VULNSUITE_E2E=1 go test ./internal/e2e/`) compiles a static
  Go HTTP server, builds it `FROM scratch` through the real engine, runs both
  states in host and internal exposure, verifies them, builds an overlay on
  top, and tears down. No registry access is needed.
