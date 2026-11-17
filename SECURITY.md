# Security model

vulnsuite stands up **knowingly vulnerable** targets. Two trust boundaries matter:

1. **The target is hostile by design.** It runs in a container, by default on an
   internal Docker network with no route off the host (`run -no-egress`), and
   should be scanned from a container on that network or via `-expose host`.
   Never run targets on a machine you care about or on a shared network.

2. **Templates are untrusted input.** Anyone can contribute to
   `vulnsuite-templates`, and a template is data (a `contract.yaml` plus build
   context) that `vulnsuite build`/`run` processes on the host. The engine must
   never let a template escape "spawn a container" into "run code on, or read
   /write, the host." The controls below enforce that.

## Controls

### Build time (source / build bases)

- **git transport is restricted.** `base.repo` is validated to be a real remote
  URL (`https`, `http`, `git`, `ssh`, or `user@host:path`); `ext::` / `fd::`
  transports, `file://`, bare local paths and leading-dash option injection are
  rejected. git runs with `GIT_ALLOW_PROTOCOL=https:http:git:ssh`,
  `GIT_TERMINAL_PROMPT=0`, `GIT_PROTOCOL_FROM_USER=0`, and the repo is passed
  after `--`. Without this, `base.repo: "ext::sh -c ..."` would run commands on
  the host at clone time.
- **patches cannot escape the source tree.** A `patch` is scanned and rejected
  if any hunk targets an absolute path or contains a `..` segment; `git apply`
  runs **without** `--unsafe-paths` (so it confines to the working tree) and the
  GNU `patch` fallback uses `--no-absolute-filenames`. Without this, a crafted
  patch could write `~/.ssh/authorized_keys` or a cron entry on the host.
- **template paths cannot leave the template folder.** Overlay `src`, `patch`,
  `base.context` and `base.dockerfile` must be relative paths; absolute paths
  (POSIX or Windows) and `..` segments are rejected when the contract is
  parsed. At build time every path is resolved with its symlinks followed and
  must still be inside the (resolved) template folder, so a symlink such as
  `files/app.conf -> ~/.aws/credentials` is refused instead of being baked into
  an image (`vulnsuite validate` reports it as `path-escapes-template`). The
  build-context walk never follows or includes symlinks.
- **generated Dockerfile lines cannot be injected into.** Overlay `dest` must be
  a plain path (letters, digits and `. _ @ % + = : , / -`; absolute for an
  image base; no `..` segments), state environment names must be plain
  variable names, and values may not contain newlines or other control
  characters. Values are double-quoted with `"`, `$` and the escape character
  escaped (honouring a Dockerfile's `# escape=` directive), so `pa$word` is
  baked literally. Without this a `dest` or env value containing `\nRUN ...`
  would add build instructions to a "no code" overlay build.
- Build steps (`Dockerfile` `RUN`, overlays, `seed`) execute inside the
  container/build sandbox, not on the host.

### Registry credentials

- `VULNSUITE_REGISTRY_USER` / `VULNSUITE_REGISTRY_TOKEN` name no registry, and
  templates choose which images are pulled, so the pair is scoped: it is sent
  only when **pushing** (to the `-registry` the user chose), never on pulls of
  base or sidecar images. If `VULNSUITE_REGISTRY` is set (a host such as
  `ghcr.io`, or a repository prefix), the pair is used for that registry only,
  pulls and pushes alike, and never for any other (Docker Hub matches however
  it is spelt: `docker.io`, `index.docker.io`, or a bare `nginx:1.25`). The
  pair is never included in the registry config sent with a build, whose
  Dockerfile pulls are template-chosen too. Credentials from
  `~/.docker/config.json` and credential helpers are keyed by registry and are
  used as the docker CLI would.

### Run time

- **Host device passthrough and elevated capabilities are consent-gated.**
  `service.devices` and any `service.cap_add` outside a small benign allowlist
  (`NET_BIND_SERVICE`, `CHOWN`, `SETUID`, `SETGID`, `KILL`, `FOWNER`,
  `DAC_OVERRIDE`) are refused unless the user passes `run -allow-host-access`.
  These are host-access primitives (a raw device or `SYS_ADMIN` can escape the
  container), never needed just to stand up a vulnerable service, so the user
  must opt in per run for a template they trust.
- **Raw disk/memory devices are rejected outright** at parse time
  (`/dev/mem`, `/dev/kmem`, `/dev/port`, `/dev/sd*`, `/dev/nvme*`, `/dev/dm-*`,
  `/dev/loop*`, `/dev/mapper/*`, …) — never legitimate for a target, so no
  `-allow-host-access` can enable them.
- Containers run with `no-new-privileges` and Docker's default (reduced)
  capability set. vulnsuite does **not** expose `privileged`, `--network host`,
  arbitrary `security_opt`, or host volume binds to templates.

### Author/review aid

- `vulnsuite validate` warns (`host-device-access`, `elevated-capability`) when
  a template requests host access, so reviewers see it before merging, and
  `vulnsuite info` shows the declared devices and capabilities.

## Reporting

Found a way a template can affect the host beyond the container? Please open an
issue (or contact the maintainer) rather than adding it to the public templates.
