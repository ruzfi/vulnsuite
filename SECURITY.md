# Security model

vulnsuite stands up **knowingly vulnerable** targets. Two trust boundaries matter:

1. **The target is hostile by design.** It runs in a container, by default on an
   internal Docker network with no route off the host (`run -no-egress`), and
   should be scanned from a container on that network or via `-expose host`.
   `-no-egress` is checked against the network the target actually joins: if
   `vulnsuite-net` already exists with egress (created by a run without the
   flag), the run fails rather than attach the target to it.
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
  build-context walk never follows symlinks: one inside the context is sent
  as a symlink, which the daemon resolves inside the context, so the host
  file it names is never read.
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

### Template installs (`update-templates`)

- **an archive install can never become a git checkout.** The GitHub archive
  is extracted with directories and regular files only (symlinks are
  skipped), every entry must stay inside the install, sizes and entry counts
  are capped, and any `.git` path segment (in any case, `.git.` / `.git `, or
  the 8.3 name `git~1`) is refused. A directory carrying the
  `.vulnsuite-templates-version` marker is never treated as a checkout, so
  `git` is not run in it. Without this, an archive carrying `.git/config`
  (`core.fsmonitor`, `core.sshCommand`) or hooks would run commands on the
  host at the next `update-templates`.

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
- **Only allowlisted devices can be requested at all.** `service.devices`
  accepts exactly `/dev/kvm`, `/dev/net/tun`, `/dev/fuse`, `/dev/vhost-net`,
  `/dev/vhost-vsock` and `/dev/dri/cardN` / `/dev/dri/renderDN`, spelt
  canonically (`/dev//kvm` is refused, not cleaned). Every other path, notably
  raw disk and memory devices (`/dev/mem`, `/dev/sd*`, `/dev/nvme*`, LVM
  `/dev/<vg>/<lv>`, `/dev/nbd*`, zvols, …), is rejected at parse time, so no
  `-allow-host-access` can enable it. An allowlist, because a denylist of
  block devices can never be complete.
- Containers run with `no-new-privileges` and Docker's default (reduced)
  capability set. vulnsuite does **not** expose `privileged`, `--network host`,
  arbitrary `security_opt`, or host volume binds to templates.

### Reading the templates tree

- **A malformed contract cannot crash or hang the CLI.** Every command that
  reads contracts (`list`, `info`, `validate`, `run <id>`) checks a document's
  aliases, merge keys and tags before decoding it: a document that expands to
  more than 100,000 nodes through aliases or merge keys, or that carries a
  non-core tag or a tag with no value, is rejected, and a panic in the YAML
  decoder is reported as a parse error. A `net` probe step reads at most
  65536 bytes.
- **Discovery stays inside the tree.** A symlinked directory is followed only
  when it resolves inside the folder being walked, so a link such as `x -> /`
  in a checkout cannot make `list` walk the host's file system.

### Author/review aid

- `vulnsuite validate` warns (`host-device-access`, `elevated-capability`) when
  a template requests host access, so reviewers see it before merging, and
  `vulnsuite info` shows the declared devices and capabilities.

## Reporting

Found a way a template can affect the host beyond the container? Please open an
issue (or contact the maintainer) rather than adding it to the public templates.
