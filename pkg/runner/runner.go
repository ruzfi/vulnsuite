// Package runner stands a target up in a chosen state with a chosen exposure
// mode, waits for it to be ready, and verifies it is genuinely in that state.
//
// Exposure modes decide how your (manually run) scanner reaches the target:
//
//	internal  the target joins a Docker network (default vulnsuite-net) and is
//	          NOT published to the host. Run your scanner as a container on the
//	          same network. Nothing is exposed outside Docker: the safest mode
//	          for a knowingly-vulnerable service.
//	host      the target's port is published on the host (127.0.0.1 by default,
//	          or 0.0.0.0 with --bind). One host port serves one target.
//	macvlan   the target attaches to a host interface via a macvlan network and
//	          gets its own IP on the LAN, as if it were a separate device.
package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// Exposure modes.
const (
	ModeInternal = "internal"
	ModeHost     = "host"
	ModeMacvlan  = "macvlan"
)

// DefaultNetwork is the internal network targets join.
const DefaultNetwork = "vulnsuite-net"

// LabelManaged marks containers vulnsuite started.
const LabelManaged = "dev.vulnsuite.managed"

// Labels stamped on the containers vulnsuite runs, next to builder.LabelID and
// builder.LabelState (both set on targets and sidecars). The fleet commands
// (ps, targets, stop) select containers by these, never by name prefix.
const (
	// LabelRole is RoleTarget or RoleSidecar.
	LabelRole = "dev.vulnsuite.role"
	// LabelNetwork names the network a target's scanner-facing address is on.
	LabelNetwork = "dev.vulnsuite.network"
	// LabelSidecarNetwork names the private network a target state shares with
	// its sidecars (only set when the template has sidecars).
	LabelSidecarNetwork = "dev.vulnsuite.sidecar_network"
	// LabelPorts records the ports a target publishes to a scanner, primary
	// first, as "3000/http,8443/https,5432" (no scheme: raw TCP), so `targets`
	// can address a running target without its template (FormatPortsLabel).
	LabelPorts = "dev.vulnsuite.ports"
)

// FormatPortsLabel renders published ports as the LabelPorts value.
func FormatPortsLabel(ports []contract.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		v := strconv.Itoa(p.Container)
		if s := p.Scheme(); s != "" {
			v += "/" + s
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ",")
}

// ParsePortsLabel reads a LabelPorts value back as container ports with their
// schemes, in order. Malformed entries are skipped.
func ParsePortsLabel(v string) []PublishedPort {
	out := []PublishedPort{}
	for _, part := range strings.Split(v, ",") {
		port, scheme, _ := strings.Cut(strings.TrimSpace(part), "/")
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		out = append(out, PublishedPort{ContainerPort: n, Scheme: scheme})
	}
	return out
}

// Container roles.
const (
	RoleTarget  = "target"
	RoleSidecar = "sidecar"
)

// CleanupTimeout bounds the removal of containers and networks after a failed
// or cancelled run. Cleanup runs on a fresh context, so an interrupt that
// cancelled the run does not also leak what it had already started.
var CleanupTimeout = 60 * time.Second

// CleanupContext returns a context for tearing things down: not cancelled
// with parent (it keeps parent's values only), bounded by CleanupTimeout.
func CleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), CleanupTimeout)
}

// TargetAlias is the network alias of a target in one state, e.g.
// "exposed-dotenv-file-vulnerable". It is unique per state, so with both
// states of a template running each alias resolves to exactly one container.
func TargetAlias(id, state string) string {
	return strings.ReplaceAll(id, "/", "-") + "-" + state
}

// SidecarContainerName is the container name of a sidecar of one target state:
// vulnsuite-<id>-<state>-<sidecar>. Each state has its own sidecars.
func SidecarContainerName(id, state, sidecar string) string {
	return contract.ContainerName(id, state) + "-" + sidecar
}

// SidecarNetworkName is the private network a target state shares with its
// sidecars, where each sidecar resolves under its template name (e.g. "db").
func SidecarNetworkName(id, state string) string {
	return contract.ContainerName(id, state) + "-net"
}

// Exposure is how the target is reachable.
type Exposure struct {
	Mode     string `json:"mode"`
	Network  string `json:"network,omitempty"`
	Bind     string `json:"bind,omitempty"`
	HostPort int    `json:"host_port,omitempty"`
	// HostPortMap pins the host port for a published container port (host mode),
	// container port -> host port. The primary port uses HostPort; additional
	// published ports fall here, and anything unmapped gets a free host port.
	HostPortMap map[int]int `json:"host_port_map,omitempty"`
	Parent      string      `json:"parent,omitempty"` // macvlan parent interface
	IP          string      `json:"ip,omitempty"`     // macvlan static ip
	Subnet      string      `json:"subnet,omitempty"`
	Gateway     string      `json:"gateway,omitempty"`
	// Internal makes the bridge network host-only (no egress at all).
	Internal bool `json:"internal,omitempty"`
}

// DefaultExposure is internal mode on the default network.
func DefaultExposure() Exposure {
	return Exposure{Mode: ModeInternal, Network: DefaultNetwork, Bind: "127.0.0.1"}
}

// Handle describes a running target.
type Handle struct {
	ID        string            `json:"id"`
	State     string            `json:"state"`
	Container string            `json:"container"`
	Image     *builder.Resolved `json:"image"`
	Exposure  Exposure          `json:"exposure"`
	Sidecars  []string          `json:"sidecars,omitempty"`
	// SidecarNetwork is the private network the target shares with its
	// sidecars ("" when the template has none).
	SidecarNetwork string `json:"sidecar_network,omitempty"`
	EndpointHost   string `json:"endpoint_host"` // per-state alias, 127.0.0.1, or macvlan ip
	EndpointPort   int    `json:"endpoint_port"`
	IP             string `json:"ip,omitempty"` // container ip (internal/macvlan)
	Scheme         string `json:"scheme"`       // http | https | "" (raw tcp)
	Ready          bool   `json:"ready"`
	// ReadyDetail says why the target is not ready (the container exited, or
	// the healthcheck did not pass in time) with the last container log lines.
	// Empty when ready.
	ReadyDetail string `json:"ready_detail,omitempty"`
	// ExitCode is the container's exit code when it exited before it was
	// ready (nil while it runs).
	ExitCode *int `json:"exit_code,omitempty"`
	// DaemonRemote is set when the engine talks to a daemon on another machine;
	// then a host-published port on the daemon's loopback cannot be reached from
	// here, which changes how readiness and verification are reported.
	DaemonRemote bool `json:"daemon_remote,omitempty"`
	// PublishedPorts is every port made reachable to a scanner: the primary port
	// first, then any additional publish: true ports. In host mode each carries
	// its host binding; in internal/macvlan mode only the container port.
	PublishedPorts []PublishedPort `json:"published_ports,omitempty"`
	// VerifyOK is nil when verification was skipped.
	VerifyOK     *bool           `json:"verify_ok"`
	VerifyDetail string          `json:"verify_detail,omitempty"`
	Probes       []probes.Result `json:"probes,omitempty"`
	// Seeds is the outcome of each of the state's seed steps, in order. Seeds
	// run only once the target is ready; otherwise each is recorded as skipped.
	Seeds []SeedResult `json:"seeds,omitempty"`
}

// SeedResult is the outcome of one seed step.
type SeedResult struct {
	Run      string `json:"run"`
	OK       bool   `json:"ok"`
	Skipped  bool   `json:"skipped,omitempty"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
	Output   string `json:"output,omitempty"` // tail of the output, on failure
}

// Problem returns why this target must not be handed out (not ready, a seed
// step failed, or verify failed), or "" when nothing is wrong. Verify that was
// skipped (VerifyOK nil) is not a problem in itself.
func (h *Handle) Problem() string {
	var why []string
	if !h.Ready {
		if h.ExitCode != nil {
			why = append(why, fmt.Sprintf("not ready: container exited with code %d", *h.ExitCode))
		} else {
			why = append(why, "not ready")
		}
	}
	for _, s := range h.Seeds {
		if !s.OK && !s.Skipped { // a skip follows a failure or "not ready", already reported
			why = append(why, "seed failed")
			break
		}
	}
	if h.VerifyOK != nil && !*h.VerifyOK {
		why = append(why, "verify failed")
	}
	return strings.Join(why, ", ")
}

// PublishedPort is one container port exposed to a scanner. In host mode HostIP
// and HostPort are its binding on the host; in internal/macvlan mode they are
// zero and the port is reached at the container (or macvlan) IP. Scheme is the
// URL scheme ("" for raw TCP).
type PublishedPort struct {
	ContainerPort int    `json:"container_port"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
	Scheme        string `json:"scheme,omitempty"`
}

// ScannerTarget is what a scanner should be pointed at (scheme://host:port,
// or host:port for raw TCP services). It is the primary port; ScannerTargets
// returns every published port.
func (h *Handle) ScannerTarget() string {
	return FormatTarget(h.Scheme, h.EndpointHost, h.EndpointPort)
}

// PortTarget pairs a published container port with its scannable URL.
type PortTarget struct {
	ContainerPort int
	URL           string
}

// PortTargets returns a scannable URL for every published port, primary first,
// each tagged with its container port. In host mode these are the host
// bindings; in internal/macvlan mode they are the container (or macvlan) IP and
// the container ports. Ports this host cannot address are skipped.
func (h *Handle) PortTargets() []PortTarget {
	var out []PortTarget
	for _, p := range h.PublishedPorts {
		host, port := h.portAddress(p)
		if host == "" {
			continue
		}
		out = append(out, PortTarget{ContainerPort: p.ContainerPort, URL: FormatTarget(p.Scheme, host, port)})
	}
	return out
}

// ScannerTargets returns a scannable URL for every published port, primary
// first. Falls back to the primary ScannerTarget when no published ports were
// recorded or none is addressable from here.
func (h *Handle) ScannerTargets() []string {
	pts := h.PortTargets()
	if len(pts) == 0 {
		return []string{h.ScannerTarget()}
	}
	out := make([]string, len(pts))
	for i, pt := range pts {
		out[i] = pt.URL
	}
	return out
}

// portAddress resolves the address a scanner uses for one published port, per
// exposure mode, or "" when this host cannot reach it.
func (h *Handle) portAddress(p PublishedPort) (string, int) {
	switch h.Exposure.Mode {
	case ModeHost:
		return normalizeHostIP(p.HostIP), p.HostPort
	case ModeInternal:
		host := h.IP
		if host == "" {
			host = h.EndpointHost // the network alias
		}
		return host, p.ContainerPort
	case ModeMacvlan:
		return h.EndpointHost, p.ContainerPort
	}
	return "", 0
}

// normalizeHostIP turns a binding's host IP into one a local scanner can dial:
// a port on all interfaces (empty, 0.0.0.0 or ::) is reached via loopback; an
// explicit bind address is carried through unchanged.
func normalizeHostIP(ip string) string {
	switch ip {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	}
	return ip
}

// FormatTarget renders scheme://host:port (or host:port for raw TCP).
func FormatTarget(scheme, host string, port int) string {
	hp := net.JoinHostPort(host, strconv.Itoa(port))
	if scheme == "" {
		return hp
	}
	return scheme + "://" + hp
}

// Options tune a run.
type Options struct {
	Verify bool
	// ReadyTimeout overrides the contract's healthcheck timeout when > 0.
	ReadyTimeout time.Duration
	// Build options used to resolve the image.
	Build builder.Options
	// AllowHostAccess honors a template's host-device passthrough and elevated
	// capabilities. Off by default: those are host-access primitives and
	// templates are untrusted, so the user must opt in per run.
	AllowHostAccess bool
	// IgnoreRequires skips the template's requires.probe (-ignore-requires).
	// Otherwise the probe runs once the image is resolved, before anything
	// starts, and a failing probe makes Run return a *SkipError.
	IgnoreRequires bool
}

// safeCaps are capabilities benign enough to add without host-access consent.
// Everything else (SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN, DAC_READ_SEARCH,
// SYS_RAWIO, ...) can lead to a container escape and is consent-gated.
var safeCaps = map[string]bool{
	"NET_BIND_SERVICE": true,
	"CHOWN":            true,
	"SETUID":           true,
	"SETGID":           true,
	"KILL":             true,
	"FOWNER":           true,
	"DAC_OVERRIDE":     true,
}

// HostAccessReason returns a human-readable reason when a contract asks for
// host access (device passthrough or a non-benign added capability), or "".
// Callers use it to consent-gate or to skip-with-reason before running.
func HostAccessReason(c *contract.Contract) string {
	var reasons []string
	if len(c.Service.Devices) > 0 {
		reasons = append(reasons, fmt.Sprintf("host device(s) %v", c.Service.Devices))
	}
	var caps []string
	for _, cp := range c.Service.CapAdd {
		if !safeCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cp), "CAP_"))] {
			caps = append(caps, cp)
		}
	}
	if len(caps) > 0 {
		reasons = append(reasons, fmt.Sprintf("elevated capabilit(ies) %v", caps))
	}
	return strings.Join(reasons, " and ")
}

// Runner runs targets.
type Runner struct {
	Engine  engine.Engine
	Builder *builder.Builder
	// Reach decides whether a container address is routable from this host
	// (default probes.Reachability; tests override it).
	Reach func(host string, port int, timeout time.Duration) probes.Reach
	// ExitPoll is how often awaitReady checks whether the container has
	// exited (default 1s; tests shorten it).
	ExitPoll time.Duration
}

// readyLogLines is how many trailing container log lines a not-ready target
// reports.
const readyLogLines = 20

// New returns a Runner on eng.
func New(eng engine.Engine) *Runner {
	return &Runner{Engine: eng, Builder: builder.New(eng), Reach: probes.Reachability}
}

// Run builds/pulls the state's image, starts it, waits for readiness and
// verifies it. The target is left running; Stop tears it down.
func (r *Runner) Run(ctx context.Context, c *contract.Contract, state string, exp Exposure, opts Options) (*Handle, error) {
	st, err := c.State(state)
	if err != nil {
		return nil, err
	}
	if exp.Network == "" {
		exp.Network = DefaultNetwork
	}
	if exp.Bind == "" {
		exp.Bind = "127.0.0.1"
	}
	// Templates are untrusted. Host device passthrough and elevated
	// capabilities can escape the container to the host, which is never needed
	// just to stand up a vulnerable service, so they require explicit per-run
	// consent.
	if !opts.AllowHostAccess {
		if reason := HostAccessReason(c); reason != "" {
			return nil, fmt.Errorf("refusing to run %s: it requests %s, which grants access to the host. "+
				"Re-run with -allow-host-access only if you trust this template", c.ID(), reason)
		}
	}
	img, err := r.Builder.Resolve(ctx, c, state, opts.Build)
	if err != nil {
		return nil, err
	}
	// requires.probe needs the image, so it runs here: after the image is
	// resolved, before any container, sidecar or network of the target.
	if c.Requires.Probe != nil && !opts.IgnoreRequires {
		d, err := RequiresProbe(ctx, r.Engine, c, state, img.Ref, opts.Build.Platform)
		if err != nil {
			return nil, err
		}
		if d.Skip() {
			return nil, &SkipError{ID: c.ID(), Decision: d}
		}
	}
	name := c.ContainerName(state)
	port := c.Service.PrimaryPort()
	alias := TargetAlias(c.ID(), state)
	scNet := ""
	if len(c.Service.Sidecars) > 0 {
		scNet = SidecarNetworkName(c.ID(), state)
	}

	// Replace a stale container of the same name, and this state's sidecars.
	// The other state's containers are left alone: they have their own names.
	if err := r.Engine.ContainerRemove(ctx, name); err != nil {
		return nil, err
	}
	for _, sc := range c.Service.Sidecars {
		if err := r.Engine.ContainerRemove(ctx, SidecarContainerName(c.ID(), state, sc.Name)); err != nil {
			return nil, err
		}
	}
	if scNet != "" {
		if err := r.clearSidecarNetwork(ctx, scNet); err != nil {
			return nil, err
		}
	}

	spec := engine.ContainerSpec{
		Name:  name,
		Image: img.Ref,
		User:  c.Service.User,
		Labels: map[string]string{
			LabelManaged:       "true",
			LabelRole:          RoleTarget,
			builder.LabelID:    c.ID(),
			builder.LabelState: state,
		},
		// Baseline hardening: block privilege escalation and keep Docker's
		// default capability set (which already excludes SYS_ADMIN, NET_ADMIN,
		// SYS_PTRACE, SYS_MODULE, ...). Deliberately not cap-drop ALL: stock
		// server images need caps from the default set just to boot. The real
		// isolation for a knowingly-vulnerable target is the no-egress internal
		// network and a dedicated host. A contract can tighten per target.
		SecurityOpt: []string{"no-new-privileges:true"},
		CapAdd:      c.Service.CapAdd,
		CapDrop:     c.Service.CapDrop,
		// Run the platform the image was resolved for (emulation), not the
		// daemon's default variant of a multi-platform image.
		Platform: opts.Build.Platform,
	}
	if scNet != "" {
		spec.Labels[LabelSidecarNetwork] = scNet
	}
	spec.Labels[LabelPorts] = FormatPortsLabel(c.Service.HostPublishPorts())
	for _, d := range c.Service.Devices {
		spec.Devices = append(spec.Devices, engine.Device{PathOnHost: d, PathInContainer: d})
	}
	env := mergeEnv(c.Service.Environment, st.Environment)
	spec.Env = env
	if len(st.Command) > 0 {
		spec.Cmd = st.Command
	} else if len(c.Service.Command) > 0 {
		spec.Cmd = c.Service.Command
	}

	h := &Handle{ID: c.ID(), State: state, Container: name, Image: img, Exposure: exp, SidecarNetwork: scNet,
		EndpointPort: port.Container, Scheme: port.Scheme(), DaemonRemote: engineRemote(r.Engine)}

	// The sidecar network. The target joins it next to its exposure network
	// (internal, macvlan) or, in host mode, publishes its ports from it: either
	// way it resolves its sidecars by name, which the default bridge cannot do.
	// - internal: egress follows -no-egress, like the exposure network.
	// - host: a plain bridge (ports cannot be published from an internal one).
	// - macvlan: internal, so it adds no default route and the target's
	//   traffic keeps leaving through its LAN address.
	scSpec := engine.NetworkSpec{Name: scNet}
	// primaryNet is the network the scanner-facing address is on.
	primaryNet := ""
	switch exp.Mode {
	case ModeInternal:
		stop := "vulnsuite stop -prune-net"
		if exp.Network != DefaultNetwork {
			stop = "vulnsuite stop -network " + exp.Network + " -prune-net"
		}
		if err := r.ensureNetwork(ctx, engine.NetworkSpec{Name: exp.Network, Internal: exp.Internal},
			fmt.Sprintf("stop the targets on it and remove it with %q (or \"docker network rm %s\"), or pick another network with -network", stop, exp.Network)); err != nil {
			return nil, err
		}
		primaryNet = exp.Network
		spec.Network = &engine.NetworkAttachment{Name: exp.Network, Aliases: []string{alias}}
		h.EndpointHost = alias
		scSpec.Internal = exp.Internal
		for _, pp := range c.Service.HostPublishPorts() {
			h.PublishedPorts = append(h.PublishedPorts, PublishedPort{ContainerPort: pp.Container, Scheme: pp.Scheme()})
		}
	case ModeHost:
		pubs := c.Service.HostPublishPorts()
		// Pinned host ports are checked here; every other port is published
		// on host port 0, so the daemon picks a free one atomically (on its
		// own machine, which is the right one for a remote daemon too). They
		// are read back from inspect once the container has started.
		alloc, err := pinnedHostPorts(exp, pubs, !h.DaemonRemote)
		if err != nil {
			return nil, err
		}
		for i, pp := range pubs {
			hp := alloc[pp.Container] // 0 = assigned by the daemon
			spec.Ports = append(spec.Ports, engine.PortBinding{HostIP: exp.Bind, HostPort: hp, ContainerPort: pp.Container, Protocol: "tcp"})
			h.PublishedPorts = append(h.PublishedPorts, PublishedPort{ContainerPort: pp.Container, HostIP: exp.Bind, HostPort: hp, Scheme: pp.Scheme()})
			if i == 0 {
				// A wildcard bind (0.0.0.0 or ::) is dialled via loopback, as
				// every other published port is (portAddress).
				h.EndpointHost, h.EndpointPort = normalizeHostIP(exp.Bind), hp
			}
		}
		primaryNet = "bridge"
		if scNet != "" {
			primaryNet = scNet
		}
	case ModeMacvlan:
		if exp.Parent == "" {
			return nil, errors.New("macvlan exposure needs --parent <host interface>")
		}
		netName := "vulnsuite-macvlan-" + exp.Parent
		if err := r.ensureNetwork(ctx, engine.NetworkSpec{
			Name: netName, Driver: "macvlan", Options: map[string]string{"parent": exp.Parent},
			Subnet: exp.Subnet, Gateway: exp.Gateway,
		}, fmt.Sprintf("stop the targets on it and remove it with \"vulnsuite stop -network %s -prune-net\" (or \"docker network rm %s\"), or run with its -subnet and -gateway", netName, netName)); err != nil {
			return nil, fmt.Errorf("macvlan network: %w", err)
		}
		primaryNet = netName
		spec.Network = &engine.NetworkAttachment{Name: netName, IPv4: exp.IP}
		scSpec.Internal = true
		h.EndpointHost = exp.IP
		if h.EndpointHost == "" {
			h.EndpointHost = "<macvlan-ip>"
		}
		for _, pp := range c.Service.HostPublishPorts() {
			h.PublishedPorts = append(h.PublishedPorts, PublishedPort{ContainerPort: pp.Container, Scheme: pp.Scheme()})
		}
	default:
		return nil, fmt.Errorf("unknown exposure mode %q", exp.Mode)
	}
	spec.Labels[LabelNetwork] = primaryNet

	// From here on anything created is torn down again on failure, on a fresh
	// context so a cancelled run does not leak it.
	fail := func(err error) (*Handle, error) {
		cctx, cancel := CleanupContext(ctx)
		defer cancel()
		if cerr := r.cleanup(cctx, name, h.Sidecars, scNet); cerr != nil {
			err = fmt.Errorf("%w (cleanup: %v)", err, cerr)
		}
		return nil, err
	}
	// The sidecar network: target state and its sidecars only. Any stale copy
	// was removed above, so it is created afresh with this run's settings.
	var targetExtraNet *engine.NetworkAttachment
	if scNet != "" {
		if err := r.ensureNetwork(ctx, scSpec, "another run of this target state may have recreated it; stop it and run again"); err != nil {
			return fail(err)
		}
		att := engine.NetworkAttachment{Name: scNet, Aliases: []string{c.ID(), alias}}
		if spec.Network == nil {
			spec.Network = &att // host mode: the target's only network
		} else {
			targetExtraNet = &att
		}
	}

	sidecars, err := r.startSidecars(ctx, c, st, state, scNet, opts.Build.Platform)
	h.Sidecars = sidecars
	if err != nil {
		return fail(err)
	}

	id, err := r.Engine.ContainerCreate(ctx, spec)
	if err != nil {
		return fail(fmt.Errorf("create %s: %w", name, err))
	}
	if targetExtraNet != nil {
		if err := r.Engine.NetworkConnect(ctx, targetExtraNet.Name, id, targetExtraNet.Aliases); err != nil {
			return fail(fmt.Errorf("connect %s to %s: %w", name, targetExtraNet.Name, err))
		}
	}
	if err := r.Engine.ContainerStart(ctx, id); err != nil {
		return fail(fmt.Errorf("start %s: %w", name, err))
	}

	// Discover the address a probe from this host can use: the one on the
	// exposure network, never the private sidecar network.
	det, err := r.Engine.ContainerInspect(ctx, name)
	if err == nil {
		h.IP = pickIP(det.IPs, primaryNet, scNet)
		if exp.Mode == ModeMacvlan && exp.IP == "" && h.IP != "" {
			h.EndpointHost = h.IP
		}
	}
	if exp.Mode == ModeHost {
		if err != nil {
			return fail(fmt.Errorf("inspect %s for its host ports: %w", name, err))
		}
		if err := assignedHostPorts(h, det); err != nil {
			return fail(err)
		}
	}

	r.awaitReady(ctx, c, h, opts.ReadyTimeout)
	r.seed(ctx, st, h)
	if opts.Verify {
		r.verify(ctx, c, st, h)
	}
	return h, nil
}

// pickIP returns the address on network prefer, else on any network other
// than exclude (deterministically: by network name), else "".
func pickIP(ips map[string]string, prefer, exclude string) string {
	if ip, ok := ips[prefer]; ok && prefer != "" {
		return ip
	}
	names := make([]string, 0, len(ips))
	for n := range ips {
		if n != exclude || exclude == "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return ips[names[0]]
}

// seed runs the state's seed steps once the target is ready, recording each
// outcome. A step that fails stops the rest: later steps usually build on it.
// When the target is not ready nothing runs; every step is recorded as skipped.
func (r *Runner) seed(ctx context.Context, st *contract.State, h *Handle) {
	stopped := ""
	if !h.Ready {
		stopped = "target not ready"
	}
	for _, step := range st.Seed {
		res := SeedResult{Run: step.Run}
		if stopped != "" {
			res.Skipped, res.ExitCode, res.Error = true, -1, "skipped: "+stopped
			h.Seeds = append(h.Seeds, res)
			continue
		}
		code, out, err := r.Engine.ContainerExec(ctx, h.Container, step.Run, 2*time.Minute)
		res.ExitCode = code
		switch {
		case err != nil:
			res.Error = err.Error()
		case code != 0:
			res.Error = fmt.Sprintf("exit %d", code)
		default:
			res.OK = true
		}
		if !res.OK {
			res.Output = tail(out, 512)
			stopped = "an earlier seed step failed"
		}
		h.Seeds = append(h.Seeds, res)
	}
}

// seedDetail summarises failed or skipped seed steps for the verify detail.
func seedDetail(h *Handle) string {
	var lines []string
	for _, s := range h.Seeds {
		if s.OK {
			continue
		}
		line := fmt.Sprintf("FAIL seed %q -> %s", s.Run, s.Error)
		if o := strings.TrimSpace(s.Output); o != "" {
			line += ": " + strings.ReplaceAll(o, "\n", " | ")
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// Stop tears a handle down: the target, its sidecars and their network. Every
// removal is attempted; the errors of those that failed are returned joined.
// Pass a context that is still live (see CleanupContext) when tearing down
// after an interrupt.
func (r *Runner) Stop(ctx context.Context, h *Handle) error {
	return r.cleanup(ctx, h.Container, h.Sidecars, h.SidecarNetwork)
}

func (r *Runner) cleanup(ctx context.Context, container string, sidecars []string, network string) error {
	var errs []error
	if container != "" {
		if err := r.Engine.ContainerRemove(ctx, container); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", container, err))
		}
	}
	for _, s := range sidecars {
		if err := r.Engine.ContainerRemove(ctx, s); err != nil {
			errs = append(errs, fmt.Errorf("remove sidecar %s: %w", s, err))
		}
	}
	if network != "" && len(errs) == 0 { // a network with containers left on it cannot go
		if err := r.Engine.NetworkRemove(ctx, network); err != nil {
			errs = append(errs, fmt.Errorf("remove network %s: %w", network, err))
		}
	}
	return errors.Join(errs...)
}

// ensureNetwork creates the network spec names, or checks that the existing one
// has the settings spec asks for. NetworkEnsure keeps an existing network as it
// is, so without this check a -no-egress run would join a network with egress
// (created by an earlier run without the flag) and the target could reach the
// internet. A mismatch is an error naming what differs and remedy, the way out.
func (r *Runner) ensureNetwork(ctx context.Context, spec engine.NetworkSpec, remedy string) error {
	n, err := r.Engine.NetworkEnsure(ctx, spec)
	if err != nil {
		return fmt.Errorf("network %s: %w", spec.Name, err)
	}
	if diffs := networkMismatch(spec, n); len(diffs) > 0 {
		return fmt.Errorf("network %s already exists with other settings than this run needs: %s; %s",
			spec.Name, strings.Join(diffs, "; "), remedy)
	}
	return nil
}

// networkMismatch lists how the network n differs from spec. Subnet and gateway
// are compared only when spec sets them (the daemon picks them otherwise).
func networkMismatch(spec engine.NetworkSpec, n engine.Network) []string {
	var diffs []string
	want := spec.Driver
	if want == "" {
		want = "bridge"
	}
	if n.Driver != want {
		diffs = append(diffs, fmt.Sprintf("its driver is %q, not %q", n.Driver, want))
	}
	switch {
	case spec.Internal && !n.Internal:
		diffs = append(diffs, "it has egress (a route off the host), but -no-egress needs an internal network")
	case !spec.Internal && n.Internal:
		diffs = append(diffs, "it is internal (no egress, created with -no-egress), but this run asks for egress")
	}
	keys := make([]string, 0, len(spec.Options))
	for k := range spec.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if got := n.Options[k]; got != spec.Options[k] {
			diffs = append(diffs, fmt.Sprintf("its %s is %q, not %q", k, got, spec.Options[k]))
		}
	}
	if spec.Subnet != "" && !samePrefix(spec.Subnet, n.Subnet) {
		diffs = append(diffs, fmt.Sprintf("its subnet is %q, not %q", n.Subnet, spec.Subnet))
	}
	if spec.Gateway != "" && !sameAddr(spec.Gateway, n.Gateway) {
		diffs = append(diffs, fmt.Sprintf("its gateway is %q, not %q", n.Gateway, spec.Gateway))
	}
	return diffs
}

func samePrefix(a, b string) bool {
	pa, errA := netip.ParsePrefix(a)
	pb, errB := netip.ParsePrefix(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return pa.Masked() == pb.Masked()
}

func sameAddr(a, b string) bool {
	aa, errA := netip.ParseAddr(a)
	ab, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return aa == ab
}

// clearSidecarNetwork removes the sidecar network an earlier run of this state
// left behind, so the run creates it afresh with its own settings. NetworkEnsure
// keeps an existing network as it is, and a stale one may differ from what this
// run needs: an internal network left by a -no-egress run cannot publish ports
// in host mode. Every managed container labelled with the network goes first,
// including sidecars the template no longer declares (renamed or dropped since):
// they would keep the network attached and impossible to remove. A network that
// still cannot be removed is an error, not silently reused.
func (r *Runner) clearSidecarNetwork(ctx context.Context, scNet string) error {
	rows, err := r.Engine.ContainerList(ctx, true, contract.ContainerNamePrefix)
	if err != nil {
		return fmt.Errorf("list containers on network %s: %w", scNet, err)
	}
	for _, row := range rows {
		if row.Labels[LabelManaged] != "true" || row.Labels[LabelSidecarNetwork] != scNet {
			continue
		}
		if err := r.Engine.ContainerRemove(ctx, row.Name); err != nil {
			return fmt.Errorf("remove %s from stale network %s: %w", row.Name, scNet, err)
		}
	}
	if err := r.Engine.NetworkRemove(ctx, scNet); err != nil {
		return fmt.Errorf("remove stale network %s (a container vulnsuite did not start may still be attached): %w", scNet, err)
	}
	return nil
}

// startSidecars starts the state's sidecars on the private network scNet,
// each resolvable there under its template name. They run on the target's
// platform: a stack that needs emulation is emulated as a whole. It returns
// the name of every container it created, including one whose start then
// failed, so the caller can remove them all.
func (r *Runner) startSidecars(ctx context.Context, c *contract.Contract, st *contract.State, state, scNet, platform string) ([]string, error) {
	var names []string
	for _, sc := range c.Service.Sidecars {
		name := SidecarContainerName(c.ID(), state, sc.Name)
		ref := st.SidecarRef(sc)
		if exists, _ := r.Engine.ImageExists(ctx, ref, platform); !exists {
			if err := r.Engine.ImagePull(ctx, ref, platform, nil); err != nil {
				return names, fmt.Errorf("sidecar %s: %w", sc.Name, err)
			}
		}
		spec := engine.ContainerSpec{Name: name, Image: ref, Cmd: sc.Command, Env: mergeEnv(nil, sc.Environment),
			Labels: map[string]string{
				LabelManaged:        "true",
				LabelRole:           RoleSidecar,
				builder.LabelID:     c.ID(),
				builder.LabelState:  state,
				LabelSidecarNetwork: scNet,
			},
			Network:  &engine.NetworkAttachment{Name: scNet, Aliases: []string{sc.Name}},
			Platform: platform,
		}
		id, err := r.Engine.ContainerCreate(ctx, spec)
		if err != nil {
			return names, fmt.Errorf("sidecar %s: %w", sc.Name, err)
		}
		names = append(names, name)
		if err := r.Engine.ContainerStart(ctx, id); err != nil {
			return names, fmt.Errorf("sidecar %s: %w", sc.Name, err)
		}
	}
	return names, nil
}

// engineRemote reports whether the engine talks to a daemon on another machine.
// Engines that don't expose their host (e.g. test fakes) are treated as local.
func engineRemote(e engine.Engine) bool {
	h, ok := e.(interface{ Host() string })
	if !ok {
		return false
	}
	return remoteDaemonHost(h.Host())
}

// remoteDaemonHost classifies a DOCKER_HOST-style address: a local socket or a
// loopback tcp endpoint is local; tcp/ssh to any other host is remote.
func remoteDaemonHost(host string) bool {
	i := strings.Index(host, "://")
	if i < 0 {
		return false
	}
	scheme, rest := host[:i], host[i+3:]
	switch scheme {
	case "ssh":
		return true
	case "tcp", "http", "https":
		hostOnly := rest
		if h, _, err := net.SplitHostPort(rest); err == nil {
			hostOnly = h
		}
		return !isLoopbackHost(hostOnly)
	default: // unix, npipe, fd, ...
		return false
	}
}

// isLoopbackHost reports whether host names the local machine's loopback.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// probeFromHereFutile reports that no probe run on this machine can reach the
// target: host mode on a remote daemon that published the port on the daemon
// host's loopback (default -bind 127.0.0.1, or a wildcard -bind 0.0.0.0 / ::
// which we dial as 127.0.0.1). The port lives on the daemon's host, not here.
func probeFromHereFutile(h *Handle) bool {
	return h.Exposure.Mode == ModeHost && h.DaemonRemote && isLoopbackHost(h.EndpointHost)
}

// remoteProbeHint explains why a remote-daemon target could not be probed from
// here and names the flag that fixes it.
func remoteProbeHint(h *Handle) string {
	bind := h.Exposure.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	if isLoopbackHost(h.EndpointHost) {
		return fmt.Sprintf("could not verify from this machine: in host mode the port is published on the Docker daemon's "+
			"host (bind %s, reachable from here only as 127.0.0.1) and the daemon is remote, so the target is on another "+
			"machine. The target is up; pass -bind <an address of the daemon host reachable from here> to probe and scan it "+
			"from this machine, or scan from the daemon host.", bind)
	}
	return fmt.Sprintf("could not verify from this machine: nothing answered at %s, though the daemon reports the target up. "+
		"The daemon is remote -- make sure -bind %s is an address of the daemon host reachable from this machine.",
		h.ScannerTarget(), bind)
}

// allTransportFailures reports whether every probe failed to reach the target
// (so this machine could not get to it), rather than any reaching it.
func allTransportFailures(rs []probes.Result) bool {
	if len(rs) == 0 {
		return false
	}
	for _, r := range rs {
		if !r.Transport {
			return false
		}
	}
	return true
}

// probeAddress is where a probe run on this host can reach the target, or ""
// when it cannot (internal mode on Docker Desktop/OrbStack, macvlan).
func (r *Runner) probeAddress(h *Handle, c *contract.Contract) (string, int) {
	if h.Exposure.Mode == ModeHost {
		return h.EndpointHost, h.EndpointPort
	}
	if h.IP != "" {
		return h.IP, c.Service.PrimaryPort().Container
	}
	return "", 0
}

// awaitReady waits for the target's healthcheck. It stops early when the
// container exits (a crash on boot need not cost the whole ready timeout), and
// a target that is not ready gets a ReadyDetail with the reason and the last
// container log lines.
func (r *Runner) awaitReady(ctx context.Context, c *contract.Contract, h *Handle, override time.Duration) {
	timeout, err := contract.ParseDuration(c.Service.Healthcheck.Timeout, 60*time.Second)
	if err != nil {
		timeout = 60 * time.Second
	}
	if override > 0 {
		timeout = override
	}
	wctx, cancel := context.WithCancel(ctx)
	exited := make(chan *engine.ContainerDetail, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.watchExit(wctx, h.Container, exited, cancel)
	}()
	r.waitReady(wctx, c, h, timeout)
	cancel()
	<-done
	if h.Ready {
		return
	}
	var det *engine.ContainerDetail
	select {
	case det = <-exited:
	default:
		// The wait ended for another reason; the container may still have
		// exited in the meantime.
		if d, err := r.Engine.ContainerInspect(ctx, h.Container); err == nil && !d.Running {
			det = d
		}
	}
	if det != nil {
		code := det.ExitCode
		h.ExitCode = &code
		h.ReadyDetail = fmt.Sprintf("the container exited with code %d before it was ready", code)
	} else if ctx.Err() != nil {
		h.ReadyDetail = "cancelled before the target was ready"
		return
	} else {
		h.ReadyDetail = fmt.Sprintf("the healthcheck did not pass within %s", timeout)
	}
	if logs, err := r.Engine.ContainerLogs(ctx, h.Container, readyLogLines); err == nil {
		if logs = strings.TrimRight(logs, "\n"); strings.TrimSpace(logs) != "" {
			h.ReadyDetail += fmt.Sprintf("; last %d log lines:\n%s", readyLogLines, logs)
		}
	}
}

// watchExit polls the container until ctx ends; when it is no longer running
// it sends the detail on exited and calls stop.
func (r *Runner) watchExit(ctx context.Context, container string, exited chan<- *engine.ContainerDetail, stop context.CancelFunc) {
	every := r.ExitPoll
	if every <= 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		det, err := r.Engine.ContainerInspect(ctx, container)
		if err == nil && !det.Running {
			exited <- det
			stop()
			return
		}
	}
}

func (r *Runner) waitReady(ctx context.Context, c *contract.Contract, h *Handle, timeout time.Duration) {
	hc := c.Service.Healthcheck
	host, port := r.probeAddress(h, c)
	if host == "" {
		// Cannot reach it from here: run the healthcheck inside the target.
		h.Ready = r.waitReadyInside(ctx, c, h, time.Now().Add(timeout))
		return
	}
	if probeFromHereFutile(h) {
		// A remote daemon's loopback-published port never comes up here; don't
		// burn the whole healthcheck timeout against it. verify explains.
		h.Ready = r.waitReadyInside(ctx, c, h, time.Now().Add(timeout))
		return
	}
	{
		// Docker Desktop reports container IPs the host cannot route to, and a
		// remote daemon publishes host ports on its own machine. A connection
		// that is *refused* means the address is routable and the service just
		// isn't up yet; a timeout / no-route means we can't reach it from here at
		// all, so check from inside the target instead.
		reach := r.Reach
		if reach == nil {
			reach = probes.Reachability
		}
		if reach(host, port, 2*time.Second) == probes.Unreachable {
			sleepCtx(ctx, time.Second)
			if reach(host, port, 2*time.Second) == probes.Unreachable {
				if h.Exposure.Mode != ModeHost {
					h.IP = "" // verify will explain instead of failing
				}
				h.Ready = r.waitReadyInside(ctx, c, h, time.Now().Add(timeout))
				return
			}
		}
	}
	deadline := time.Now().Add(timeout)
	switch {
	case hc.HTTP != nil && h.Scheme != "":
		path := hc.HTTP.Path
		if path == "" {
			path = "/"
		}
		h.Ready = probes.WaitForHTTP(ctx, host, port, h.Scheme, path, hc.HTTP.Status, time.Until(deadline))
	case hc.TCP != nil && hc.TCP.Port != 0:
		// The healthcheck names a container port; in host mode it is reached on
		// its published host port. An unpublished port cannot be checked from
		// here, so fall back to the primary port.
		hcPort := hc.TCP.Port
		if pm := hostPortMap(h); pm != nil {
			if hp, ok := pm[hcPort]; ok {
				hcPort = hp
			} else {
				hcPort = port
			}
		}
		h.Ready = probes.WaitForPort(ctx, host, hcPort, time.Until(deadline))
	default:
		h.Ready = probes.WaitForPort(ctx, host, port, time.Until(deadline))
	}
}

// Exit codes of the in-container healthcheck scripts.
const (
	insideReady    = 0
	insideNotReady = 1
	insideCannot   = 3 // the script cannot tell (no /proc/net/tcp)
)

// insidePoll is how often the in-container healthcheck runs.
var insidePoll = 500 * time.Millisecond

// waitReadyInside runs the healthcheck from inside the target's own network
// namespace, for a target this machine cannot reach (internal mode on Docker
// Desktop/OrbStack, macvlan, a remote daemon). Without it the target would be
// ready as soon as it runs, and seeds would race the service's startup.
//
// A tcp (or default) healthcheck passes once something listens on the port,
// read from /proc/net/tcp{,6} with POSIX sh builtins only, so it works in any
// image with a shell. An http healthcheck uses curl when the image has it and
// otherwise falls back to the listening check. An image the check cannot run in
// (no shell, no /proc/net/tcp) gets the old answer: ready once it is running.
func (r *Runner) waitReadyInside(ctx context.Context, c *contract.Contract, h *Handle, deadline time.Time) bool {
	hc := c.Service.Healthcheck
	port := c.Service.PrimaryPort().Container
	if hc.TCP != nil && hc.TCP.Port != 0 {
		port = hc.TCP.Port
	}
	cmd := listenScript(port)
	if hc.HTTP != nil && h.Scheme != "" {
		cmd = httpScript(h.Scheme, port, hc.HTTP.Path, hc.HTTP.Status)
	}
	running := func() bool {
		det, err := r.Engine.ContainerInspect(ctx, h.Container)
		return err == nil && det.Running
	}
	for first := true; ; first = false {
		// At least one attempt, however short the timeout.
		left := time.Until(deadline)
		if (left <= 0 && !first) || ctx.Err() != nil {
			return false
		}
		code, _, err := r.Engine.ContainerExec(ctx, h.Container, cmd, min(10*time.Second, max(left, 5*time.Second)))
		switch {
		case ctx.Err() != nil:
			return false
		case err == nil && code == insideReady:
			return true
		case err == nil && code == insideNotReady:
			// not up yet
		case err != nil && !running():
			// Not started yet, or exited (the exit watcher then cancels ctx).
		default:
			// No shell (exec error, 126/127) or nothing to read: the check
			// cannot run in this image.
			return running()
		}
		sleepCtx(ctx, insidePoll)
	}
}

// listenScript exits 0 when a TCP socket listens on port in the namespace it
// runs in (state 0A in /proc/net/tcp or tcp6), 1 when none does, and 3 when
// neither file can be read. POSIX sh builtins only: no cat, grep or awk.
func listenScript(port int) string {
	return fmt.Sprintf(`p=%04X; seen=; for f in /proc/net/tcp /proc/net/tcp6; do [ -r "$f" ] || continue; seen=1; `+
		`while read -r _ l _ st _; do [ "$st" = 0A ] && [ "${l##*:}" = "$p" ] && exit 0; done < "$f"; done; `+
		`[ -n "$seen" ] || exit 3; exit 1`, port)
}

// httpScript runs an http healthcheck with curl from inside the target, or the
// listening check when the image has no curl. want 0 accepts any status.
func httpScript(scheme string, port int, path string, want int) string {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, port, path)
	ok := `[ "$s" != 000 ]`
	if want != 0 {
		ok = fmt.Sprintf(`[ "$s" = %d ]`, want)
	}
	return fmt.Sprintf(`if command -v curl >/dev/null 2>&1; then s=$(curl -sk -o /dev/null -w '%%{http_code}' --max-time 5 %s); `+
		`%s && exit 0; exit 1; fi; %s`, shellQuote(url), ok, listenScript(port))
}

// shellQuote quotes s as one sh word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sleepCtx sleeps for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// verify runs the state's probes and folds failed or skipped seed steps into
// the result: the probes may pass on the image alone, but the state the seeds
// were meant to set up is not guaranteed, so that is a failed verify.
func (r *Runner) verify(ctx context.Context, c *contract.Contract, st *contract.State, h *Handle) {
	r.runProbes(ctx, c, st, h)
	sd := seedDetail(h)
	if sd == "" {
		return
	}
	if h.VerifyDetail != "" {
		sd += "\n" + h.VerifyDetail
	}
	h.VerifyDetail = sd
	if h.VerifyOK != nil {
		*h.VerifyOK = false
	}
}

func (r *Runner) runProbes(ctx context.Context, c *contract.Contract, st *contract.State, h *Handle) {
	if len(st.Verify) == 0 {
		h.VerifyDetail = "no verify probes declared"
		return
	}
	exec := func(ctx context.Context, container, command string, timeout time.Duration) (int, string, error) {
		return r.Engine.ContainerExec(ctx, container, command, timeout)
	}
	host, port := r.probeAddress(h, c)
	if host == "" {
		r.runExecProbesOnly(ctx, st, h, exec, fmt.Sprintf("could not verify from this host in %s mode: the target's address lives on the Docker daemon's network, "+
			"not this machine's (normal on Docker Desktop/OrbStack and macvlan, and whenever the daemon is remote). "+
			"The target is up; scan it from a container on the same network, or use --expose host.", h.Exposure.Mode))
		return
	}
	if probeFromHereFutile(h) {
		// The probe address resolves to our own loopback but the daemon, and so
		// the target, is elsewhere. Report it as unreachable-from-here, not as a
		// wrong state, and name the flag that fixes it.
		r.runExecProbesOnly(ctx, st, h, exec, remoteProbeHint(h))
		return
	}
	scheme := h.Scheme
	if scheme == "" {
		scheme = "http"
	}
	ok, results := probes.RunAll(ctx, st.Verify, probes.Target{
		Host: host, Port: port, Scheme: scheme, Schemes: portSchemes(c), Container: h.Container, PortMap: hostPortMap(h),
		Exec: exec,
	})
	if h.DaemonRemote && allTransportFailures(results) {
		// Every probe failed to connect and the daemon is remote: the bound
		// address isn't reachable from here, which is an addressing problem, not
		// a wrong state.
		h.Probes = results
		h.VerifyDetail = remoteProbeHint(h)
		return
	}
	h.VerifyOK = &ok
	h.Probes = results
	h.VerifyDetail = probes.FormatResults(results)
}

// runExecProbesOnly verifies a target this machine cannot reach. exec and
// sequence probes need no network path (they run through the engine and on
// the private sidecar network), so they run; the network probes are skipped
// and why says why. A failed exec or sequence probe fails verify. When every
// probe is one of those and all pass, verify passes; when network probes were
// skipped, the result is partial and VerifyOK stays nil (not verified), with
// the in-container results in the detail.
func (r *Runner) runExecProbesOnly(ctx context.Context, st *contract.State, h *Handle, exec probes.ExecFunc, why string) {
	var execs []contract.Probe
	for _, p := range st.Verify {
		if k := p.Kind(); k == "exec" || k == "sequence" {
			execs = append(execs, p)
		}
	}
	if len(execs) == 0 {
		h.VerifyDetail = why
		return
	}
	ok, results := probes.RunAll(ctx, execs, probes.Target{Container: h.Container, Exec: exec})
	h.Probes = results
	h.VerifyDetail = probes.FormatResults(results)
	skipped := len(st.Verify) - len(execs)
	if skipped > 0 {
		h.VerifyDetail += fmt.Sprintf("\nskip %d network probe(s): %s", skipped, why)
	}
	if !ok || skipped == 0 {
		h.VerifyOK = &ok
	}
}

// portSchemes is the scheme of every declared container port ("" for raw TCP),
// so a probe naming a port speaks that port's protocol.
func portSchemes(c *contract.Contract) map[int]string {
	m := make(map[int]string, len(c.Service.Ports))
	for _, p := range c.Service.Ports {
		m[p.Container] = p.Scheme()
	}
	return m
}

// hostPortMap is container port -> host port for every published port in host
// mode, or nil in other modes (where probes dial container ports directly).
func hostPortMap(h *Handle) map[int]int {
	if h.Exposure.Mode != ModeHost {
		return nil
	}
	m := make(map[int]int, len(h.PublishedPorts))
	for _, p := range h.PublishedPorts {
		m[p.ContainerPort] = p.HostPort
	}
	return m
}

// -- fleet ---------------------------------------------------------------------

// Target is a running target as seen by `ps` / `targets`.
type Target struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Container string `json:"container"`
	Status    string `json:"status"`
	Image     string `json:"image"`
	IP        string `json:"ip,omitempty"`
	HostIP    string `json:"host_ip,omitempty"` // host IP the primary port is published on (host mode)
	HostPort  int    `json:"host_port,omitempty"`
	// Ports is every published port's host binding (host mode), by ascending
	// container port. HostIP/HostPort above mirror the first. Scheme is unset
	// here (the daemon doesn't know it); see Published.
	Ports []PublishedPort `json:"ports,omitempty"`
	// Published is the ports the target publishes to a scanner with their
	// schemes, primary first, as recorded on the container at run time
	// (LabelPorts). Nil for containers started before vulnsuite recorded them:
	// callers then fall back to the template.
	Published []PublishedPort `json:"published_ports,omitempty"`
}

// fleetMember classifies a listed container: whether vulnsuite manages it,
// whether it is a target (not a sidecar), and its template id and state.
// Containers from before the role/state labels fall back to the name.
func fleetMember(row engine.ContainerInfo) (managed, target bool, id, state string) {
	if row.Labels[LabelManaged] != "true" {
		return false, false, "", ""
	}
	id, state = row.Labels[builder.LabelID], row.Labels[builder.LabelState]
	switch row.Labels[LabelRole] {
	case RoleSidecar:
		return true, false, id, state
	case RoleTarget:
		if id != "" && state != "" {
			return true, true, id, state
		}
	}
	nid, nstate, ok := contract.ParseContainerName(row.Name)
	if !ok {
		return true, false, id, state // e.g. a legacy sidecar, vulnsuite-<id>-<sidecar>
	}
	if id == "" {
		id = nid
	}
	return true, true, id, nstate
}

// Running lists running vulnsuite targets (not sidecars). A target's IP is its
// address on the network its scanner-facing address lives on (its label), else
// on network, never on its private sidecar network.
func (r *Runner) Running(ctx context.Context, network string) ([]Target, error) {
	if network == "" {
		network = DefaultNetwork
	}
	rows, err := r.Engine.ContainerList(ctx, false, contract.ContainerNamePrefix)
	if err != nil {
		return nil, err
	}
	var out []Target
	for _, row := range rows {
		managed, target, id, state := fleetMember(row)
		if !managed || !target {
			continue
		}
		t := Target{ID: id, State: state, Container: row.Name, Status: row.Status, Image: row.Image}
		if v, ok := row.Labels[LabelPorts]; ok {
			t.Published = ParsePortsLabel(v)
		}
		if det, err := r.Engine.ContainerInspect(ctx, row.Name); err == nil {
			prefer := row.Labels[LabelNetwork]
			if _, ok := det.IPs[prefer]; !ok || prefer == "" {
				prefer = network
			}
			t.IP = pickIP(det.IPs, prefer, row.Labels[LabelSidecarNetwork])
			for portProto, b := range det.Ports {
				t.Ports = append(t.Ports, PublishedPort{ContainerPort: containerPortOf(portProto), HostIP: b.IP, HostPort: b.Port})
			}
			sort.Slice(t.Ports, func(i, j int) bool { return t.Ports[i].ContainerPort < t.Ports[j].ContainerPort })
			if len(t.Ports) > 0 {
				t.HostIP, t.HostPort = t.Ports[0].HostIP, t.Ports[0].HostPort
			}
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Container < out[j].Container })
	return out, nil
}

// StopAll removes every container vulnsuite manages (targets and sidecars, in
// every state), or only those of one template, matched exactly on the
// dev.vulnsuite.id label (so stopping "foo" leaves "foo-bar" alone), then the
// private sidecar networks they used. Every removal is attempted; it returns
// the container names removed and the failures joined.
func (r *Runner) StopAll(ctx context.Context, templateID string) ([]string, error) {
	rows, err := r.Engine.ContainerList(ctx, true, contract.ContainerNamePrefix)
	if err != nil {
		return nil, err
	}
	var names []string
	var errs []error
	nets := map[string]bool{}
	for _, row := range rows {
		managed, _, id, _ := fleetMember(row)
		if !managed || (templateID != "" && id != templateID) {
			continue
		}
		if n := row.Labels[LabelSidecarNetwork]; n != "" {
			nets[n] = true
		}
		if err := r.Engine.ContainerRemove(ctx, row.Name); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", row.Name, err))
			continue
		}
		names = append(names, row.Name)
	}
	if len(errs) == 0 {
		netNames := make([]string, 0, len(nets))
		for n := range nets {
			netNames = append(netNames, n)
		}
		sort.Strings(netNames)
		for _, n := range netNames {
			if err := r.Engine.NetworkRemove(ctx, n); err != nil {
				errs = append(errs, fmt.Errorf("remove network %s: %w", n, err))
			}
		}
	}
	sort.Strings(names)
	return names, errors.Join(errs...)
}

// PruneNetwork removes the internal network.
func (r *Runner) PruneNetwork(ctx context.Context, network string) error {
	if network == "" {
		network = DefaultNetwork
	}
	return r.Engine.NetworkRemove(ctx, network)
}

func mergeEnv(a, b map[string]string) []string {
	m := map[string]string{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// containerPortOf extracts the port number from an engine port key like
// "9999/tcp".
func containerPortOf(portProto string) int {
	s := portProto
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	n, _ := strconv.Atoi(s)
	return n
}

// pinnedHostPorts resolves the explicitly pinned host ports in host mode
// (-host-port for the primary, -host-port-map for the rest), checking them for
// duplicates and, when the daemon is local (checkFree), that nothing listens on
// them yet, so a clash fails before any container is created. Returns
// container port -> host port; a port that is not pinned is absent, and is
// published on host port 0 for the daemon to assign.
func pinnedHostPorts(exp Exposure, pubs []contract.Port, checkFree bool) (map[int]int, error) {
	out := make(map[int]int, len(pubs))
	used := map[int]bool{}
	for i, pp := range pubs {
		want := 0
		if i == 0 {
			want = exp.HostPort // -host-port maps the primary
		}
		if m, ok := exp.HostPortMap[pp.Container]; ok {
			want = m
		}
		if want == 0 {
			continue
		}
		if used[want] {
			return nil, fmt.Errorf("host port %d is requested for more than one container port", want)
		}
		if checkFree {
			if err := assertPortFree(exp.Bind, want); err != nil {
				return nil, fmt.Errorf("cannot publish container port %d: %w", pp.Container, err)
			}
		}
		used[want] = true
		out[pp.Container] = want
	}
	return out, nil
}

// assignedHostPorts fills in the host port of every published port from the
// started container's inspect data (the daemon assigned the unpinned ones),
// and the endpoint port from the primary.
func assignedHostPorts(h *Handle, det *engine.ContainerDetail) error {
	for i := range h.PublishedPorts {
		p := &h.PublishedPorts[i]
		b, ok := det.Ports[fmt.Sprintf("%d/tcp", p.ContainerPort)]
		if !ok || b.Port == 0 {
			if p.HostPort == 0 {
				return fmt.Errorf("the daemon reported no host port for container port %d of %s", p.ContainerPort, h.Container)
			}
			continue // pinned: keep what was asked for
		}
		p.HostPort = b.Port
		if i == 0 {
			h.EndpointPort = b.Port
		}
	}
	return nil
}

func assertPortFree(bind string, port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(normalizeHostIP(bind), strconv.Itoa(port)), time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("port %d is already in use on %s; pick another with --host-port, or use --expose internal (one host port serves one target)", port, bind)
	}
	return nil
}
