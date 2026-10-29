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
	ID           string            `json:"id"`
	State        string            `json:"state"`
	Container    string            `json:"container"`
	Image        *builder.Resolved `json:"image"`
	Exposure     Exposure          `json:"exposure"`
	Sidecars     []string          `json:"sidecars,omitempty"`
	EndpointHost string            `json:"endpoint_host"` // alias, 127.0.0.1, or macvlan ip
	EndpointPort int               `json:"endpoint_port"`
	IP           string            `json:"ip,omitempty"` // container ip (internal/macvlan)
	Scheme       string            `json:"scheme"`       // http | https | "" (raw tcp)
	Ready        bool              `json:"ready"`
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
}

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
	name := c.ContainerName(state)
	port := c.Service.PrimaryPort()

	// Replace any stale container of the same name.
	if err := r.Engine.ContainerRemove(ctx, name); err != nil {
		return nil, err
	}

	spec := engine.ContainerSpec{
		Name:  name,
		Image: img.Ref,
		User:  c.Service.User,
		Labels: map[string]string{
			LabelManaged:       "true",
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
	}
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

	h := &Handle{ID: c.ID(), State: state, Container: name, Image: img, Exposure: exp,
		EndpointPort: port.Container, Scheme: port.Scheme(), DaemonRemote: engineRemote(r.Engine)}

	switch exp.Mode {
	case ModeInternal:
		if _, err := r.Engine.NetworkEnsure(ctx, engine.NetworkSpec{Name: exp.Network, Internal: exp.Internal}); err != nil {
			return nil, fmt.Errorf("network %s: %w", exp.Network, err)
		}
		spec.Network = &engine.NetworkAttachment{Name: exp.Network, Aliases: []string{c.ID()}}
		h.EndpointHost = c.ID()
		for _, pp := range c.Service.HostPublishPorts() {
			h.PublishedPorts = append(h.PublishedPorts, PublishedPort{ContainerPort: pp.Container, Scheme: pp.Scheme()})
		}
	case ModeHost:
		pubs := c.Service.HostPublishPorts()
		alloc, err := allocateHostPorts(exp, pubs)
		if err != nil {
			return nil, err
		}
		for i, pp := range pubs {
			hp := alloc[pp.Container]
			spec.Ports = append(spec.Ports, engine.PortBinding{HostIP: exp.Bind, HostPort: hp, ContainerPort: pp.Container, Protocol: "tcp"})
			h.PublishedPorts = append(h.PublishedPorts, PublishedPort{ContainerPort: pp.Container, HostIP: exp.Bind, HostPort: hp, Scheme: pp.Scheme()})
			if i == 0 {
				h.EndpointHost, h.EndpointPort = exp.Bind, hp
				if exp.Bind == "0.0.0.0" {
					h.EndpointHost = "127.0.0.1"
				}
			}
		}
	case ModeMacvlan:
		if exp.Parent == "" {
			return nil, errors.New("macvlan exposure needs --parent <host interface>")
		}
		netName := "vulnsuite-macvlan-" + exp.Parent
		if _, err := r.Engine.NetworkEnsure(ctx, engine.NetworkSpec{
			Name: netName, Driver: "macvlan", Options: map[string]string{"parent": exp.Parent},
			Subnet: exp.Subnet, Gateway: exp.Gateway,
		}); err != nil {
			return nil, fmt.Errorf("macvlan network: %w", err)
		}
		spec.Network = &engine.NetworkAttachment{Name: netName, IPv4: exp.IP}
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

	sidecars, err := r.startSidecars(ctx, c, st, exp)
	if err != nil {
		return nil, err
	}
	h.Sidecars = sidecars

	id, err := r.Engine.ContainerCreate(ctx, spec)
	if err != nil {
		r.cleanup(ctx, name, sidecars)
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	if err := r.Engine.ContainerStart(ctx, id); err != nil {
		r.cleanup(ctx, name, sidecars)
		return nil, fmt.Errorf("start %s: %w", name, err)
	}

	// Discover the address a probe from this host can use.
	if det, err := r.Engine.ContainerInspect(ctx, name); err == nil {
		if ip, ok := det.IPs[exp.Network]; ok {
			h.IP = ip
		} else {
			for _, ip := range det.IPs {
				h.IP = ip
				break
			}
		}
		if exp.Mode == ModeMacvlan && exp.IP == "" && h.IP != "" {
			h.EndpointHost = h.IP
		}
	}

	r.awaitReady(ctx, c, h, opts.ReadyTimeout)
	for _, step := range st.Seed {
		_, _, _ = r.Engine.ContainerExec(ctx, name, step.Run, 2*time.Minute)
	}
	if opts.Verify {
		r.verify(ctx, c, st, h)
	}
	return h, nil
}

// Stop tears a handle down.
func (r *Runner) Stop(ctx context.Context, h *Handle) {
	r.cleanup(ctx, h.Container, h.Sidecars)
}

func (r *Runner) cleanup(ctx context.Context, container string, sidecars []string) {
	_ = r.Engine.ContainerRemove(ctx, container)
	for _, s := range sidecars {
		_ = r.Engine.ContainerRemove(ctx, s)
	}
}

func (r *Runner) startSidecars(ctx context.Context, c *contract.Contract, st *contract.State, exp Exposure) ([]string, error) {
	var names []string
	for _, sc := range c.Service.Sidecars {
		name := contract.ContainerNamePrefix + strings.ReplaceAll(c.ID(), "/", "-") + "-" + sc.Name
		_ = r.Engine.ContainerRemove(ctx, name)
		ref := st.SidecarRef(sc)
		if exists, _ := r.Engine.ImageExists(ctx, ref); !exists {
			if err := r.Engine.ImagePull(ctx, ref, nil); err != nil {
				return names, fmt.Errorf("sidecar %s: %w", sc.Name, err)
			}
		}
		spec := engine.ContainerSpec{Name: name, Image: ref, Cmd: sc.Command, Env: mergeEnv(nil, sc.Environment),
			Labels: map[string]string{LabelManaged: "true", builder.LabelID: c.ID()}}
		if exp.Mode == ModeInternal {
			spec.Network = &engine.NetworkAttachment{Name: exp.Network, Aliases: []string{sc.Name}}
		}
		id, err := r.Engine.ContainerCreate(ctx, spec)
		if err != nil {
			return names, fmt.Errorf("sidecar %s: %w", sc.Name, err)
		}
		if err := r.Engine.ContainerStart(ctx, id); err != nil {
			return names, fmt.Errorf("sidecar %s: %w", sc.Name, err)
		}
		names = append(names, name)
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
// host's loopback (default -bind 127.0.0.1, or -bind 0.0.0.0 which we dial as
// 127.0.0.1). The port lives on the daemon's host, not here.
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

func (r *Runner) awaitReady(ctx context.Context, c *contract.Contract, h *Handle, override time.Duration) {
	hc := c.Service.Healthcheck
	timeout, err := contract.ParseDuration(hc.Timeout, 60*time.Second)
	if err != nil {
		timeout = 60 * time.Second
	}
	if override > 0 {
		timeout = override
	}
	running := func() bool {
		det, err := r.Engine.ContainerInspect(ctx, h.Container)
		return err == nil && det.Running
	}
	host, port := r.probeAddress(h, c)
	if host == "" {
		// Cannot reach it from here; the engine says whether it's running.
		time.Sleep(2 * time.Second)
		h.Ready = running()
		return
	}
	if probeFromHereFutile(h) {
		// A remote daemon's loopback-published port never comes up here; don't
		// burn the whole healthcheck timeout against it. verify explains.
		time.Sleep(time.Second)
		h.Ready = running()
		return
	}
	{
		// Docker Desktop reports container IPs the host cannot route to, and a
		// remote daemon publishes host ports on its own machine. A connection
		// that is *refused* means the address is routable and the service just
		// isn't up yet; a timeout / no-route means we can't reach it from here at
		// all, so don't sit through the whole healthcheck.
		reach := r.Reach
		if reach == nil {
			reach = probes.Reachability
		}
		if reach(host, port, 2*time.Second) == probes.Unreachable {
			time.Sleep(time.Second)
			if reach(host, port, 2*time.Second) == probes.Unreachable {
				if h.Exposure.Mode != ModeHost {
					h.IP = "" // verify will explain instead of failing
				}
				h.Ready = running()
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
		h.Ready = probes.WaitForPort(ctx, host, hc.TCP.Port, time.Until(deadline))
	default:
		h.Ready = probes.WaitForPort(ctx, host, port, time.Until(deadline))
	}
}

func (r *Runner) verify(ctx context.Context, c *contract.Contract, st *contract.State, h *Handle) {
	if len(st.Verify) == 0 {
		h.VerifyDetail = "no verify probes declared"
		return
	}
	host, port := r.probeAddress(h, c)
	if host == "" {
		h.VerifyDetail = fmt.Sprintf("could not verify from this host in %s mode: the target's address lives on the Docker daemon's network, "+
			"not this machine's (normal on Docker Desktop/OrbStack and macvlan, and whenever the daemon is remote). "+
			"The target is up; scan it from a container on the same network, or use --expose host.", h.Exposure.Mode)
		return
	}
	if probeFromHereFutile(h) {
		// The probe address resolves to our own loopback but the daemon, and so
		// the target, is elsewhere. Report it as unreachable-from-here, not as a
		// wrong state, and name the flag that fixes it.
		h.VerifyDetail = remoteProbeHint(h)
		return
	}
	scheme := h.Scheme
	if scheme == "" {
		scheme = "http"
	}
	ok, results := probes.RunAll(ctx, st.Verify, probes.Target{
		Host: host, Port: port, Scheme: scheme, Container: h.Container,
		Exec: func(ctx context.Context, container, command string, timeout time.Duration) (int, string, error) {
			return r.Engine.ContainerExec(ctx, container, command, timeout)
		},
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
	// here (the daemon doesn't know it); callers fill it from the template.
	Ports []PublishedPort `json:"ports,omitempty"`
}

// Running lists running vulnsuite targets (not sidecars).
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
		id, state, ok := contract.ParseContainerName(row.Name)
		if !ok {
			continue
		}
		t := Target{ID: id, State: state, Container: row.Name, Status: row.Status, Image: row.Image}
		if det, err := r.Engine.ContainerInspect(ctx, row.Name); err == nil {
			if ip, ok := det.IPs[network]; ok {
				t.IP = ip
			} else {
				for _, ip := range det.IPs {
					t.IP = ip
					break
				}
			}
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

// StopAll removes every vulnsuite container (optionally only one template's).
// It returns the names removed.
func (r *Runner) StopAll(ctx context.Context, templateID string) ([]string, error) {
	prefix := contract.ContainerNamePrefix
	if templateID != "" {
		prefix += strings.ReplaceAll(templateID, "/", "-") + "-"
	}
	rows, err := r.Engine.ContainerList(ctx, true, prefix)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, row := range rows {
		if err := r.Engine.ContainerRemove(ctx, row.Name); err != nil {
			return names, err
		}
		names = append(names, row.Name)
	}
	sort.Strings(names)
	return names, nil
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

func freePort(bind string) (int, error) {
	host := bind
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// allocateHostPorts resolves the host port for each published container port in
// host mode. Explicit ports (-host-port for the primary, -host-port-map for the
// rest) are checked for duplicates and availability; the remaining ports get
// distinct free host ports. Returns container port -> host port. All checks run
// before any container is created, so a clash fails cleanly.
func allocateHostPorts(exp Exposure, pubs []contract.Port) (map[int]int, error) {
	out := make(map[int]int, len(pubs))
	used := map[int]bool{}
	var auto []int
	for i, pp := range pubs {
		want := 0
		if i == 0 {
			want = exp.HostPort // -host-port maps the primary
		}
		if m, ok := exp.HostPortMap[pp.Container]; ok {
			want = m
		}
		if want == 0 {
			auto = append(auto, pp.Container)
			continue
		}
		if used[want] {
			return nil, fmt.Errorf("host port %d is requested for more than one container port", want)
		}
		if err := assertPortFree(exp.Bind, want); err != nil {
			return nil, fmt.Errorf("cannot publish container port %d: %w", pp.Container, err)
		}
		used[want] = true
		out[pp.Container] = want
	}
	// Grab distinct free host ports for the rest, holding each listener open so
	// the OS does not hand out the same port twice, then release them all.
	host := exp.Bind
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	var held []net.Listener
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()
	for _, cp := range auto {
		l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, err
		}
		held = append(held, l)
		p := l.Addr().(*net.TCPAddr).Port
		used[p] = true
		out[cp] = p
	}
	return out, nil
}

func assertPortFree(bind string, port int) error {
	host := bind
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("port %d is already in use on %s; pick another with --host-port, or use --expose internal (one host port serves one target)", port, bind)
	}
	return nil
}
