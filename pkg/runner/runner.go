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
	Parent   string `json:"parent,omitempty"` // macvlan parent interface
	IP       string `json:"ip,omitempty"`     // macvlan static ip
	Subnet   string `json:"subnet,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
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
	// VerifyOK is nil when verification was skipped.
	VerifyOK     *bool           `json:"verify_ok"`
	VerifyDetail string          `json:"verify_detail,omitempty"`
	Probes       []probes.Result `json:"probes,omitempty"`
}

// ScannerTarget is what a scanner should be pointed at (scheme://host:port,
// or host:port for raw TCP services).
func (h *Handle) ScannerTarget() string {
	return FormatTarget(h.Scheme, h.EndpointHost, h.EndpointPort)
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
		EndpointPort: port.Container, Scheme: port.Scheme()}

	switch exp.Mode {
	case ModeInternal:
		if _, err := r.Engine.NetworkEnsure(ctx, engine.NetworkSpec{Name: exp.Network, Internal: exp.Internal}); err != nil {
			return nil, fmt.Errorf("network %s: %w", exp.Network, err)
		}
		spec.Network = &engine.NetworkAttachment{Name: exp.Network, Aliases: []string{c.ID()}}
		h.EndpointHost = c.ID()
	case ModeHost:
		hp := exp.HostPort
		if hp == 0 {
			hp, err = freePort(exp.Bind)
			if err != nil {
				return nil, err
			}
		} else if err := assertPortFree(exp.Bind, hp); err != nil {
			return nil, err
		}
		spec.Ports = []engine.PortBinding{{HostIP: exp.Bind, HostPort: hp, ContainerPort: port.Container, Protocol: "tcp"}}
		h.EndpointHost, h.EndpointPort = exp.Bind, hp
		if exp.Bind == "0.0.0.0" {
			h.EndpointHost = "127.0.0.1"
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
	if h.Exposure.Mode != ModeHost {
		// Docker Desktop reports container IPs the host cannot route to. A
		// connection that is *refused* means the address is routable and the
		// service just isn't up yet; a timeout / no-route means we can't reach
		// it from here at all, so don't sit through the whole healthcheck.
		reach := r.Reach
		if reach == nil {
			reach = probes.Reachability
		}
		if reach(host, port, 2*time.Second) == probes.Unreachable {
			time.Sleep(time.Second)
			if reach(host, port, 2*time.Second) == probes.Unreachable {
				h.IP = "" // verify will explain instead of failing
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
		h.VerifyDetail = fmt.Sprintf("could not verify from this host in %s mode (normal on Docker Desktop/OrbStack and macvlan). "+
			"The target is up; scan it from a container on the same network, or use --expose host.", h.Exposure.Mode)
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
	HostPort  int    `json:"host_port,omitempty"`
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
			for _, hp := range det.Ports {
				t.HostPort = hp
				break
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
