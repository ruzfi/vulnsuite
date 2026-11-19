// Package engine abstracts the container engine vulnsuite builds and runs
// targets on. The default implementation (engine/docker) speaks the Docker
// Engine API directly over the socket; anything that implements Engine can be
// swapped in.
package engine

import (
	"context"
	"io"
	"strings"
	"time"
)

// BuildOptions describes an image build.
type BuildOptions struct {
	// Context is a tar stream of the build context.
	Context io.Reader
	// Tags to apply to the result.
	Tags []string
	// Dockerfile path inside the context (default "Dockerfile").
	Dockerfile string
	BuildArgs  map[string]string
	NoCache    bool
	Pull       bool
	Labels     map[string]string
	// Platform, e.g. "linux/amd64" (empty = engine default).
	Platform string
}

// PortBinding publishes a container port on the host.
type PortBinding struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Protocol      string // tcp | udp
}

// Device passes a host device through.
type Device struct {
	PathOnHost      string
	PathInContainer string
	Permissions     string
}

// NetworkAttachment attaches the container to a network.
type NetworkAttachment struct {
	Name    string
	Aliases []string
	IPv4    string
}

// ContainerSpec describes a container to create.
type ContainerSpec struct {
	Name        string
	Image       string
	Cmd         []string
	Env         []string
	User        string
	Labels      map[string]string
	CapAdd      []string
	CapDrop     []string
	SecurityOpt []string
	Devices     []Device
	Ports       []PortBinding
	Network     *NetworkAttachment
	// Binds are host:container[:mode] volume binds.
	Binds []string
	// AutoRemove removes the container when it exits.
	AutoRemove bool
	// Platform runs the image for this platform, e.g. "linux/amd64" under
	// emulation (empty = engine default, normally the host's).
	Platform string
}

// ContainerInfo is a row from a container listing.
type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	State  string // running, exited, ...
	Status string // human text, e.g. "Up 3 minutes"
	Labels map[string]string
}

// ContainerDetail is the inspected view of a container.
type ContainerDetail struct {
	ID       string
	Name     string
	Image    string
	Running  bool
	ExitCode int
	// IPs maps network name -> IPv4 address.
	IPs map[string]string
	// Ports maps "containerPort/proto" -> the host binding (first binding).
	Ports map[string]HostBinding
}

// HostBinding is a published port's binding on the host: the host IP it is
// published on (empty = all interfaces) and the host port.
type HostBinding struct {
	IP   string
	Port int
}

// NetworkSpec describes a network to create.
type NetworkSpec struct {
	Name    string
	Driver  string // bridge (default) | macvlan
	Options map[string]string
	Subnet  string
	Gateway string
	// Internal networks have no route off the host.
	Internal bool
}

// Network is a network as the daemon reports it.
type Network struct {
	ID       string
	Driver   string
	Internal bool
	Options  map[string]string
	// Subnet and Gateway are the first IPAM config ("" when there is none).
	Subnet  string
	Gateway string
}

// HostInfo describes the daemon's platform.
type HostInfo struct {
	OS   string // linux, windows
	Arch string // amd64, arm64, ...
	// CPUFlags are the CPU feature flags of the daemon's machine as its
	// /proc/cpuinfo lists them ("flags" on x86, "Features" on arm64). Info
	// does not fill them: the daemon's API does not report them, and reading
	// them takes a container (runner.ReadCPUFlags). They are meaningful only
	// when CPUFlagsKnown is set.
	CPUFlags      []string
	CPUFlagsKnown bool
	// CPUFlagsError says why reading the flags failed ("" when they were
	// read, or not tried).
	CPUFlagsError string
}

// Engine is the container backend.
type Engine interface {
	// Ping checks connectivity and returns the engine's version string.
	Ping(ctx context.Context) (string, error)
	// Info returns the daemon's OS/arch, for preflighting target requirements.
	Info(ctx context.Context) (HostInfo, error)

	// ImageExists reports whether ref is present locally. With a platform
	// (e.g. "linux/amd64") the local image must also be for that platform, so
	// a native image is not mistaken for the one an emulated run needs.
	ImageExists(ctx context.Context, ref, platform string) (bool, error)
	// ImagePull pulls ref for platform (empty = engine default), streaming
	// progress text to out (may be nil).
	ImagePull(ctx context.Context, ref, platform string, out io.Writer) error
	// ImageBuild builds an image, streaming build output to out (may be nil).
	ImageBuild(ctx context.Context, opts BuildOptions, out io.Writer) error
	ImageTag(ctx context.Context, source, target string) error
	// ImagePush pushes ref, streaming progress text to out (may be nil).
	ImagePush(ctx context.Context, ref string, out io.Writer) error
	// ImageRemove deletes an image (force untags even when containers use it).
	ImageRemove(ctx context.Context, ref string, force bool) error
	// ImageList lists image references (repo:tag) matching a repository prefix.
	ImageList(ctx context.Context, repoPrefix string) ([]string, error)

	ContainerCreate(ctx context.Context, spec ContainerSpec) (id string, err error)
	ContainerStart(ctx context.Context, idOrName string) error
	// ContainerRemove force-removes a container; a missing container is not an error.
	ContainerRemove(ctx context.Context, idOrName string) error
	// ContainerList lists containers whose name starts with namePrefix.
	ContainerList(ctx context.Context, all bool, namePrefix string) ([]ContainerInfo, error)
	ContainerInspect(ctx context.Context, idOrName string) (*ContainerDetail, error)
	// ContainerExec runs a shell command inside the container.
	ContainerExec(ctx context.Context, idOrName, command string, timeout time.Duration) (exitCode int, output string, err error)
	// ContainerLogs returns the last lines of a container's logs.
	ContainerLogs(ctx context.Context, idOrName string, tail int) (string, error)
	// ContainerWait blocks until the container exits and returns its exit code.
	ContainerWait(ctx context.Context, idOrName string) (int, error)

	// NetworkEnsure creates the network if it does not exist and returns it
	// as the daemon reports it. An existing network is returned unchanged,
	// with its own settings (which may differ from spec): the caller compares.
	NetworkEnsure(ctx context.Context, spec NetworkSpec) (Network, error)
	NetworkExists(ctx context.Context, name string) (bool, error)
	// NetworkRemove deletes a network; a missing network is not an error.
	NetworkRemove(ctx context.Context, name string) error
	// NetworkConnect attaches an existing (created or running) container to a
	// further network, resolvable there under aliases.
	NetworkConnect(ctx context.Context, network, container string, aliases []string) error
}

// PlatformMatches reports whether an image built for imgOS/imgArch/imgVariant
// satisfies want, a platform such as "linux/amd64" or "linux/arm/v7". An empty
// want matches anything; an image that reports no architecture does not match
// a non-empty want. Architecture aliases (x86_64, aarch64) are normalised, and
// a want without a variant accepts any variant.
func PlatformMatches(want, imgOS, imgArch, imgVariant string) bool {
	if want == "" {
		return true
	}
	wOS, wArch, wVariant := SplitPlatform(want)
	if imgArch == "" || normArch(imgArch) != wArch {
		return false
	}
	if imgOS != "" && !strings.EqualFold(imgOS, wOS) {
		return false
	}
	if wVariant == "" {
		return true
	}
	if imgVariant == "" && wArch == "arm64" {
		imgVariant = "v8" // arm64 images usually omit their default variant
	}
	return strings.EqualFold(imgVariant, wVariant)
}

// SplitPlatform splits "os/arch[/variant]" into its normalised parts.
func SplitPlatform(p string) (os, arch, variant string) {
	parts := strings.SplitN(strings.ToLower(strings.TrimSpace(p)), "/", 3)
	os = parts[0]
	if len(parts) > 1 {
		arch = normArch(parts[1])
	}
	if len(parts) > 2 {
		variant = parts[2]
	}
	return os, arch, variant
}

func normArch(a string) string {
	switch a = strings.ToLower(a); a {
	case "x86_64", "x86-64":
		return "amd64"
	case "aarch64":
		return "arm64"
	}
	return a
}

// CappedBuffer is an io.Writer that keeps the first Max bytes written and
// silently discards the rest while still reporting a full write, so a reader
// can be drained to EOF without holding unbounded output.
type CappedBuffer struct {
	Max int
	buf []byte
	// Truncated is set once anything was discarded.
	Truncated bool
}

// Write keeps what fits under Max and drops the remainder.
func (b *CappedBuffer) Write(p []byte) (int, error) {
	if room := b.Max - len(b.buf); room > 0 {
		if len(p) <= room {
			b.buf = append(b.buf, p...)
			return len(p), nil
		}
		b.buf = append(b.buf, p[:room]...)
	}
	b.Truncated = true
	return len(p), nil
}

// String returns the kept bytes.
func (b *CappedBuffer) String() string { return string(b.buf) }
