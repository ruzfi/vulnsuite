// Package engine abstracts the container engine vulnsuite builds and runs
// targets on. The default implementation (engine/docker) speaks the Docker
// Engine API directly over the socket; anything that implements Engine can be
// swapped in.
package engine

import (
	"context"
	"io"
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
	// Ports maps "containerPort/proto" -> host port (first binding).
	Ports map[string]int
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

// HostInfo describes the daemon's platform.
type HostInfo struct {
	OS   string // linux, windows
	Arch string // amd64, arm64, ...
}

// Engine is the container backend.
type Engine interface {
	// Ping checks connectivity and returns the engine's version string.
	Ping(ctx context.Context) (string, error)
	// Info returns the daemon's OS/arch, for preflighting target requirements.
	Info(ctx context.Context) (HostInfo, error)

	ImageExists(ctx context.Context, ref string) (bool, error)
	// ImagePull pulls ref, streaming progress text to out (may be nil).
	ImagePull(ctx context.Context, ref string, out io.Writer) error
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

	// NetworkEnsure creates the network if it does not exist and returns its id.
	NetworkEnsure(ctx context.Context, spec NetworkSpec) (string, error)
	NetworkExists(ctx context.Context, name string) (bool, error)
	NetworkRemove(ctx context.Context, name string) error
}
