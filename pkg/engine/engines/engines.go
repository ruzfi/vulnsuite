// Package engines picks a container engine client by name.
package engines

import (
	"fmt"
	"os"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/docker"
	"github.com/ruzfi/vulnsuite/pkg/engine/moby"
)

// Kinds.
const (
	SDK = "sdk" // github.com/moby/moby/client, the official SDK (default)
	API = "api" // the built-in, dependency-free Engine API client
	Env = "VULNSUITE_ENGINE"
)

// New constructs the engine client for kind ("" means $VULNSUITE_ENGINE, then sdk)
// against host ("" means $DOCKER_HOST or the local socket).
func New(kind, host string) (engine.Engine, error) {
	if kind == "" {
		kind = os.Getenv(Env)
	}
	switch kind {
	case "", SDK, "moby":
		return moby.New(host)
	case API, "docker":
		return docker.New(host)
	}
	return nil, fmt.Errorf("unknown engine %q (sdk or api)", kind)
}
