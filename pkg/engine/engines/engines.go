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

// Resolve returns the engine kind New would use for kind ("" means
// $VULNSUITE_ENGINE, then sdk), or an error naming an unknown one.
func Resolve(kind string) (string, error) {
	from := "-engine"
	if kind == "" {
		kind, from = os.Getenv(Env), "$"+Env
	}
	switch kind {
	case "", SDK, "moby":
		return SDK, nil
	case API, "docker":
		return API, nil
	}
	return "", fmt.Errorf("unknown engine %q from %s (sdk or api)", kind, from)
}

// New constructs the engine client for kind ("" means $VULNSUITE_ENGINE, then sdk)
// against host ("" means $DOCKER_HOST or the local socket).
func New(kind, host string) (engine.Engine, error) {
	kind, err := Resolve(kind)
	if err != nil {
		return nil, err
	}
	if kind == API {
		return docker.New(host)
	}
	return moby.New(host)
}
