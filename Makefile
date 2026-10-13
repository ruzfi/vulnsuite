VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -s -w -X github.com/ruzfi/vulnsuite/internal/cli.Version=$(VERSION) \
           -X github.com/ruzfi/vulnsuite/internal/cli.Commit=$(COMMIT) \
           -X github.com/ruzfi/vulnsuite/internal/cli.Date=$(DATE)

.PHONY: build install test e2e lint fmt validate-templates clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/vulnsuite ./cmd/vulnsuite

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/vulnsuite

test:
	go test ./...

e2e:
	VULNSUITE_E2E=1 go test -count=1 -v ./internal/e2e/

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run make fmt" && exit 1)
	go vet ./...

fmt:
	gofmt -w .

# Validate a templates checkout with the freshly built binary.
validate-templates: build
	./bin/vulnsuite -templates $${VULNSUITE_TEMPLATES:-$$HOME/vulnsuite-templates} validate -allow-unpinned

clean:
	rm -rf bin
