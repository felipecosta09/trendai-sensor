IMAGE        ?= ghcr.io/felipecosta09/trendai-sensor
TAG          ?= latest
CHART_DIR    ?= .
PLATFORMS    ?= linux/amd64,linux/arm64
# Host arch for local `make build` — detect with uname so `make build` on an
# M-series mac cross-compiles to darwin/arm64 stubs, while on a linux/amd64 CI
# runner it produces the real capture binary.
HOST_OS      := $(shell go env GOOS)
HOST_ARCH    := $(shell go env GOARCH)
TARGETOS     ?= linux
TARGETARCH   ?= $(HOST_ARCH)
# Version injected into sensor_info{version=...}. Release workflow overrides
# this to the git tag (e.g. v0.1.7); plain `make build` produces "dev".
VERSION      ?= dev

.PHONY: all bpf build test lint clean \
        docker docker-buildx docker-push \
        fmt vet golangci-lint \
        helm-lint helm-template helm-package

all: bpf build

# Compile bpf/filter.c -> internal/capture/sensorbpf_bpfel.{go,o}. Requires
# clang + libbpf-dev + linux-libc-dev on the host.
bpf:
	cd internal/capture && go generate ./...

# `go build` fails with an opaque `undefined: sensorBPFObjects` when the
# bpf2go outputs are missing (they're gitignored, since they're generated
# from bpf/filter.c via clang). Guard the user by requiring bpf to have run
# first, and print a clear message otherwise.
BPF_GENERATED := internal/capture/sensorbpf_bpfel.go
build: $(BPF_GENERATED)
	CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) \
		go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" \
		-o bin/sensor-$(TARGETOS)-$(TARGETARCH) ./cmd/sensor

$(BPF_GENERATED):
	@echo "error: BPF bindings missing — run 'make bpf' first"
	@echo "       (requires clang + libbpf-dev + linux-libc-dev)"
	@exit 1

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# golangci-lint runs the battery defined in .golangci.yml. Install with:
#   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not installed — see Makefile comment for install command"; exit 1; }
	golangci-lint run ./...

lint: vet golangci-lint

# Single-arch local build. Fast iteration.
docker:
	docker build -t $(IMAGE):$(TAG) .

# Multi-arch build + push. Requires `docker buildx create --use` first.
# Use this for the release image consumed by the DaemonSet.
docker-buildx:
	docker buildx build \
		--platform $(PLATFORMS) \
		-t $(IMAGE):$(TAG) \
		--push \
		.

# Alias kept for clarity in CI.
docker-push: docker-buildx

helm-lint:
	helm lint $(CHART_DIR)

# Render the chart with default values to stdout. Handy for `| kubectl apply -f -`.
helm-template:
	helm template trendai-sensor $(CHART_DIR)

# Package the chart as a .tgz. Release workflow does this with version from the git tag.
# .helmignore keeps the Go source + build artifacts out of the tarball.
helm-package:
	helm package $(CHART_DIR)

clean:
	rm -rf bin/ \
		internal/capture/sensorbpf_bpfel.go \
		internal/capture/sensorbpf_bpfel.o \
		internal/capture/sensorbpf_bpfeb.go \
		internal/capture/sensorbpf_bpfeb.o \
		trendai-sensor-*.tgz
