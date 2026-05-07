# syntax=docker/dockerfile:1.7

# Multi-arch build (linux/amd64, linux/arm64) via docker buildx.
# The builder stage always runs on the native BUILDPLATFORM (no QEMU for the Go
# compile), and Go cross-compiles to the requested TARGETARCH. BPF bytecode is
# endian-neutral (clang -target bpf emits bpfel on both x86_64 and aarch64), so
# the same filter_bpfel.o is loaded on both archs.

ARG GO_VERSION=1.22
ARG DEBIAN_RELEASE=bookworm

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${DEBIAN_RELEASE} AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# Compile the BPF program once on the build host. Output is checked against
# build so a stale committed _bpfel.o won't silently hide a broken .c.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    cd internal/capture && go generate ./...

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/sensor ./cmd/sensor

# distroless/static is ~2 MiB, has ca-certs and tzdata, no shell. Root by
# default — the pod spec drops all caps and adds only NET_RAW/NET_ADMIN/BPF/
# PERFMON, with allowPrivilegeEscalation=false and readOnlyRootFilesystem=true.
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /out/sensor /sensor

EXPOSE 8080 9090
ENTRYPOINT ["/sensor"]
