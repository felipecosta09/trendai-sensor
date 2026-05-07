# TrendAI Sensor

Kubernetes node-level network sensor. Captures traffic via TC-BPF (eBPF) with
an AF_PACKET fallback, filters noise in the kernel, and forwards relevant
packets to the TrendAI NDR appliance over VXLAN.

## Features

- **In-kernel filtering.** TC-BPF on clsact ingress + egress, or a cBPF
  program attached to an AF_PACKET socket — DNS, metadata-service, and the
  sensor's own VXLAN traffic are dropped before userspace sees them.
- **Zero-copy delivery on the TC-BPF path** via a 4 MiB BPF ring buffer. The
  AF_PACKET fallback uses blocking `read(2)` — correct but not zero-copy; it
  exists to keep the sensor working on kernels that pre-date `clsact`/ringbuf.
- **Prometheus metrics** including kernel drop counters, per-reason filter
  drops, MTU-exceeded counters, and send errors.
- **`/healthz` + `/readyz`** for kubelet liveness/readiness probes.
- **No `privileged: true`** — runs with `NET_RAW NET_ADMIN BPF PERFMON`,
  `readOnlyRootFilesystem: true`, and `allowPrivilegeEscalation: false`.
- **Structured JSON logs** (slog), with per-10 s aggregate tick lines.
- **MTU-aware forwarding.** Frames whose inner + VXLAN overhead would exceed
  the NDR link MTU are dropped and counted.

## Kernel matrix

| Kernel | Path |
|---|---|
| ≥ 5.8 with ringbuf + clsact | TC-BPF (primary) |
| 4.15 – 5.7 | AF_PACKET + cBPF fallback |
| < 4.15 | Unsupported |

Auto-detected at startup; override with `CAPTURE_MODE=tcbpf` or `afpacket`.

## Configuration

| Env | Default | Description |
|---|---|---|
| `SENSOR` | `10.0.0.1` | NDR appliance IP |
| `VNI` | `0` | VXLAN VNI (hex) |
| `NDR_MTU` | `1500` | NDR link MTU; inner max = NDR_MTU − 50 |
| `CAPTURE_MODE` | `auto` | `auto`, `tcbpf`, or `afpacket` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `METRICS_ADDR` | `:9090` | Prometheus exposition |
| `HEALTH_ADDR` | `:8080` | Health probes |

In Kubernetes these are rendered from the `sensor.*` keys in
[values.yaml](values.yaml) into a ConfigMap mounted via `envFrom`; locally
copy `.env.example` to `.env`.

## Build

```
make bpf       # compile BPF program via bpf2go (requires clang + llvm + libbpf-dev)
make build     # static Linux binary
make docker    # distroless image (~20 MB)
make test      # unit tests
make lint      # go vet + golangci-lint
```

## Install

The chart lives at the repo root and is shipped on every tagged release.
Images are published to GHCR.

Drop your cluster-specific settings into `overrides.yaml` — you only need to
list the values you're changing, everything else falls back to the chart
defaults in [values.yaml](values.yaml):

```yaml
# overrides.yaml
sensor:
  ndrAddr: 10.0.0.5
  vni: "0x0a0b0c"
prometheus:
  serviceMonitor:
    enabled: true   # if prometheus-operator is installed
```

Then install from the packaged chart attached to the GitHub release:

```
helm install \
  --values overrides.yaml \
  --namespace trendai-sensor --create-namespace \
  trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.5/trendai-sensor-0.1.5.tgz
```

The packaged tgz is smaller than the source archive and is the canonical
install artifact — every tagged release uploads it automatically. Check
[the releases page](https://github.com/felipecosta09/trendai-sensor/releases/latest)
for the current tag.

Without Helm — render the chart and pipe to `kubectl`:

```
helm template trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.5/trendai-sensor-0.1.5.tgz \
  --values overrides.yaml \
  --namespace trendai-sensor | kubectl apply -f -
```

Without prometheus-operator, scrape `<node-ip>:9090` directly (the sensor runs
on `hostNetwork`; the default `podAnnotations` already carry the
`prometheus.io/scrape` metadata).

## Benchmarks

See `benchmarks/README.md` for the load generator and collection harness.

## License

MIT — see [LICENSE](LICENSE).
