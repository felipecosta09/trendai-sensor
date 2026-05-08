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
- **Optional Prometheus metrics** (`prometheus.enabled`, default off)
  including kernel drop counters, per-reason filter drops, MTU-exceeded
  counters, send errors, and a `sensor_info{version,node,mode,ndr_configured}`
  gauge for rolling-upgrade and misconfig alerting. With Prometheus off,
  the same numbers surface as 10-s `tick` lines in stdout.
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
| `SENSOR_NDR_ADDR` | _(empty)_ | NDR appliance IP. Empty = parked mode (see below). |
| `VNI` | `0` | VXLAN VNI (hex) |
| `NDR_MTU` | `1500` | NDR link MTU; inner max = NDR_MTU − 50 |
| `CAPTURE_MODE` | `auto` | `auto`, `tcbpf`, or `afpacket` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `METRICS_ADDR` | `:9090` | Prometheus exposition (only when `prometheus.enabled=true`) |
| `HEALTH_ADDR` | `:8080` | Health probes |

> **Breaking in v0.1.7:** `SENSOR` was renamed to `SENSOR_NDR_ADDR` and the
> placeholder default `10.0.0.1` was removed. Unset = parked mode, not
> "forward to 10.0.0.1."

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
  ndrAddr: 10.0.0.5          # leave empty to deploy in parked mode
  vni: "0x0a0b0c"
prometheus:
  enabled: true              # expose /metrics + add scrape annotations
  serviceMonitor:
    enabled: true            # additionally requires prometheus-operator
```

Then install from the packaged chart attached to the GitHub release:

```
helm install \
  --values overrides.yaml \
  --namespace trendai-sensor --create-namespace \
  trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.7/trendai-sensor-0.1.7.tgz
```

The packaged tgz is smaller than the source archive and is the canonical
install artifact — every tagged release uploads it automatically. Check
[the releases page](https://github.com/felipecosta09/trendai-sensor/releases/latest)
for the current tag.

Without Helm — render the chart and pipe to `kubectl`:

```
helm template trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.7/trendai-sensor-0.1.7.tgz \
  --values overrides.yaml \
  --namespace trendai-sensor | kubectl apply -f -
```

## Observability

The sensor ships with Prometheus exposition **off by default** — many
environments don't run Prometheus, and a root-privileged pod exposing an
HTTP endpoint nobody scrapes is unnecessary attack surface.

**Stdout only** (default — `prometheus.enabled=false`):

- No `/metrics` HTTP server.
- No `prometheus.io/scrape` pod annotations, no metrics port on the Service.
- Health probes (`:8080`) still on.
- Every 10 s the sensor logs a `tick` line with `pps_in`, `pps_out`,
  `mbps_out`, `kernel_drops`, `mtu_exceeded`, `send_errors`. Enough for
  `kubectl logs` to spot regressions.

**Prometheus enabled** (`prometheus.enabled=true`):

- `/metrics` on `<node-ip>:9090` (hostNetwork). Scrape annotations are
  rendered automatically. Without prometheus-operator this is all you need.
- With prometheus-operator, additionally set `prometheus.serviceMonitor.enabled=true`.
- Useful alerts:
  - `max(sensor_info{ndr_configured="false"}) == 1` — a pod deployed
    without `sensor.ndrAddr` (see parked mode below).
  - `rate(sensor_packets_dropped_kernel_total[5m]) > 0` — ring buffer
    full; sensor is CPU- or bandwidth-bound.
  - `count(group by (version) (sensor_info)) > 1` for > 10 min — rolling
    upgrade got stuck.

## Parked mode

Deploying the chart without an NDR endpoint is a first-class configuration
rather than an error. Leave `sensor.ndrAddr` empty (or unset
`SENSOR_NDR_ADDR`) and the sensor:

- passes `/healthz` + `/readyz`,
- emits `sensor_info{ndr_configured="false"}` (when Prometheus is on),
- logs a startup warn + a reminder every 10 s,
- **does not attach any BPF programs, open any AF_PACKET sockets, or read
  any packets.** Idle pod — essentially the Go runtime only.

Set `sensor.ndrAddr` and the pod restarts; capture starts for real.
Useful for validating RBAC / scheduling / image pulls on the cluster side
before the NDR is provisioned, without silently forwarding captured frames
to a placeholder IP.

## Performance

Measured on a 2-node EKS cluster (t3.medium, AL2023 / kernel 6.1, TC-BPF
fast path), sensor v0.1.5, light production-style traffic:

- **~1 m CPU / ~10 Mi RAM per sensor pod** — 2 % of the chart's 50 m CPU
  request, 16 % of its 64 Mi memory request. 0 kernel drops.
- **Memory is constant per node** (dominated by the preallocated 4 MiB BPF
  ring buffer). Footprint does **not** grow with pod count; CPU is the only
  axis that scales with load.
- **Filter drops 67–76 % of inspected traffic** (IMDS metadata, k8s
  plumbing, DNS, VXLAN self-loopback) before it leaves the node, cutting
  both wire bandwidth and NDR ingestion.
- **VXLAN adds ~20 % byte overhead** per forwarded frame (50 B outer header
  on a typical small control-plane frame).
- Rule of thumb: **≈ 0.05 m CPU per observed PPS** at the current filter
  complexity. The 50 m CPU request is sized for ~250 pods/node of chatty
  workload; at typical 30–100 pod/node density the sensor uses 2–7 % of
  its 300 m limit.

For raw counters, per-watched-pod amortization, the scaling projection, and
the iperf3-driven stress harness, see [`benchmarks/README.md`](benchmarks/README.md).

## License

MIT — see [LICENSE](LICENSE).
