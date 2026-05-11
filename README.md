# TrendAI Sensor

A Kubernetes DaemonSet that captures network traffic on every node, filters
out noise in-kernel, and forwards relevant packets to the TrendAI NDR
appliance over VXLAN. One pod per node; no sidecar required.

## Requirements

- Kubernetes 1.24+
- Helm 3
- TrendAI NDR appliance reachable from the nodes (or deploy in parked mode first)
- Linux kernel ≥ 4.15 (TC-BPF fast path requires ≥ 5.8)

## Kernel matrix

| Kernel | Capture path |
|--------|-------------|
| ≥ 5.8 with clsact + ringbuf | TC-BPF (default) |
| 4.15 – 5.7 | AF\_PACKET + cBPF fallback |
| < 4.15 | Not supported |

Auto-selected at startup. Override with `sensor.captureMode`.

## Install

Create an `overrides.yaml` with your cluster-specific settings:

```yaml
# overrides.yaml
sensor:
  ndrAddr: 10.0.0.5     # NDR appliance IP; leave empty for parked mode
  vni: "0x0a0b0c"       # VXLAN VNI — "0" is fine for single-tenant
prometheus:
  enabled: true         # expose /metrics and add scrape annotations
```

Then install from the release tarball:

```bash
helm install \
  --values overrides.yaml \
  --namespace trendai-sensor --create-namespace \
  trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.9/trendai-sensor-0.1.9.tgz
```

Without Helm:

```bash
helm template trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.9/trendai-sensor-0.1.9.tgz \
  --values overrides.yaml \
  --namespace trendai-sensor | kubectl apply -f -
```

## Upgrade

```bash
helm upgrade trendai-sensor \
  --values overrides.yaml \
  --namespace trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.9/trendai-sensor-0.1.9.tgz
```

The DaemonSet uses `RollingUpdate` with `maxUnavailable: 1`, so one node
at a time is updated. Capture is interrupted only on the node being
upgraded.

## Uninstall

```bash
helm uninstall trendai-sensor --namespace trendai-sensor
```

BPF programs are detached and AF\_PACKET sockets are closed automatically
when the pod exits. No kernel-level cleanup is required after uninstall.

## Configuration

All `sensor.*` values become environment variables on the container via a
ConfigMap. Set them in your `overrides.yaml`.

| Key | Default | Description |
|-----|---------|-------------|
| `sensor.ndrAddr` | _(empty)_ | NDR appliance IP. Empty = parked mode (see below). |
| `sensor.vni` | `"0"` | VXLAN Network Identifier (hex string). |
| `sensor.ndrMtu` | `1500` | MTU of the link to the NDR appliance. Frames whose inner payload + 50 B VXLAN overhead would exceed this are dropped and counted. |
| `sensor.captureMode` | `"auto"` | Capture backend: `auto`, `tcbpf`, or `afpacket`. |
| `sensor.captureIntraNode` | `false` | Capture pod-to-pod traffic on the same node. See [Intra-node capture](#intra-node-capture). |
| `sensor.logLevel` | `"info"` | Log verbosity: `debug`, `info`, `warn`, `error`. |
| `sensor.metricsAddr` | `":9090"` | Prometheus endpoint (only active when `prometheus.enabled=true`). |
| `sensor.healthAddr` | `":8080"` | Liveness (`/healthz`) and readiness (`/readyz`) probes. |

### MTU recommendations by cloud

| Cloud | Recommended `sensor.ndrMtu` |
|-------|-----------------------------|
| AWS (EKS, jumbo enabled) | `9001` |
| AWS (standard) | `1500` |
| Azure (AKS) | `1500` |
| GCP (GKE, default VPC) | `1460` |
| On-prem with jumbo path | `9000` |

## Parked mode

Deploying without `sensor.ndrAddr` is a valid configuration. In parked
mode the sensor:

- passes `/healthz` and `/readyz`,
- emits `sensor_info{ndr_configured="false"}` when Prometheus is enabled,
- logs a startup warning and a reminder every 10 s,
- **attaches no BPF programs, opens no capture sockets, and forwards no traffic.**

Set `sensor.ndrAddr` and restart the pod to start capture. Use parked
mode to validate RBAC, scheduling, and image pull on a cluster before
the NDR appliance is provisioned.

## Intra-node capture

By default the sensor captures traffic on the primary node NIC (`eth0`),
which does not see packets exchanged between two pods on the same node —
those are switched inside the kernel via CNI veth pairs.

Set `sensor.captureIntraNode: true` to attach to pod-veth interfaces
instead. When enabled, the sensor skips `eth0` entirely and listens on
each pod's host-side veth. A netlink watcher attaches new interfaces as
pods start and detaches them when pods stop — no sensor restart required.

### Supported CNIs

| Interface prefix | CNI | Cloud |
|-----------------|-----|-------|
| `eni*` | aws-vpc-cni | EKS |
| `azv*` | Azure CNI | AKS |
| `veth*` | kubenet / generic | GKE, bare Kubernetes |
| `cali*` | Calico (non-eBPF datapath) | Any |

> **Cilium is not supported.** Cilium's eBPF datapath redirects packets
> before they traverse the veth pair, so veth-level capture misses most
> traffic. If you need intra-node capture on Cilium, open an issue.

### How to enable

Add to your `overrides.yaml`:

```yaml
sensor:
  ndrAddr: 10.0.0.5
  captureIntraNode: true
```

Then upgrade the release:

```bash
helm upgrade trendai-sensor \
  --values overrides.yaml \
  --namespace trendai-sensor \
  https://github.com/felipecosta09/trendai-sensor/releases/download/v0.1.9/trendai-sensor-0.1.9.tgz
```

Sensor logs will show `"pod veth appeared, attaching"` and `"pod veth
removed, detaching"` as pods start and stop.

## Observability

### Stdout (always on)

Every 10 seconds the sensor logs a `tick` line:

```json
{"level":"INFO","msg":"tick","pps_in":120,"pps_out":87,"mbps_out":0,"kernel_drops":0,"mtu_exceeded":0,"send_errors":0}
```

`pps_in` / `pps_out` are per-second averages over the interval.
`kernel_drops` is a cumulative count of frames the kernel dropped before
userspace could read them (ring buffer full on TC-BPF, or socket buffer
overflow on AF\_PACKET).

### Prometheus

Set `prometheus.enabled: true` to start the `/metrics` HTTP server on
`<node-ip>:9090` and add `prometheus.io/scrape` pod annotations.

Useful metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `sensor_packets_captured_total` | counter | Packets read by the sensor, by iface and direction |
| `sensor_packets_forwarded_total` | counter | Packets successfully forwarded to the NDR |
| `sensor_packets_dropped_kernel_total` | counter | Kernel-level drops (ring buffer / socket overflow) |
| `sensor_packets_dropped_filter_total` | counter | In-kernel filter drops, by reason |
| `sensor_mtu_exceeded_total` | counter | Frames dropped because inner + overhead > NDR MTU |
| `sensor_send_errors_total` | counter | VXLAN send failures |
| `sensor_info` | gauge | Always 1; labels: `version`, `node`, `mode`, `ndr_configured` |

Useful alerts:

```yaml
# A node's sensor is running but not forwarding to NDR
- alert: SensorParked
  expr: max(sensor_info{ndr_configured="false"}) == 1

# Ring buffer is full — sensor is CPU- or bandwidth-bound
- alert: SensorKernelDrops
  expr: rate(sensor_packets_dropped_kernel_total[5m]) > 0

# Rolling upgrade stalled
- alert: SensorVersionSkew
  expr: count(group by (version) (sensor_info)) > 1
  for: 10m
```

### ServiceMonitor (prometheus-operator)

```yaml
prometheus:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
    labels:
      release: kube-prometheus-stack   # match your Prometheus instance selector
```

## Performance

Measured on a 2-node EKS cluster (t3.medium, Amazon Linux 2023, kernel 6.1,
TC-BPF path), light production-style traffic:

- **~1 m CPU / ~10 Mi RAM per pod** — well within the 50 m CPU and 64 Mi
  memory requests.
- **Memory is constant per node** — footprint does not grow with pod count.
  CPU scales with observed packet rate.
- **67–76 % of inspected traffic is filtered in-kernel** (IMDS, DNS, VXLAN
  self-loopback, Kubernetes plumbing) before reaching userspace.
- **Rule of thumb: ~0.05 m CPU per observed PPS.** The 50 m request covers
  roughly 250 pods/node of chatty workload.

For the iperf3-driven stress harness and raw counter tables see
[`benchmarks/README.md`](benchmarks/README.md).

## License

MIT — see [LICENSE](LICENSE).
