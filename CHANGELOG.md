## v0.1.7 — 2026-05-08

### Breaking

- **`SENSOR` env renamed to `SENSOR_NDR_ADDR`** and the placeholder default
  `10.0.0.1` was removed. The old name was a generic stub; the old default
  let a misconfigured chart silently forward captured frames to whatever
  RFC1918 host happened to live at `10.0.0.1`. No alias — existing
  overrides.yaml files using `SENSOR` will need an update.
- **Prometheus exposure is now opt-in.** New Helm value `prometheus.enabled`
  (default `false`) gates the `/metrics` HTTP server, the scrape
  annotations, and the metrics Service port. `serviceMonitor.enabled`
  additionally requires `prometheus.enabled=true`. When disabled, the 10-s
  `tick` stdout log is still emitted so operators without Prometheus retain
  basic health visibility.

### Fixed

- AF_PACKET fallback no longer hangs for the full `terminationGracePeriodSeconds`
  on SIGTERM. `readLoop` blocks in `unix.Read` with no deadline; a new
  ctx-watcher goroutine closes the fds on cancel and lets the in-flight
  read return `EBADF` (mirrors the TC-BPF fix from v0.1.6). Impact was
  latent on TC-BPF-capable kernels (5.8+) but day-one visible on any
  cluster using the AF_PACKET path — 10-s pod exits, 1024-packet buffer
  lost to SIGKILL.
- Double-capture on modern CNIs. `skipPrefixes` extended with `azv` (Azure
  CNI), `eni` (AWS VPC CNI routed / prefix-delegation), `lxc` (Cilium),
  `kube-ipvs0` (kube-proxy IPVS dummy), and `dummy`. Pre-v0.1.7 a sensor
  on those clusters attached capture sockets to both the primary NIC and
  every per-pod interface — each frame was read, forwarded, and counted
  twice.

### Added

- **Parked mode.** Deploying with `sensor.ndrAddr=""` (or unsetting
  `SENSOR_NDR_ADDR`) is now a first-class configuration: the pod passes
  health probes, logs a reminder every 10 s, and does not attach any BPF
  programs, open any AF_PACKET sockets, or read any packets. Idle pod.
  Useful for validating RBAC / scheduling before an NDR endpoint exists.
  Setting `sensor.ndrAddr` and restarting the pod starts real capture.
- `sensor_info{version,node,mode,ndr_configured}` gauge. `version` comes
  from `-ldflags -X main.version` (Makefile + Dockerfile pass `VERSION`);
  `node` from the `NODE_NAME` env wired via downward API. Enables
  `group by (version) (sensor_info)` for rolling-upgrade tracking and
  `max(sensor_info{ndr_configured="false"}) == 1` for misconfig alerts.

### Performance

- `forward.Send` no longer allocates per frame. Switched from
  `make([]byte, 8+len(frame))` per call to a single preallocated
  `innerMax+8` buffer on the `Forwarder` (caller is single-threaded).
  `TestSendZeroAllocs` guards the invariant. At 10k pps × 1.5 KB this
  drops ~15 MB/s of transient allocations.

### Docs

- New "Observability" and "Parked mode" sections in README covering the
  Prometheus toggle and the unconfigured-NDR behavior. Install-URL drift
  (`v0.1.5` → `v0.1.7`) cleaned up.

---

## v0.1.6 — 2026-04

- Fixed TC-BPF shutdown hang on idle nodes (ctx cancel did not unblock the
  ringbuf reader).
- Added golangci-lint + helm-lint gates to CI and resolved the findings
  they surfaced.
- Bounds-checked cBPF `JumpIf` skip offsets so an oversized port list
  fails to assemble loudly instead of silently truncating.
- Wrapped `capture.Pick` errors with `ErrUnsupported` for stable callers.

## v0.1.5 — 2026-03

- Filtered CoreDNS `/ready` probes on port 8181.
- Matched metadata IP on source *or* destination so IMDS responses don't
  leak past the filter.
- Filtered k8s plumbing noise (kubelet, kube-proxy healthz, sensor's own
  health/metrics ports); aligned release `appVersion` with image tag.

## v0.1.4 — 2026-02

- Promoted the Helm chart to the repo root.
- Distributed the chart as a GitHub release `.tgz` asset.

## Earlier

See `git log` — initial commit, CI/release workflow bring-up, Dockerfile
`GO_VERSION=1.23` bump, MIT LICENSE + Prometheus Operator integration.
