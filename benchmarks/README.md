# Benchmarks

Harness for measuring sensor CPU, memory, and drop rate under load, plus a
record of the observed footprint from real clusters. Kernel version, NIC
driver, and CPU generation all affect the numbers — always re-measure
before publishing.

## Observed footprint (EKS, light load)

Reference datapoint from a 2-node EKS 1.30 cluster (`t3.medium`, AL2023 /
kernel 6.1, TC-BPF fast path), sensor **v0.1.5**, 43 min of light
production-style traffic (2× nginx + 1× traffic-gen hitting a 15-URI
round-robin every 5 s ≈ 12 req/min).

### Per sensor pod

| Resource | Observed | Chart request | Chart limit | Headroom vs. limit |
|---|---|---|---|---|
| CPU | **1 m** | 50 m | 300 m | 300× |
| Memory | **8–10 Mi** | 64 Mi | 256 Mi | 25× |
| Forwarded packets | 4.7–5.0 pps | — | — | — |
| Forwarded bandwidth (inner) | 7 kbps | — | — | — |
| Outer bandwidth (incl. 50 B VXLAN) | ~9 kbps | — | ~500 Mbps sustained NIC | 55,000× |
| Kernel ring-buffer drops | 0 | — | — | — |

### Filter effectiveness

Fraction of observed traffic dropped before leaving the node, by reason:

| Reason | Typical share | What it catches |
|---|---|---|
| `vxlan_self` | 30–40 % | The sensor's own forwarded frames looping back on the host NIC |
| `k8s_noise` | 10–30 % | SSH, kubelet, kube-proxy, CoreDNS ready, sensor's own probes, NTP |
| `metadata` | 20–30 % | Cloud IMDS (`169.254.169.254`) — request and response |
| `dns` | 5–10 % | Port 53 UDP/TCP (both directions) |
| `non_ipv4` | <1 % | ARP, IPv6, STP |
| `truncated` | 0 % | Malformed / short frames |

**End-to-end suppression: 67–76 %** of packets the BPF program inspects are
dropped in-kernel. The NDR only sees the remainder.

### Per-watched-pod amortization

Cluster had 5 workload pods co-located with each sensor. Amortizing the
sensor's cost across the pods it watches:

| Resource | Per sensor pod | Per watched pod (5/node) |
|---|---|---|
| CPU | 1 m | **0.2 m** |
| Memory | 8–10 Mi | **1.6–2.0 Mi** |
| Forwarded PPS | 4.7–5.0 pps | **~1.0 pps** |
| Forwarded bandwidth | 7 kbps | **~1.4 kbps** |

> Traffic-gen was deliberately chatty (~12 req/min) so these are
> upper-bound amortized costs for a pod with steady east-west traffic,
> not a quiet idle pod.

## Scaling rules

Three distinct cost axes; only one scales with load:

| Axis | Scales with | Ceiling |
|---|---|---|
| Fixed overhead (binary, BPF maps, health/metrics HTTP servers) | nothing — constant | ~4–6 Mi RAM floor per pod |
| BPF ring buffer | nothing — preallocated | 4 MiB (~22 k avg frames) |
| Per-packet CPU (filter eval → ringbuf push → userspace read → VXLAN encap → `sendto`) | **observed PPS** | ~20 k pps before saturating 1 vCPU (extrapolated) |

Memory does **not** grow with pod count. Adding 100 pods to a node adds
~0 MiB to the sensor's footprint. CPU is the only scaling axis.

**Rule of thumb: ≈ 0.05 m CPU per observed PPS** at the current filter
complexity. Linear projection (order-of-magnitude, since `kubectl top`
bottoms out at 1 m):

| Observed PPS/node | Projected sensor CPU | % of 1 vCPU |
|---|---|---|
| 20 (reference) | 1 m | 0.1 % |
| 200 | 10 m | 1 % |
| 2,000 | 100 m | 10 % |
| 20,000 | ~1 vCPU | 100 % — filter saturates |

Projected against realistic pod densities (assuming ~1 observed pps per
chatty pod):

| Pods/node | Sensor CPU | % of 50 m request | % of 300 m limit |
|---|---|---|---|
| 10 | ~2 m | 4 % | 0.7 % |
| 30 (typical EKS density) | ~6 m | 12 % | 2 % |
| 100 | ~20 m | 40 % | 7 % |
| 250 (high-density) | ~50 m | 100 % of request | 17 % of limit |

The 50 m CPU request is sized for **~250 pods/node of chatty workload**.
Below that density the sensor consumes 2–12 % of its limit.

Binding constraint at scale is **CPU** — not NIC (55,000× headroom at
reference load), not memory (constant), not ring buffer (0 drops at
reference load).

## Stress test (iperf3 harness)

Use this to validate the rule of thumb above under heavy synthetic load,
or to re-measure on different hardware.

### Setup

1. Kubernetes node with ≥ 2 vCPU, kernel ≥ 5.8 for the TC-BPF path.
2. Deploy the sensor (`../deploy/`) on the target node.
3. NDR appliance reachable at the configured `SENSOR` IP, or replace the
   forwarder target with a local `tcpdump -i any -w /dev/null udp port 4789`
   to sink traffic without skewing numbers.

## Traffic profile

`load.sh` uses `iperf3` to generate:

- 100 Mbps TCP (~8 kpps avg, 1500 B frames)
- 500 Mbps TCP (~40 kpps)
- 1 Gbps TCP (~80 kpps)
- 500 Mbps UDP (~42 kpps at 1500 B, or ~340 kpps at 200 B for small-packet stress)

## Measurement

`collect.sh` scrapes `kubectl top pod` every 5 s for 2 minutes, takes the
median, and gates on `sensor_packets_dropped_kernel_total == 0`:

```sh
# in one shell: start load
SERVER=10.0.0.50 ./load.sh

# in another: for each profile, run collect.sh labeled with the profile name
POD=$(kubectl get pod -n trendai-sensor -l app=trendai-sensor -o name | head -1 | cut -d/ -f2)
POD=$POD ./collect.sh 100mbps-tcp
POD=$POD ./collect.sh 500mbps-tcp
POD=$POD ./collect.sh 1gbps-tcp
POD=$POD ./collect.sh 500mbps-udp-small
```

The script prints median CPU (mCPU) and memory (MiB) and dumps raw samples to
`results/<label>/sensor.top`. Paste medians into the table below.

| Profile | CPU (mCPU) | Mem (MiB) | Kernel drops |
|---|---|---|---|
| 100 Mbps TCP | _run_ | _run_ | _run_ |
| 500 Mbps TCP | _run_ | _run_ | _run_ |
| 1 Gbps TCP   | _run_ | _run_ | _run_ |
| 500 Mbps small UDP | _run_ | _run_ | _run_ |

> Numbers must be collected on real hardware. Do not publish synthetic estimates.

## Correctness checks (run once)

- Generate DNS traffic from the node: `dig @8.8.8.8 example.com`. Confirm
  `sensor_packets_dropped_filter_total{reason="dns"}` increments and no DNS
  frames reach the NDR.
- Generate traffic to the cloud metadata service: `curl -m1 http://169.254.169.254/`
  on AWS/GCP. Confirm `sensor_packets_dropped_filter_total{reason="metadata"}`
  increments and no metadata frames reach the NDR.
- Confirm the sensor doesn't loop on its own output:
  `sensor_packets_dropped_filter_total{reason="vxlan_self"}` should increment
  in proportion to forwarded traffic.
