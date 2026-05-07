# Benchmarks

Harness for measuring sensor CPU, memory, and drop rate under load. Run on a
real Kubernetes node — kernel version, NIC driver, and CPU generation all
affect the numbers.

## Setup

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
