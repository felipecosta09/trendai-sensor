#!/usr/bin/env bash
# Scrape CPU/memory from `kubectl top` + drop counters from /metrics, producing
# the numbers that go into README.md's performance table. Run this ON the node
# while load.sh is generating traffic.
#
# Usage:
#   NS=trendai-sensor POD=trendai-sensor-xxxx DURATION=120 ./collect.sh 100mbps-tcp

set -euo pipefail

LABEL="${1:-unlabeled}"
DURATION="${DURATION:-120}"
INTERVAL="${INTERVAL:-5}"
NS="${NS:-trendai-sensor}"
POD="${POD:?set POD=<daemonset pod name>}"

mkdir -p "results/$LABEL"
SAMPLES=$((DURATION / INTERVAL))

echo "collecting $SAMPLES samples every ${INTERVAL}s into results/$LABEL/"
for i in $(seq 1 "$SAMPLES"); do
    TS=$(date -u +%s)
    kubectl top pod -n "$NS" "$POD" --no-headers \
        | awk -v ts="$TS" '{print ts,$2,$3}' >> "results/$LABEL/sensor.top"
    sleep "$INTERVAL"
done

# Final drop counter snapshot for correctness gate.
kubectl exec -n "$NS" "$POD" -- wget -qO- http://localhost:9090/metrics \
    | grep -E '^sensor_packets_dropped_(kernel|filter)_total' \
    > "results/$LABEL/sensor.drops"

echo "median CPU (mCPU) and mem (MiB):"
awk '{gsub(/m$/,"",$2); gsub(/Mi$/,"",$3); print $2,$3}' "results/$LABEL/sensor.top" \
    | sort -n -k1 | awk '
        { cpu[NR]=$1; mem[NR]=$2 }
        END {
            n=NR; mid=int(n/2)+1;
            printf "  cpu=%s mCPU  mem=%s MiB\n", cpu[mid], mem[mid]
        }'

echo "kernel drops (should be 0 for a clean run):"
grep sensor_packets_dropped_kernel_total "results/$LABEL/sensor.drops" || true
