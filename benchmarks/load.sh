#!/usr/bin/env bash
# Generate traffic against an iperf3 server for the benchmark table.
# Usage: SERVER=10.0.0.50 ./load.sh
set -euo pipefail

SERVER="${SERVER:?set SERVER=<iperf3 server IP>}"
DURATION="${DURATION:-120}"

run() {
    local label="$1"; shift
    echo "=== $label ==="
    iperf3 -c "$SERVER" -t "$DURATION" "$@"
    echo
}

run "100 Mbps TCP"        -b 100M
run "500 Mbps TCP"        -b 500M
run "1 Gbps TCP"          -b 1G
run "500 Mbps UDP 1500B"  -u -b 500M -l 1448
run "500 Mbps UDP 200B"   -u -b 500M -l 200
