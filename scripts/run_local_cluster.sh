#!/usr/bin/env bash
set -euo pipefail

# QR-DLT 4-Node Local Cluster Orchestrator
# Spawns 4 validating nodes on localhost with isolated data directories

CLUSTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_BASE="$CLUSTER_DIR/data/cluster"
NODE_BIN="$CLUSTER_DIR/target/debug/qr-dlt-node"

echo "============================================================"
echo "  Starting Quantum-Resilient Distributed Ledger (QR-DLT)   "
echo "  4-Node Local Consensus Devnet                            "
echo "============================================================"

# Compile binary if not present
if [ ! -f "$NODE_BIN" ]; then
    echo "Building qr-dlt-node binary..."
    cargo build -p qr-dlt-node
fi

# Clean previous state
rm -rf "$DATA_BASE"
mkdir -p "$DATA_BASE/node1" "$DATA_BASE/node2" "$DATA_BASE/node3" "$DATA_BASE/node4"

PIDS=()

cleanup() {
    echo ""
    echo "Shutting down QR-DLT cluster nodes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "All nodes stopped."
}

trap cleanup SIGINT SIGTERM EXIT

# Node 1 (Bootstrap Node, Ed25519)
echo "Launching Node 1 on 127.0.0.1:8001 (Ed25519)..."
"$NODE_BIN" run \
    --bind-addr "127.0.0.1:8001" \
    --db-path "$DATA_BASE/node1" \
    --validator-scheme ed25519 \
    > "$DATA_BASE/node1/node.log" 2>&1 &
PIDS+=($!)
sleep 1

# Node 2 (Falcon-512)
echo "Launching Node 2 on 127.0.0.1:8002 (Falcon-512)..."
"$NODE_BIN" run \
    --bind-addr "127.0.0.1:8002" \
    --peers "127.0.0.1:8001" \
    --db-path "$DATA_BASE/node2" \
    --validator-scheme falcon512 \
    > "$DATA_BASE/node2/node.log" 2>&1 &
PIDS+=($!)
sleep 0.5

# Node 3 (ML-DSA-44)
echo "Launching Node 3 on 127.0.0.1:8003 (ML-DSA-44)..."
"$NODE_BIN" run \
    --bind-addr "127.0.0.1:8003" \
    --peers "127.0.0.1:8001,127.0.0.1:8002" \
    --db-path "$DATA_BASE/node3" \
    --validator-scheme ml-dsa44 \
    > "$DATA_BASE/node3/node.log" 2>&1 &
PIDS+=($!)
sleep 0.5

# Node 4 (Pruned Mode, Falcon-512)
echo "Launching Node 4 on 127.0.0.1:8004 (Falcon-512, Pruned Mode)..."
"$NODE_BIN" run \
    --bind-addr "127.0.0.1:8004" \
    --peers "127.0.0.1:8001,127.0.0.1:8003" \
    --db-path "$DATA_BASE/node4" \
    --validator-scheme falcon512 \
    --prune-depth 50 \
    > "$DATA_BASE/node4/node.log" 2>&1 &
PIDS+=($!)

echo "============================================================"
echo "  All 4 Nodes Active:"
echo "    Node 1: 127.0.0.1:8001 (PID ${PIDS[0]})"
echo "    Node 2: 127.0.0.1:8002 (PID ${PIDS[1]})"
echo "    Node 3: 127.0.0.1:8003 (PID ${PIDS[2]})"
echo "    Node 4: 127.0.0.1:8004 (PID ${PIDS[3]})"
echo "  Logs: $DATA_BASE/node*/node.log"
echo "============================================================"

# If running with --duration N, exit after N seconds
if [ "${1:-}" = "--duration" ] && [ -n "${2:-}" ]; then
    echo "Running cluster for $2 seconds..."
    sleep "$2"
    echo "Duration reached."
else
    echo "Press Ctrl+C to stop cluster."
    wait
fi
