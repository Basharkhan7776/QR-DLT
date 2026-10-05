#!/usr/bin/env bash
set -euo pipefail

# CPU Profiling and Flamegraph Generation Script
# Profiles memory bandwidth, cache misses, and CPU hotspots during batch verification

SCHEME="${1:-falcon512}"
TX_COUNT="${2:-2000}"
OUTPUT_SVG="flamegraph_${SCHEME}_${TX_COUNT}tx.svg"

echo "============================================================"
echo "  QR-DLT CPU & Memory Flamegraph Profiler                   "
echo "============================================================"
echo "  Scheme:       $SCHEME"
echo "  Batch Size:   $TX_COUNT transactions"
echo "  Output File:  $OUTPUT_SVG"
echo "============================================================"

if ! command -v cargo-flamegraph >/dev/null 2>&1; then
    echo "cargo-flamegraph not found. Installing..."
    cargo install flamegraph
fi

# Run flamegraph profiling against the bench-block subcommand
echo "Running profile under native CPU flags..."
RUSTFLAGS="-C target-cpu=native" cargo flamegraph \
    --bin qr-dlt-node \
    --output "$OUTPUT_SVG" \
    -- bench-block --scheme "$SCHEME" --tx-count "$TX_COUNT"

echo "Flamegraph saved to: $OUTPUT_SVG"
