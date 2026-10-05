#!/usr/bin/env bash
set -euo pipefail

# WAN Latency and Packet Loss Emulation Script using Linux 'tc netem'
# Evaluates P2P block propagation across high-latency WAN links

INTERFACE="lo"
DELAY="100ms"
LOSS="0.5%"
CLEAR=false

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --delay D       Latency to inject (e.g. 50ms, 100ms, 200ms) [Default: 100ms]"
    echo "  --loss L        Packet loss percentage (e.g. 0.1%, 0.5%, 1%) [Default: 0.5%]"
    echo "  --interface I   Network interface to shape [Default: lo]"
    echo "  --clear         Remove traffic shaping rules and restore normal latency"
    echo "  --help          Display this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --delay)
            DELAY="$2"
            shift 2
            ;;
        --loss)
            LOSS="$2"
            shift 2
            ;;
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        --clear)
            CLEAR=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$CLEAR" = true ]; then
    echo "Clearing netem rules on $INTERFACE..."
    if command -v tc >/dev/null 2>&1; then
        sudo tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        echo "Traffic shaping rules removed from $INTERFACE."
    fi
    exit 0
fi

echo "============================================================"
echo "  QR-DLT WAN Latency Emulation                              "
echo "============================================================"
echo "  Target Interface: $INTERFACE"
echo "  Added Delay:      $DELAY"
echo "  Packet Loss:      $LOSS"
echo "============================================================"

if ! command -v tc >/dev/null 2>&1; then
    echo "Error: Linux 'tc' (iproute2) tool is not installed."
    exit 1
fi

# Reset existing qdisc
sudo tc qdisc del dev "$INTERFACE" root 2>/dev/null || true

# Add new netem qdisc
sudo tc qdisc add dev "$INTERFACE" root netem delay "$DELAY" loss "$LOSS"

echo "Latency shaping applied successfully to $INTERFACE."
echo "Current qdisc status:"
tc qdisc show dev "$INTERFACE"
echo ""
echo "To revert changes when tests conclude, run:"
echo "  sudo $0 --clear"
