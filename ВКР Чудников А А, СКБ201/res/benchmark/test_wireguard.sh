#!/bin/bash
set -e

source "$(dirname "$0")/lib_benchmark.sh"

setup_vpn_impl() {
    echo -e "${GREEN}[Setup] Initializing Standard WireGuard...${NC}"

    modprobe wireguard || { echo -e "${RED}WireGuard module not found${NC}"; exit 1; }

    ip netns exec ns1 ip link add wg0 type wireguard
    ip netns exec ns1 ip addr add 192.168.1.1/24 dev wg0
    ip netns exec ns1 ip link set wg0 up

    ip netns exec ns2 ip link add wg0 type wireguard
    ip netns exec ns2 ip addr add 192.168.1.2/24 dev wg0
    ip netns exec ns2 ip link set wg0 up

    PRIV1=$(wg genkey)
    PUB1=$(echo "$PRIV1" | wg pubkey)
    PRIV2=$(wg genkey)
    PUB2=$(echo "$PRIV2" | wg pubkey)

    echo "$PRIV1" | ip netns exec ns1 wg set wg0 \
        private-key /dev/stdin \
        listen-port 51820 \
        peer "$PUB2" allowed-ips 192.168.1.0/24 endpoint 10.0.0.2:51821

    echo "$PRIV2" | ip netns exec ns2 wg set wg0 \
        private-key /dev/stdin \
        listen-port 51821 \
        peer "$PUB1" allowed-ips 192.168.1.0/24 endpoint 10.0.0.1:51820
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$(pwd)/testing/logs/wireguard_${TIMESTAMP}"
mkdir -p "$LOG_DIR"

cleanup_common
run_benchmark_suite "Standard WireGuard"
