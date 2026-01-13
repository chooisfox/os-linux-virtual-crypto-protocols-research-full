#!/bin/bash
set -e

source "$(dirname "$0")/lib_benchmark.sh"

setup_vpn_impl() {
    echo -e "${GREEN}[Setup] Configuring Direct VETH Baseline (No Encryption)...${NC}"

    ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth1
    ip netns exec ns2 ip addr add 192.168.1.2/24 dev veth2

    ip netns exec ns1 ip link set veth1 mtu 1500
    ip netns exec ns2 ip link set veth2 mtu 1500
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$(pwd)/testing/logs/baseline_${TIMESTAMP}"
mkdir -p "$LOG_DIR"

cleanup_common
run_benchmark_suite "Baseline (Raw VETH)"
