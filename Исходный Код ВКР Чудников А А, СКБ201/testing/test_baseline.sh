#!/bin/bash
set -e

# Import Library
source "$(dirname "$0")/lib_benchmark.sh"

# Define Implementation Specific Setup
setup_vpn_impl() {
    echo -e "${GREEN}[Setup] Configuring Direct VETH Baseline (No Encryption)...${NC}"

    # In the baseline test, there is no tunnel interface (wg0).
    # We simply add the "Overlay" IP addresses directly to the "Underlay" VETH interfaces.
    # This allows iperf3 to dial 192.168.1.2 exactly as it does in the VPN tests.

    ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth1
    ip netns exec ns2 ip addr add 192.168.1.2/24 dev veth2

    # Explicitly ensure MTU is standard Ethernet (1500) for baseline
    ip netns exec ns1 ip link set veth1 mtu 1500
    ip netns exec ns2 ip link set veth2 mtu 1500
}

# Prep Logging
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$(pwd)/testing/logs/baseline_${TIMESTAMP}"
mkdir -p "$LOG_DIR"

# Run
cleanup_common
run_benchmark_suite "Baseline (Raw VETH)"
