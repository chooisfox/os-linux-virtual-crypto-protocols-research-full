#!/bin/bash
set -e

source "$(dirname "$0")/lib_benchmark.sh"

CLI_TOOL="$(dirname "$0")/wg_gost_cli"
BUILD_DIR="$(pwd)/build"

setup_vpn_impl() {
    echo -e "${GREEN}[Setup] Initializing WireGost (Kernel 512-bit)...${NC}"

    if ! lsmod | grep -q "wiregost"; then
        echo "Loading module..."
        if [ ! -f "$BUILD_DIR/wiregost.ko" ]; then
             echo -e "${RED}Error: Build the module first!${NC}"; exit 1
        fi
        insmod "$BUILD_DIR/wiregost.ko"
    fi

    if [ ! -f "$CLI_TOOL" ]; then
        gcc -o "$CLI_TOOL" "$(dirname "$0")/wg_gost_cli.c"
    fi

    ip netns exec ns1 ip link add wg0 type wiregost
    ip netns exec ns1 ip addr add 192.168.1.1/24 dev wg0
    ip netns exec ns1 ip link set wg0 up

    ip netns exec ns2 ip link add wg0 type wiregost
    ip netns exec ns2 ip addr add 192.168.1.2/24 dev wg0
    ip netns exec ns2 ip link set wg0 up

    OUT1=$(ip netns exec ns1 $CLI_TOOL init wg0 51820 gen 2>&1)
    PUB1=$(echo "$OUT1" | grep "PUBLIC:" | awk '{print $2}')

    OUT2=$(ip netns exec ns2 $CLI_TOOL init wg0 51821 gen 2>&1)
    PUB2=$(echo "$OUT2" | grep "PUBLIC:" | awk '{print $2}')

    ip netns exec ns1 $CLI_TOOL peer wg0 $PUB2 10.0.0.2 51821 192.168.1.2
    ip netns exec ns2 $CLI_TOOL peer wg0 $PUB1 10.0.0.1 51820 192.168.1.1
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$(pwd)/testing/logs/gost_${TIMESTAMP}"
mkdir -p "$LOG_DIR"

cleanup_common
run_benchmark_suite "WireGost"
