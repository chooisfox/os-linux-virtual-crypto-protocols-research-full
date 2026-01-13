#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

FILE_SIZE_MB=512
TEST_DURATION=10
LOG_DIR="/tmp"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] This script must be run as root.${NC}"
  exit 1
fi

if ! command -v iperf3 &> /dev/null; then
    echo -e "${RED}[ERROR] iperf3 is not installed.${NC}"
    exit 1
fi

get_cpu_usage() {
    grep 'cpu ' /proc/stat | awk '{print $2+$3+$4+$7}'
}

cleanup_common() {
    echo -e "${YELLOW}[*] Cleaning up resources...${NC}"

    if [ -f "/var/run/netns/ns1" ]; then
        ip netns pids ns1 | xargs -r kill -9 2>/dev/null || true
    fi
    if [ -f "/var/run/netns/ns2" ]; then
        ip netns pids ns2 | xargs -r kill -9 2>/dev/null || true
    fi

    ip netns del ns1 2>/dev/null || true
    ip netns del ns2 2>/dev/null || true

    rm -f /tmp/test_file.bin /tmp/recv_file.bin
    rm -f "$LOG_DIR"/iperf_*.json "$LOG_DIR"/latency.log
}

trap "cleanup_common; exit" INT TERM

setup_namespaces() {
    echo -e "${GREEN}[Setup] Creating Namespaces and VETH...${NC}"
    ip netns add ns1
    ip netns add ns2

    ip link add veth1 type veth peer name veth2
    ip link set veth1 netns ns1
    ip link set veth2 netns ns2

    ip netns exec ns1 bash -c "ip addr add 10.0.0.1/24 dev veth1; ip link set veth1 up"
    ip netns exec ns2 bash -c "ip addr add 10.0.0.2/24 dev veth2; ip link set veth2 up"

    ip netns exec ns1 sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1
    ip netns exec ns2 sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1

    sleep 1
    if ! ip netns exec ns1 ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] VETH Underlay connectivity failed.${NC}"
        cleanup_common
        exit 1
    fi
}

setup_vpn_impl() {
    echo -e "${GREEN}[Setup] Configuring Overlay/VPN IPs...${NC}"
    ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth1 2>/dev/null || true
    ip netns exec ns2 ip addr add 192.168.1.2/24 dev veth2 2>/dev/null || true
}

parse_iperf_json() {
    local file=$1
    local field=$2
    if command -v python3 &>/dev/null; then
        python3 -c "import sys, json; print(json.load(sys.stdin)['end']['sum_received']['$field'])" < "$file" 2>/dev/null
    else
        grep "$field" "$file" | tail -n 1 | awk '{print $2}' | sed 's/,//'
    fi
}

run_tcp_efficiency_test() {
    echo -e "${GREEN}[Test] TCP Throughput (Max)...${NC}"

    ip netns exec ns2 iperf3 -s -D --logfile "$LOG_DIR/iperf_server.log"
    sleep 1

    local cpu_start=$(get_cpu_usage)
    local time_start=$(date +%s%N)

    ip netns exec ns1 iperf3 -c 192.168.1.2 -t $TEST_DURATION -J > "$LOG_DIR/iperf_tcp.json"

    local time_end=$(date +%s%N)
    local cpu_end=$(get_cpu_usage)

    local tcp_bw_bits=$(parse_iperf_json "$LOG_DIR/iperf_tcp.json" "bits_per_second")
    [ -z "$tcp_bw_bits" ] && tcp_bw_bits=0
    TCP_MBPS=$(echo "scale=2; $tcp_bw_bits / 1000000" | bc)

    local cpu_diff=$((cpu_end - cpu_start))
    local time_diff_sec=$(echo "scale=2; ($time_end - $time_start) / 1000000000" | bc)
    if (( $(echo "$time_diff_sec == 0" | bc -l) )); then time_diff_sec=1; fi

    CPU_COST=$(echo "scale=2; ($cpu_diff / $time_diff_sec)" | bc)
    if (( $(echo "$CPU_COST == 0" | bc -l) )); then EFFICIENCY="Inf"; else
        EFFICIENCY=$(echo "scale=2; $TCP_MBPS / $CPU_COST" | bc 2>/dev/null || echo "0")
    fi

    echo -e "    Throughput: ${CYAN}${TCP_MBPS} Mbps${NC}"
    if (( $(echo "$TCP_MBPS > 40000" | bc -l) )); then
        echo -e "                (Note: High speed is normal for VETH memory-copy)"
    fi
    echo -e "    CPU Cost:   ${CYAN}${CPU_COST}${NC}"
    echo -e "    Efficiency: ${CYAN}${EFFICIENCY}${NC}"
}

run_udp_saturation_test() {
    echo -e "${GREEN}[Test] UDP Max Throughput...${NC}"
    ip netns exec ns1 iperf3 -c 192.168.1.2 -u -b 0 -t $TEST_DURATION -J > "$LOG_DIR/iperf_udp.json"

    local udp_bw_bits=$(parse_iperf_json "$LOG_DIR/iperf_udp.json" "bits_per_second")
    [ -z "$udp_bw_bits" ] && udp_bw_bits=0
    UDP_MBPS=$(echo "scale=2; $udp_bw_bits / 1000000" | bc)

    if command -v python3 &>/dev/null; then
         UDP_LOSS=$(python3 -c "import sys, json; print(json.load(sys.stdin)['end']['sum']['lost_percent'])" < "$LOG_DIR/iperf_udp.json" 2>/dev/null)
    else
         UDP_LOSS=$(grep "lost_percent" "$LOG_DIR/iperf_udp.json" | tail -n 1 | awk '{print $2}' | sed 's/,//')
    fi

    echo -e "    Throughput: ${CYAN}${UDP_MBPS} Mbps${NC}"
    echo -e "    Packet Loss:${CYAN}${UDP_LOSS}%${NC}"
}

run_udp_pps_test() {
    echo -e "${GREEN}[Test] UDP PPS (64 byte packets)...${NC}"
    ip netns exec ns1 iperf3 -c 192.168.1.2 -u -l 64 -b 2G -t 5 -J > "$LOG_DIR/iperf_pps.json"

    if command -v python3 &>/dev/null; then
         local pps=$(python3 -c "import sys, json; print(json.load(sys.stdin)['end']['sum']['packets'])" < "$LOG_DIR/iperf_pps.json" 2>/dev/null)
    else
         local pps=$(grep "packets" "$LOG_DIR/iperf_pps.json" | tail -n 1 | awk '{print $2}' | sed 's/,//')
    fi
    [ -z "$pps" ] && pps=0
    PPS_RATE=$(echo "$pps / 5" | bc)
    echo -e "    Result:     ${CYAN}${PPS_RATE} pps${NC}"
}

run_file_integrity_test() {
    echo -e "${GREEN}[Test] File Integrity (${FILE_SIZE_MB} MB)...${NC}"

    local test_file="/tmp/test_file.bin"
    local recv_file="/tmp/recv_file.bin"
    local total_bytes=$((FILE_SIZE_MB * 1024 * 1024))

    if [ ! -f "$test_file" ] || [ $(stat -c%s "$test_file") -ne $total_bytes ]; then
        dd if=/dev/urandom of="$test_file" bs=1M count=$FILE_SIZE_MB status=none
    fi
    local orig_sum=$(md5sum "$test_file" | awk '{print $1}')

    rm -f "$recv_file"

    if command -v socat &>/dev/null; then
        ip netns exec ns2 socat -u TCP4-LISTEN:6000,reuseaddr OPEN:"$recv_file",create &
    else
        ip netns exec ns2 timeout 60 nc -l -p 6000 > "$recv_file" &
    fi
    local rx_pid=$!
    sleep 2

    echo "    Sending file..."
    local start_time=$(date +%s%N)

    if command -v socat &>/dev/null; then
        ip netns exec ns1 socat -u OPEN:"$test_file" TCP4:192.168.1.2:6000
    else
        ip netns exec ns1 timeout 60 nc -q 1 192.168.1.2 6000 < "$test_file"
    fi

    local end_time=$(date +%s%N)
    wait $rx_pid || true

    if [ -f "$recv_file" ]; then
        local recv_sum=$(md5sum "$recv_file" | awk '{print $1}')
    else
        local recv_sum="MISSING"
    fi

    if [ "$orig_sum" == "$recv_sum" ]; then
        local dur_ns=$((end_time - start_time))
        local dur_sec=$(echo "scale=4; $dur_ns / 1000000000" | bc)

        if (( $(echo "$dur_sec < 0.1" | bc -l) )); then dur_sec=0.1; fi

        local speed=$(echo "scale=2; ($FILE_SIZE_MB * 8) / $dur_sec" | bc)
        FILE_RESULT="PASS"
        echo -e "    Result:     ${CYAN}PASS${NC} (Approx $speed Mbps)"
    else
        FILE_RESULT="FAIL"
        echo -e "    Result:     ${RED}FAIL${NC} (Checksum Mismatch)"
    fi
}

run_latency_test() {
    echo -e "${GREEN}[Test] Latency under Load...${NC}"
    ip netns exec ns1 iperf3 -c 192.168.1.2 -u -b 100M -t 10 >/dev/null 2>&1 &
    local load_pid=$!
    sleep 2
    ip netns exec ns1 ping -c 5 192.168.1.2 > "$LOG_DIR/latency.log"
    wait $load_pid || true
    LATENCY_AVG=$(grep "rtt" "$LOG_DIR/latency.log" | awk -F '/' '{print $5}')
    echo -e "    Result:     ${CYAN}${LATENCY_AVG} ms${NC}"
}

print_summary() {
    local impl_name=$1
    echo -e "\n${CYAN}=== Benchmark Summary: $impl_name ===${NC}"
    {
        echo "Protocol:       $impl_name"
        echo "TCP Throughput: $TCP_MBPS Mbps"
        echo "UDP Throughput: $UDP_MBPS Mbps"
        echo "UDP Loss:       $UDP_LOSS %"
        echo "CPU Cost:       $CPU_COST"
        echo "Efficiency:     $EFFICIENCY"
        echo "PPS (64b UDP):  $PPS_RATE"
        echo "Integrity:      $FILE_RESULT"
        echo "Latency (Load): $LATENCY_AVG ms"
    } | tee "$LOG_DIR/summary.txt"
}

run_benchmark_suite() {
    local impl_name=${1:-"Generic"}
    cleanup_common
    setup_namespaces
    setup_vpn_impl

    ip netns exec ns1 ping -c 2 192.168.1.2 >/dev/null 2>&1
    sleep 1
    if ! ip netns exec ns1 ping -c 1 -W 1 192.168.1.2 >/dev/null 2>&1; then
        echo -e "${RED}[FAIL] No connectivity.${NC}"
        cleanup_common
        exit 1
    fi

    run_tcp_efficiency_test
    run_udp_saturation_test
    run_udp_pps_test
    run_file_integrity_test
    run_latency_test

    print_summary "$impl_name"
    cleanup_common
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_benchmark_suite "Manual_Run"
    exit 0
fi
