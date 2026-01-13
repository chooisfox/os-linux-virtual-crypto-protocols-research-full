#!/bin/bash
set -e

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <path to ruwireguard-go binary> <path to wg tool>"
  exit 1
fi

RUWG_BIN=$(realpath "$1")
WG_TOOL=$(realpath "$2")

source "$(dirname "$0")/lib_benchmark.sh"

export WG_HIDE_KEYS=never
export LOG_LEVEL="error"
# Userspace networking benefit from higher GOMAXPROCS in some container envs
export GOMAXPROCS=$(nproc)

cleanup_sockets() {
    rm -f /var/run/wireguard/wg1.sock /var/run/wireguard/wg2.sock
}

setup_vpn_impl() {
    echo -e "${GREEN}[Setup] Initializing ruWireGuard-Go (Userspace)...${NC}"

    cleanup_sockets

    if ! lsmod | grep -q "^tun\s"; then
        modprobe tun || echo -e "${RED}[Error] Failed to load 'tun' module.${NC}"
    fi

    # 1. Запуск ruWireGuard в Namespace 1 (Интерфейс wg1)
    echo "    Starting NS1 instance (wg1)..."
    # Передаем переменные окружения явно внутрь netns
    ip netns exec ns1 env LOG_LEVEL=error GOMAXPROCS=$(nproc) "$RUWG_BIN" wg1 > "$LOG_DIR/ns1_daemon.log" 2>&1 &
    PID1=$!
    echo $PID1 > "$LOG_DIR/ns1_pid"

    # 2. Запуск ruWireGuard в Namespace 2 (Интерфейс wg2)
    echo "    Starting NS2 instance (wg2)..."
    ip netns exec ns2 env LOG_LEVEL=error GOMAXPROCS=$(nproc) "$RUWG_BIN" wg2 > "$LOG_DIR/ns2_daemon.log" 2>&1 &
    PID2=$!
    echo $PID2 > "$LOG_DIR/ns2_pid"

    echo -n "    Waiting for interfaces..."
    for i in {1..5}; do
        if ip netns exec ns1 ip link show wg1 >/dev/null 2>&1 && \
           ip netns exec ns2 ip link show wg2 >/dev/null 2>&1; then
            echo " OK"
            break
        fi

        if ! kill -0 $PID1 2>/dev/null; then
            echo -e "\n${RED}[ERROR] NS1 process died! Logs:${NC}"
            cat "$LOG_DIR/ns1_daemon.log"
            cleanup_common; cleanup_sockets
            exit 1
        fi
        if ! kill -0 $PID2 2>/dev/null; then
            echo -e "\n${RED}[ERROR] NS2 process died! Logs:${NC}"
            cat "$LOG_DIR/ns2_daemon.log"
            cleanup_common; cleanup_sockets
            exit 1
        fi
        sleep 1
        echo -n "."
    done

    if ! ip netns exec ns1 ip link show wg1 >/dev/null 2>&1; then
        echo -e "\n${RED}[ERROR] Timeout: Interface wg1 not created.${NC}"
        cleanup_common; cleanup_sockets
        exit 1
    fi

    # 3. Настройка адресов Overlay
    # Ставим txqueuelen побольше для tun интерфейса тоже
    ip netns exec ns1 ip link set dev wg1 qlen 2000
    ip netns exec ns1 ip addr add 192.168.1.1/24 dev wg1
    ip netns exec ns1 ip link set mtu 1420 up dev wg1

    ip netns exec ns2 ip link set dev wg2 qlen 2000
    ip netns exec ns2 ip addr add 192.168.1.2/24 dev wg2
    ip netns exec ns2 ip link set mtu 1420 up dev wg2

    # 4. Генерация ключей
    PRIV1=$($WG_TOOL genkey)
    PUB1=$(echo "$PRIV1" | $WG_TOOL pubkey)
    PRIV2=$($WG_TOOL genkey)
    PUB2=$(echo "$PRIV2" | $WG_TOOL pubkey)
    PSK=$($WG_TOOL genpsk)

    # 5. Конфигурация пиров
    echo "$PRIV1" | ip netns exec ns1 $WG_TOOL set wg1 \
        private-key /dev/stdin \
        listen-port 51820 \
        peer "$PUB2" \
            preshared-key <(echo "$PSK") \
            allowed-ips 192.168.1.0/24 \
            endpoint 10.0.0.2:51821

    echo "$PRIV2" | ip netns exec ns2 $WG_TOOL set wg2 \
        private-key /dev/stdin \
        listen-port 51821 \
        peer "$PUB1" \
            preshared-key <(echo "$PSK") \
            allowed-ips 192.168.1.0/24 \
            endpoint 10.0.0.1:51820

    echo -e "${GREEN}[Setup] Crypto configured. Handshaking...${NC}"
}

cleanup_common
cleanup_sockets
setup_namespaces
setup_vpn_impl
run_benchmark_suite "ruWireGuard-Go"
