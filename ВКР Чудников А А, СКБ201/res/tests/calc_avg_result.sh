#!/bin/bash

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$#" -ne 1 ]; then
    echo -e "${YELLOW}Usage: $0 <path_to_results_file.dat>${NC}"
    exit 1
fi

FILE="$1"

if [ ! -f "$FILE" ]; then
    echo -e "${RED}[ERROR] File '$FILE' not found.${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Parsing file: $FILE ...${NC}"

awk '
    BEGIN {
        # Initialize counters
        c_tcp = 0; c_udp = 0; c_loss = 0; c_cpu = 0; c_eff = 0; c_pps = 0; c_lat = 0;
    }

    /TCP Throughput:/ {
        sum_tcp += $3;
        c_tcp++;
    }

    /UDP Throughput:/ {
        sum_udp += $3;
        c_udp++;
    }

    /UDP Loss:/ {
        sum_loss += $3;
        c_loss++;
    }

    /CPU Cost:/ {
        sum_cpu += $3;
        c_cpu++;
    }

    /Efficiency:/ {
        sum_eff += $2;
        c_eff++;
    }

    /PPS \(64b UDP\):/ {
        sum_pps += $4;
        c_pps++;
    }

    /Latency \(Load\):/ {
        sum_lat += $3;
        c_lat++;
    }

    END {
        if (c_tcp == 0) {
            print "No benchmark data found.";
            exit 1;
        }

        # Configuration for colors inside AWK
        CYAN="\033[0;36m"
        NC="\033[0m"
        BOLD="\033[1m"

        printf "\n%s=== Average Results (Processed %d tests) ===%s\n", BOLD, c_tcp, NC

        # Calculate and print averages
        # Using ternary operator (cond ? true : false) to prevent division by zero

        printf "Protocol:       Standard WireGuard (Averaged)\n"

        printf "TCP Throughput: %s%.2f Mbps%s\n", CYAN, (c_tcp>0 ? sum_tcp/c_tcp : 0), NC
        printf "UDP Throughput: %s%.2f Mbps%s\n", CYAN, (c_udp>0 ? sum_udp/c_udp : 0), NC
        printf "UDP Loss:       %s%.4f %%%s\n",   CYAN, (c_loss>0 ? sum_loss/c_loss : 0), NC
        printf "CPU Cost:       %s%.2f%s\n",      CYAN, (c_cpu>0 ? sum_cpu/c_cpu : 0), NC
        printf "Efficiency:     %s%.2f%s\n",      CYAN, (c_eff>0 ? sum_eff/c_eff : 0), NC
        printf "PPS (64b UDP):  %s%.0f%s\n",      CYAN, (c_pps>0 ? sum_pps/c_pps : 0), NC
        printf "Latency (Load): %s%.3f ms%s\n",   CYAN, (c_lat>0 ? sum_lat/c_lat : 0), NC
        printf "\n"
    }
' "$FILE"
