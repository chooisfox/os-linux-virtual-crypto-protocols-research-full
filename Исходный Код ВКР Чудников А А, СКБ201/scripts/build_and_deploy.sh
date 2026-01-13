#!/bin/bash

# Configuration
DEST_DIR="./deploy"
KUZ_DIR="./lkm/kuznyechik"
VKO_DIR="./lkm/ec256_vko"
BUILD_DIR="./build"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Starting Build Process...${NC}"

# ---------------------------------------------------------
# 1.1 Build Submodule (Kuznyechik)
# ---------------------------------------------------------
echo -e "${YELLOW}[*] Building Kuznyechik LKM...${NC}"
if [ -d "$KUZ_DIR" ]; then
    make -C "$KUZ_DIR" clean > /dev/null
    make -C "$KUZ_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error building Kuznyechik module.${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Kuznyechik directory not found at $KUZ_DIR${NC}"
    exit 1
fi

# ---------------------------------------------------------
# 1.2 Build Submodule (VKO)
# ---------------------------------------------------------
echo -e "${YELLOW}[*] Building VKO LKM...${NC}"
if [ -d "$VKO_DIR" ]; then
    make -C "$VKO_DIR" clean > /dev/null
    make -C "$VKO_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error building VKO module.${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Kuznyechik directory not found at $VKO_DIR${NC}"
    exit 1
fi

# ---------------------------------------------------------
# 2. Build Main Module (Wiregost)
# ---------------------------------------------------------
echo -e "${YELLOW}[*] Building Wiregost...${NC}"
make clean > /dev/null
make
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Error building Wiregost module.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Build Successful.${NC}"

# ---------------------------------------------------------
# 3. Consolidate Artifacts
# ---------------------------------------------------------
# To make the 'shared' folder self-contained, we copy the LKM modules
# into the build folder.
echo -e "${YELLOW}[*] Consolidating modules into $BUILD_DIR...${NC}"
cp "$KUZ_DIR/build/kuznyechik_generic.ko" "$BUILD_DIR/"
# cp "$KUZ_DIR/build/kuznyechik_mgm_generic.ko" "$BUILD_DIR/"
cp "$VKO_DIR/build/ec256_vko_generic.ko" "$BUILD_DIR/"

# ---------------------------------------------------------
# 4. Generate Run Script (load_modules.sh)
# ---------------------------------------------------------
# We generate this script INSIDE the build directory.
# The paths are relative to the script location (.) so it works
# when moved to the VM.
RUN_SCRIPT="$BUILD_DIR/load_modules.sh"

echo -e "${YELLOW}[*] Generating run script at $RUN_SCRIPT...${NC}"

cat <<EOF > "$RUN_SCRIPT"
#!/bin/bash

echo "[-] Unloading existing modules..."
# Unload in reverse dependency order
if lsmod | grep -q "^wiregost"; then sudo rmmod wiregost; fi
# if lsmod | grep -q "^kuznyechik_mgm_generic"; then sudo rmmod kuznyechik_mgm_generic; fi
if lsmod | grep -q "^kuznyechik_generic"; then sudo rmmod kuznyechik_generic; fi
if lsmod | grep -q "^ec256_vko_generic"; then sudo rmmod ec256_vko_generic; fi

echo "[+] Loading dependencies..."
sudo modprobe udp_tunnel
sudo modprobe ip6_udp_tunnel
sudo modprobe streebog_generic

echo "[+] Inserting compiled modules..."
# Using local paths because we consolidated them into this folder
if [ -f "./kuznyechik_generic.ko" ]; then
    sudo insmod ./kuznyechik_generic.ko
else
    echo "Error: kuznyechik_generic.ko not found in current directory"
    exit 1
fi

#if [ -f "./kuznyechik_mgm_generic.ko" ]; then
#    sudo insmod ./kuznyechik_mgm_generic.ko
#else
#    echo "Error: kuznyechik_mgm_generic.ko not found in current directory"
#    exit 1
#fi

if [ -f "./ec256_vko_generic.ko" ]; then
    sudo insmod ./ec256_vko_generic.ko
else
    echo "Error: ec256_vko_generic.ko not found in current directory"
    exit 1
fi

if [ -f "./wiregost.ko" ]; then
    sudo insmod ./wiregost.ko
else
    echo "Error: wiregost.ko not found in current directory"
    exit 1
fi

echo "[+] Done. Modules loaded."
EOF

# Make the generated script executable
chmod +x "$RUN_SCRIPT"

# ---------------------------------------------------------
# 5. Move to Shared Directory
# ---------------------------------------------------------
echo -e "${YELLOW}[*] Moving build artifact to $DEST_DIR...${NC}"

# Check if destination exists, create if not
if [ ! -d "$DEST_DIR" ]; then
    mkdir -p "$DEST_DIR"
fi

# Remove old build folder in destination if it exists to avoid conflicts
if [ -d "$DEST_DIR/build" ]; then
    rm -rf "$DEST_DIR/build"
fi

# Move the directory
mv "$BUILD_DIR" "$DEST_DIR/"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Successfully moved build to $DEST_DIR/build${NC}"
    echo -e "${GREEN}[+] You can now run 'sudo ./load_modules.sh' inside that folder.${NC}"
else
    echo -e "${RED}[!] Failed to move build directory.${NC}"
    exit 1
fi
