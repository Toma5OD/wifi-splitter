#!/usr/bin/env bash
# wifi-splitter.sh
# Share your MacBook's ship WiFi (via Cloudflare WARP) to your iPhone as a hotspot.
#
# How it works:
#   Ship WiFi → Mac (en0) → Cloudflare WARP (utun) → hotspot (bridge100) → iPhone
#   Your iPhone's traffic exits through WARP automatically — no extra setup needed.
#
# Usage:
#   sudo bash wifi-splitter.sh start    # turn hotspot on
#   sudo bash wifi-splitter.sh stop     # turn hotspot off
#   sudo bash wifi-splitter.sh status   # check if running
#   sudo bash wifi-splitter.sh config   # show/set SSID & password

# ─── CONFIG ───────────────────────────────────────────────────────────────────
HOTSPOT_SSID="ShipShare"
HOTSPOT_PASS="changeme1"       # min 8 chars, WPA2
WIFI_INTERFACE="en0"           # your WiFi interface (auto-detected below)
NAT_PLIST="/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
SHARING_DAEMON="/System/Library/LaunchDaemons/com.apple.NetworkSharing.plist"
SHARING_SERVICE="system/com.apple.NetworkSharing"
# ──────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# ─── Checks ───────────────────────────────────────────────────────────────────
[[ "$(uname)" != "Darwin" ]] && err "macOS only."
[[ "$(id -u)" != "0" ]]      && err "Run with sudo:  sudo bash wifi-splitter.sh ${1:-start}"

# Auto-detect WiFi interface
detected=$(networksetup -listallhardwareports 2>/dev/null \
    | awk '/Wi-Fi/{getline; print $2}' | head -1)
[[ -n "$detected" ]] && WIFI_INTERFACE="$detected"

# ─── Functions ────────────────────────────────────────────────────────────────

check_warp() {
    local warp_cli="/usr/local/bin/warp-cli"
    local connected=false

    if [[ -x "$warp_cli" ]]; then
        if "$warp_cli" status 2>/dev/null | grep -qi "connected"; then
            connected=true
        fi
    elif pgrep -x "Cloudflare WARP" &>/dev/null \
         || pgrep -x "warp-taskbar" &>/dev/null; then
        connected=true
    fi

    if $connected; then
        log "Cloudflare WARP is connected — iPhone traffic will be tunnelled through it"
    else
        warn "Cloudflare WARP is NOT connected. iPhone traffic will NOT be protected!"
        warn ""
        warn "To reconnect WARP:"
        warn "  1. If you see CF_DNS_PROXY_FAILURE in the 1.1.1.1 app:"
        warn "     Chrome → Settings → Privacy & Security → Security"
        warn "     → 'Use secure DNS' → turn OFF, then reconnect WARP"
        warn "  2. Otherwise: open the 1.1.1.1 app and tap Connect"
        warn ""
    fi
}

configure_nat_plist() {
    # Build the NAT plist that macOS Internet Sharing reads.
    # AirPort block sets the hotspot SSID + password.
    python3 - <<PYEOF
import plistlib, re, subprocess

path = "$NAT_PLIST"

try:
    with open(path, "rb") as f:
        data = plistlib.load(f)
except Exception:
    data = {}

nat = data.get("NAT", {})

# Look up Wi-Fi MAC (HardwareKey) and the Wi-Fi service UUID (PrimaryService).
# macOS Internet Sharing prefers PrimaryService over PrimaryInterface.Device when
# choosing the source. Without it, it falls back to network service order — which
# can pick a stale Ethernet service (e.g. an unplugged USB-Ethernet adapter).
hwkey = ""
try:
    out = subprocess.run(["networksetup", "-getmacaddress", "$WIFI_INTERFACE"],
                         capture_output=True, text=True).stdout
    m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", out, re.I)
    if m:
        hwkey = m.group(1).lower()
except Exception:
    pass

service_uuid = ""
try:
    with open("/Library/Preferences/SystemConfiguration/preferences.plist", "rb") as f:
        prefs = plistlib.load(f)
    for uuid, svc in prefs.get("NetworkServices", {}).items():
        iface = svc.get("Interface", {})
        if iface.get("DeviceName") == "$WIFI_INTERFACE" and iface.get("Hardware") == "AirPort":
            service_uuid = uuid
            break
except Exception:
    pass

# Primary interface (source of internet — ship WiFi)
nat["PrimaryInterface"] = {
    "Device":      "$WIFI_INTERFACE",
    "Enabled":     True,
    "HardwareKey": hwkey,
}
if service_uuid:
    nat["PrimaryService"] = service_uuid

# Airport (the hotspot we create)
nat["AirPort"] = {
    "Enabled":         True,
    "NetworkName":     "$HOTSPOT_SSID",
    "NetworkPassword": "$HOTSPOT_PASS"
}

nat["Enabled"] = True

# SharingDevices must NOT include the primary interface (en0).
# For WiFi→WiFi hotspot macOS creates bridge100 automatically.
# An empty list is correct — the AirPort block above handles the hotspot side.
nat["SharingDevices"] = []

data["NAT"] = nat

with open(path, "wb") as f:
    plistlib.dump(data, f)

print(f"Plist configured OK (device=$WIFI_INTERFACE hwkey={hwkey or 'MISSING'} service={service_uuid or 'MISSING'})")
PYEOF
}

is_running() {
    # Service is running AND an active sharing interface exists
    # USB tethering creates an iPhone interface (en5/en6/etc); WiFi hotspot creates bridge100
    launchctl print "$SHARING_SERVICE" 2>/dev/null | grep -q "state = running" \
        && { ifconfig 2>/dev/null | grep -q "^bridge1" \
             || pgrep -x natd &>/dev/null \
             || iphone_usb_interface; }
}

service_loaded() {
    launchctl print "$SHARING_SERVICE" 2>/dev/null | grep -q "state = running"
}

iphone_usb_interface() {
    # iPhone USB shows up as a CDC ethernet interface when plugged in and trusted
    system_profiler SPUSBDataType 2>/dev/null | grep -q "iPhone" \
        || networksetup -listallhardwareports 2>/dev/null | grep -qi "iphone\|apple mobile"
}

# ─── Commands ─────────────────────────────────────────────────────────────────

cmd_start() {
    echo ""
    info "WiFi interface : $WIFI_INTERFACE"
    check_warp

    log "Writing hotspot config (SSID: $HOTSPOT_SSID)..."
    configure_nat_plist || err "Failed to write NAT plist"

    log "Restarting Internet Sharing service..."
    # kickstart -k kills and restarts — forces it to re-read the NAT plist
    launchctl kickstart -k "$SHARING_SERVICE" 2>/dev/null
    sleep 3

    if is_running; then
        echo ""
        echo -e "  ${GREEN}Internet Sharing is active (USB).${NC}"
        echo ""
        echo "  1. Plug iPhone into Mac with USB-C cable"
        echo "  2. Tap 'Trust' on iPhone if prompted"
        echo "  3. Run the transparent proxy:  sudo bash wifi-splitter.sh tproxy"
        echo ""
        info "The proxy routes all iPhone traffic through Cloudflare WARP."
        info "iPhone WiFi can stay OFF — USB cable is all you need."
        echo ""
    else
        echo ""
        warn "Internet Sharing service started but no bridge interface found yet."
        warn "Try waiting a few seconds and running: sudo bash wifi-splitter.sh status"
        echo ""
    fi
}

cmd_stop() {
    if service_loaded; then
        launchctl kill TERM "$SHARING_SERVICE" 2>/dev/null
        sleep 1
        launchctl kickstart -k "$SHARING_SERVICE" 2>/dev/null  # restart clean (no sharing config)
        log "Hotspot stopped."
    else
        info "Hotspot was not running."
    fi
}

cmd_status() {
    echo ""
    info "WiFi interface : $WIFI_INTERFACE"

    svc_state=$(launchctl print "$SHARING_SERVICE" 2>/dev/null | awk '/state =/{print $3}')
    bridge=$(ifconfig 2>/dev/null | grep -o 'bridge1[0-9]*' | head -1)

    if [[ "$svc_state" == "running" ]]; then
        echo -e "  NetworkSharing   : ${GREEN}SERVICE RUNNING${NC}"
    else
        echo -e "  NetworkSharing   : ${RED}STOPPED${NC} (state: ${svc_state:-unknown})"
    fi
    if [[ -n "$bridge" ]]; then
        echo -e "  Hotspot bridge   : ${GREEN}$bridge (active)${NC}"
    else
        echo -e "  Hotspot bridge   : ${YELLOW}not up${NC} (hotspot not broadcasting)"
    fi

    # WARP status
    local warp_cli="/usr/local/bin/warp-cli"
    local warp_status
    if [[ -x "$warp_cli" ]]; then
        warp_status=$("$warp_cli" status 2>/dev/null | head -1)
        if echo "$warp_status" | grep -qi "connected"; then
            echo -e "  Cloudflare WARP  : ${GREEN}CONNECTED${NC} ($warp_status)"
        else
            echo -e "  Cloudflare WARP  : ${RED}NOT CONNECTED${NC} ($warp_status)"
        fi
    elif pgrep -x "Cloudflare WARP" &>/dev/null || pgrep -x "warp-taskbar" &>/dev/null; then
        echo -e "  Cloudflare WARP  : ${GREEN}RUNNING${NC} (process detected)"
    else
        echo -e "  Cloudflare WARP  : ${YELLOW}NOT DETECTED${NC}"
    fi

    echo ""
}

cmd_tproxy() {
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    TPROXY_PY="$SCRIPT_DIR/tproxy.py"
    TPROXY_GO_SRC="$SCRIPT_DIR/tproxy.go"
    TPROXY_GO_BIN="$SCRIPT_DIR/tproxy-go"

    USE_GO=false
    ARGS=()
    for arg in "$@"; do
        if [[ "$arg" == "-go" ]]; then
            USE_GO=true
        else
            ARGS+=("$arg")
        fi
    done

    if $USE_GO; then
        [[ ! -f "$TPROXY_GO_SRC" ]] && err "tproxy.go not found next to wifi-splitter.sh"
        if [[ ! -f "$TPROXY_GO_BIN" ]] || [[ "$TPROXY_GO_SRC" -nt "$TPROXY_GO_BIN" ]]; then
            command -v go &>/dev/null || err "Go not installed. See https://go.dev — or run without -go to use Python"
            log "Compiling Go proxy (this is once-only)..."
            go build -o "$TPROXY_GO_BIN" "$TPROXY_GO_SRC" || err "Build failed"
            log "Build complete."
        fi
        log "Starting transparent proxy (Go)..."
        "$TPROXY_GO_BIN" "${ARGS[@]}"
    else
        [[ ! -f "$TPROXY_PY" ]] && err "tproxy.py not found next to wifi-splitter.sh"
        log "Starting transparent proxy (Python)..."
        python3 "$TPROXY_PY" "${ARGS[@]}"
    fi
}

cmd_proxy() {
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROXY_SCRIPT="$SCRIPT_DIR/proxy.py"
    [[ ! -f "$PROXY_SCRIPT" ]] && err "proxy.py not found next to wifi-splitter.sh"

    # Run as the actual user, not root (so WARP intercepts the traffic)
    REAL_USER="${SUDO_USER:-$USER}"
    log "Starting proxy as $REAL_USER (so traffic goes through WARP)..."
    sudo -u "$REAL_USER" python3 "$PROXY_SCRIPT"
}

cmd_config() {
    echo ""
    info "Current config baked into this script:"
    echo "  SSID     : $HOTSPOT_SSID"
    echo "  Password : $HOTSPOT_PASS"
    echo "  Source   : $WIFI_INTERFACE (ship WiFi)"
    echo ""
    info "To change SSID or password, edit the CONFIG block at the top of this file."
    echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────

case "${1:-start}" in
    start)  cmd_start  ;;
    stop)   cmd_stop   ;;
    status) cmd_status ;;
    tproxy) shift; cmd_tproxy "$@" ;;
    proxy)  shift; cmd_proxy  "$@" ;;
    config) cmd_config ;;
    *)
        echo "Usage: sudo bash wifi-splitter.sh [start|stop|status|proxy|config]"
        echo ""
        echo "  start   — enable Internet Sharing (gives iPhone an IP)"
        echo "  proxy   — start HTTP proxy so iPhone traffic goes through WARP"
        echo "  stop    — shut down Internet Sharing"
        echo "  status  — show current state"
        echo "  config  — show SSID/password settings"
        ;;
esac
