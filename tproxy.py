#!/usr/bin/env python3
"""
tproxy.py — Transparent TCP proxy for wifi-splitter

Problem it solves:
  Internet Sharing NAT bypasses Cloudflare WARP → ship detects a second
  device → blocks the iPhone.

How it works:
  pf intercepts ALL TCP from the iPhone (bridge100) before it touches
  the NAT layer, redirects it to this proxy running as a Mac process.
  Because the proxy IS a Mac process, WARP tunnels its outbound
  connections through Cloudflare — just like the Mac's own traffic.

  iPhone (USB) → pf rdr → this proxy → WARP utun → Cloudflare → internet

  No proxy config needed on the iPhone. WiFi can be OFF.

Usage:
  sudo bash wifi-splitter.sh start   (Internet Sharing, gives iPhone IP)
  sudo python3 tproxy.py             (this file — transparent TCP proxy)
"""

import ctypes, socket, struct, fcntl, os, sys
import threading, select, signal, subprocess, time

# ─── Config ──────────────────────────────────────────────────────────────────

BRIDGE_IF    = "bridge100"
BRIDGE_NET   = "192.168.2.0/24"
BRIDGE_IP    = "192.168.2.1"   # Mac's IP on bridge100 — redirect target for pf rdr
PROXY_PORT   = 9999            # intercepts port 443
PROXY_PORT_PASSTHRU = 9998     # intercepts other ports (5222 etc) — connects upstream on original port
TIMEOUT      = 30
BUFFER       = 65536
ANCHOR       = "wifi_splitter"
MONITOR_SECS = 30
WARP_CLI     = "/usr/local/bin/warp-cli"

# Ports to proxy via PROXY_PORT_PASSTHRU (connects upstream on the same original port).
# Leave empty unless you have a specific port whose protocol includes SNI/hostname in the
# TLS ClientHello and you need it tunnelled through WARP.
# Port 5222 (WhatsApp XMPP) uses a custom binary protocol with no parseable hostname
# so it cannot be proxied — leave it out and let it go through Internet Sharing's NAT.
PASSTHRU_PORTS = []

# ─── DIOCNATLOOK — get original destination from pf state ────────────────────
#
# When pf redirects a TCP packet with rdr-to, the state table records the
# original (pre-redirect) destination. DIOCNATLOOK queries that table.
#
# struct pfioc_natlook (from /usr/include/net/pfvar.h):
#   saddr  (16)  daddr  (16)  rsaddr (16)  rdaddr (16)   ← pf_addr union
#   sport  (2)   dport  (2)   rsport (2)   rdport  (2)   ← network byte order
#   af(1)  proto(1)  proto_variant(1)  direction(1)
#   total: 76 bytes
#
# DIOCNATLOOK = _IOWR('D', 23, 76) = 0xC04C4417

DIOCNATLOOK = 0xC04C4417
PF_IN  = 1
PF_OUT = 2

_pf_fd = -1

def _open_pf():
    global _pf_fd
    _pf_fd = os.open("/dev/pf", os.O_RDWR)

def _get_original_dst(client_sock):
    """
    Return (dst_ip, dst_port) via DIOCNATLOOK pf state table lookup, or None.
    macOS 26+ returns ENOTSUP (errno 19) — in that case returns None silently
    and the caller falls back to SNI/HTTP inspection.
    """
    peer_ip, peer_port = client_sock.getpeername()
    our_ip,  our_port  = client_sock.getsockname()

    peer_b = socket.inet_aton(peer_ip)
    our_b  = socket.inet_aton(our_ip)

    for direction in (PF_OUT, PF_IN):
        buf = bytearray(76)
        buf[0:4]   = peer_b
        buf[16:20] = our_b
        struct.pack_into(">H", buf, 64, peer_port)
        struct.pack_into(">H", buf, 66, our_port)
        buf[72] = 2   # AF_INET
        buf[73] = 6   # IPPROTO_TCP
        buf[75] = direction

        try:
            fcntl.ioctl(_pf_fd, DIOCNATLOOK, buf)
        except OSError:
            continue

        orig_ip   = socket.inet_ntoa(bytes(buf[48:52]))
        orig_port = struct.unpack_from(">H", buf, 70)[0]
        if orig_ip not in ("0.0.0.0", "127.0.0.1") and orig_port > 0:
            return orig_ip, orig_port

    return None

# ─── Protocol inspection fallback ────────────────────────────────────────────
#
# When DIOCNATLOOK fails we inspect the first bytes of the connection:
#   • TLS ClientHello → extract SNI hostname → connect to hostname:443
#   • HTTP CONNECT    → extract target from CONNECT line
#   • Plain HTTP GET  → extract target from Host header

def _parse_tls_sni(data):
    """Extract the SNI hostname from a TLS ClientHello record, or None."""
    try:
        if len(data) < 6 or data[0] != 0x16:   # not TLS handshake record
            return None
        if data[5] != 0x01:                      # not ClientHello
            return None
        pos = 9                                  # skip record(5) + handshake type(1) + length(3)
        pos += 2 + 32                            # client_version(2) + random(32)
        if pos >= len(data): return None
        pos += 1 + data[pos]                     # session_id length + session_id
        if pos + 2 > len(data): return None
        pos += 2 + struct.unpack_from(">H", data, pos)[0]   # cipher_suites
        if pos + 1 > len(data): return None
        pos += 1 + data[pos]                     # compression_methods
        if pos + 2 > len(data): return None
        ext_end = pos + 2 + struct.unpack_from(">H", data, pos)[0]
        pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack_from(">H", data, pos)[0]
            ext_len  = struct.unpack_from(">H", data, pos + 2)[0]
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= len(data):  # SNI extension
                name_len = struct.unpack_from(">H", data, pos + 3)[0]
                return data[pos + 5: pos + 5 + name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        pass
    return None

def _parse_protocol_dst(client_sock):
    """
    Peek at the first bytes and determine the destination from the protocol.
    Returns (host, port, is_connect) or None.
      is_connect=True  → TLS/CONNECT: we've NOT consumed the CONNECT header
      is_connect=False → plain HTTP: we've NOT consumed the request
    """
    client_sock.settimeout(5)
    try:
        data = client_sock.recv(4096, socket.MSG_PEEK)
    except Exception:
        return None
    if not data:
        return None

    # TLS ClientHello → SNI (port determined by caller based on which pf rule fired)
    if data[0] == 0x16:
        sni = _parse_tls_sni(data)
        if sni:
            return sni, None, False  # port=None → use upstream_port from caller
        return None

    # HTTP
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return None
    method, target = parts[0], parts[1]
    if method == "CONNECT":
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s.isdigit() else 443
        return host, port, True
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            hostval = line.split(":", 1)[1].strip()
            if ":" in hostval:
                h, _, p = hostval.rpartition(":")
                return h, int(p) if p.isdigit() else 80, False
            return hostval, 80, False
    return None

# ─── Relay ───────────────────────────────────────────────────────────────────

def _relay(a, b):
    a.setblocking(False)
    b.setblocking(False)
    # Enable TCP keepalive so the OS detects dead connections without us
    # closing idle ones (critical for WhatsApp MQTT which has ~30s keep-alive)
    for s in (a, b):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
    socks = [a, b]
    try:
        while True:
            r, _, e = select.select(socks, [], socks, TIMEOUT)
            if e:
                break
            # Timeout (r is empty) = connection idle, keep waiting — do NOT close
            if not r:
                continue
            for s in r:
                other = b if s is a else a
                try:
                    d = s.recv(BUFFER)
                    if not d:
                        return
                    other.sendall(d)
                except (OSError, BrokenPipeError, ConnectionResetError):
                    return
    except Exception:
        pass

# ─── Per-connection handler ───────────────────────────────────────────────────

_total_conn   = 0   # lifetime connections proxied
_dropped_conn = 0   # connections where destination couldn't be determined
_verbose      = False

def _handle(client, upstream_port=443):
    global _total_conn, _dropped_conn
    peer = client.getpeername()
    upstream = None
    dst = None
    try:
        dst = _get_original_dst(client)

        if dst is None:
            info = _parse_protocol_dst(client)
            if info is None:
                _dropped_conn += 1
                if _verbose:
                    print(f"[!] {peer} — no destination found; dropping")
                return
            host, port, is_connect = info
            # port=None means TLS SNI — use the upstream_port the caller determined
            dst = (host, port if port is not None else upstream_port)
            if _verbose:
                print(f"[~] {peer} → {host}:{dst[1]}")
            if is_connect:
                client.recv(8192)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        elif _verbose:
            print(f"[>] {peer} → {dst[0]}:{dst[1]}")

        _total_conn += 1
        upstream = socket.create_connection(dst, timeout=TIMEOUT)
        _relay(client, upstream)
    except Exception as e:
        if _verbose:
            print(f"[!] {peer} → {dst}: {e}")
    finally:
        for s in (client, upstream):
            if s:
                try: s.close()
                except: pass

# ─── pf setup / teardown ─────────────────────────────────────────────────────

# pf setup/teardown:
#   We modify /etc/pf.conf to add explicit rdr-anchor and anchor references for
#   our "wifi_splitter" anchor.  The com.apple/* wildcard approach does NOT work
#   because /etc/pf.anchors/com.apple only lists specific sub-anchors and has no
#   rdr-anchor "*" to cascade to dynamically created children.
#
#   System services like Internet Sharing use their own top-level anchor lines
#   (e.g. rdr-anchor "com.apple.internet-sharing") — we follow the same pattern.
#
#   On teardown we flush the anchor and restore the original /etc/pf.conf.

PF_CONF      = "/etc/pf.conf"
_saved_pfconf = ""

_RDR_ANCHOR_LINE    = f'rdr-anchor "{ANCHOR}"'
_FILTER_ANCHOR_LINE = f'anchor "{ANCHOR}"'

def _build_anchor_rules():
    rules = (
        # Port 443/80 → PROXY_PORT (connects upstream on same port via SNI/HTTP)
        f"rdr pass log on {BRIDGE_IF} inet proto tcp "
        f"from {BRIDGE_NET} to any port 443 "
        f"-> {BRIDGE_IP} port {PROXY_PORT}\n"
        f"rdr pass log on {BRIDGE_IF} inet proto tcp "
        f"from {BRIDGE_NET} to any port 80 "
        f"-> {BRIDGE_IP} port {PROXY_PORT}\n"
        # Block QUIC so YouTube/apps fall back to TCP
        f"block in quick on {BRIDGE_IF} inet proto udp "
        f"from {BRIDGE_NET} to any port 443\n"
    )
    if PASSTHRU_PORTS:
        passthru_ports = " ".join(str(p) for p in PASSTHRU_PORTS)
        rules += (
            f"rdr pass log on {BRIDGE_IF} inet proto tcp "
            f"from {BRIDGE_NET} to any port {{ {passthru_ports} }} "
            f"-> {BRIDGE_IP} port {PROXY_PORT_PASSTHRU}\n"
        )
    return rules

_ANCHOR_RULES = _build_anchor_rules()

def _setup_pf():
    global _saved_pfconf

    subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                   capture_output=True, check=False)

    # Load our rules into the anchor first
    r = subprocess.run(["pfctl", "-a", ANCHOR, "-f", "-"],
                       input=_ANCHOR_RULES.encode(), capture_output=True)
    if r.returncode != 0 and b"not loaded" in r.stderr:
        print("[x] Failed to load anchor rules:", r.stderr.decode())
        sys.exit(1)

    # Read and patch /etc/pf.conf to add our anchor references
    with open(PF_CONF, "r") as f:
        _saved_pfconf = f.read()

    if _RDR_ANCHOR_LINE not in _saved_pfconf:
        # Insert rdr-anchor right after the last rdr-anchor line (translation section)
        # Insert anchor right after the last anchor line (filter section)
        # Appending at the end breaks ordering: translation must precede filtering.
        lines = _saved_pfconf.splitlines(keepends=True)
        patched = []
        last_rdr = -1
        last_anchor = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('rdr-anchor '):
                last_rdr = i
            if stripped.startswith('anchor ') and not stripped.startswith('anchor "com.apple'):
                # don't update — we want last com.apple anchor
                pass
            if stripped.startswith('anchor '):
                last_anchor = i

        # Rebuild, inserting our lines at the right positions
        rdr_inserted = False
        anchor_inserted = False
        for i, line in enumerate(lines):
            patched.append(line)
            if i == last_rdr and not rdr_inserted:
                patched.append(f"{_RDR_ANCHOR_LINE}\n")
                rdr_inserted = True
            if i == last_anchor and not anchor_inserted:
                patched.append(f"{_FILTER_ANCHOR_LINE}\n")
                anchor_inserted = True

        with open(PF_CONF, "w") as f:
            f.writelines(patched)

    # Reload pf from the updated pf.conf
    r = subprocess.run(["pfctl", "-f", PF_CONF], capture_output=True)
    if r.returncode != 0:
        stderr = r.stderr.decode()
        if "not loaded" in stderr:
            print("[x] pfctl -f failed:", stderr)
            # Restore pf.conf before exiting
            with open(PF_CONF, "w") as f:
                f.write(_saved_pfconf)
            sys.exit(1)

    subprocess.run(["pfctl", "-e"], capture_output=True)
    print(f"[+] pf rules active (anchor: {ANCHOR})")

def _teardown_pf():
    global _saved_pfconf
    # Flush our anchor rules
    subprocess.run(["pfctl", "-a", ANCHOR, "-F", "all"], capture_output=True)
    # Restore original /etc/pf.conf
    if _saved_pfconf:
        with open(PF_CONF, "w") as f:
            f.write(_saved_pfconf)
        subprocess.run(["pfctl", "-f", PF_CONF], capture_output=True)
    print("[+] pf rules restored")

# ─── Connection counter ───────────────────────────────────────────────────────

_conn_lock   = threading.Lock()
_active_conn = 0

def _conn_inc():
    global _active_conn
    with _conn_lock:
        _active_conn += 1

def _conn_dec():
    global _active_conn
    with _conn_lock:
        _active_conn -= 1

def _handle_counted(client, upstream_port=443):
    _conn_inc()
    try:
        _handle(client, upstream_port)
    finally:
        _conn_dec()

# ─── Monitor thread ───────────────────────────────────────────────────────────

def _warp_status():
    """Return a short WARP status string."""
    if not os.path.exists(WARP_CLI):
        return "warp-cli not found"
    try:
        r = subprocess.run([WARP_CLI, "status"], capture_output=True, timeout=5)
        out = r.stdout.decode(errors="replace").strip()
        # First non-empty line is usually "Status update: Connected" etc.
        first = next((l for l in out.splitlines() if l.strip()), out)
        return first.strip()
    except Exception as e:
        return f"error: {e}"

def _iphone_ip():
    """Return iPhone's IP on bridge100, or None."""
    try:
        r = subprocess.run(["arp", "-an"], capture_output=True, timeout=5)
        for line in r.stdout.decode(errors="replace").splitlines():
            if "bridge100" in line or "192.168.2." in line:
                import re
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                if m and not m.group(1).endswith(".1"):
                    return m.group(1)
    except Exception:
        pass
    return None

def _bridge_up():
    try:
        r = subprocess.run(["ifconfig", BRIDGE_IF], capture_output=True, timeout=5)
        return r.returncode == 0 and b"flags=" in r.stdout
    except Exception:
        return False

def _monitor_loop():
    """Print a status line every MONITOR_SECS seconds."""
    while True:
        time.sleep(MONITOR_SECS)
        warp  = _warp_status()
        conns = _active_conn
        bridge = "UP" if _bridge_up() else "DOWN"
        iphone = _iphone_ip() or "not seen"
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] WARP: {warp} | proxied: {_total_conn} | dropped: {_dropped_conn} | active: {conns} | iPhone: {iphone}")

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global _verbose
    import argparse
    parser = argparse.ArgumentParser(
        description="Transparent WARP proxy for wifi-splitter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  Example: sudo bash wifi-splitter.sh tproxy -v -s"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log every proxied connection")
    parser.add_argument("-s", "--status", action="store_true",
                        help=f"print a status line every {MONITOR_SECS}s")
    args = parser.parse_args()
    _verbose = args.verbose

    if os.getuid() != 0:
        print("[x] Run as root:  sudo python3 tproxy.py")
        sys.exit(1)

    _open_pf()
    _setup_pf()

    def _make_server(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(256)
        return s

    server = _make_server(PROXY_PORT)  # port 443/80 → upstream same port

    # Map: listen socket → upstream port to use
    server_port_map = {server: 443}

    if PASSTHRU_PORTS:
        server_passthru = _make_server(PROXY_PORT_PASSTHRU)
        server_port_map[server_passthru] = PASSTHRU_PORTS[0]
    else:
        server_passthru = None

    def _shutdown(sig, frame):
        print("\n[+] Shutting down...")
        _teardown_pf()
        server.close()
        if server_passthru:
            server_passthru.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if not _bridge_up():
        print("[!] Warning: bridge100 is not up — run 'sudo bash wifi-splitter.sh start' first")
    print(f"[+] Proxy running — Ctrl-C to stop")
    print(f"    Options: -v (log connections)  -s (status every {MONITOR_SECS}s)  --help")
    print()

    if args.status:
        threading.Thread(target=_monitor_loop, daemon=True).start()

    servers = list(server_port_map.keys())
    while True:
        try:
            readable, _, _ = select.select(servers, [], [], 1.0)
            for srv in readable:
                client, _ = srv.accept()
                upstream_port = server_port_map[srv]
                threading.Thread(
                    target=_handle_counted, args=(client, upstream_port), daemon=True
                ).start()
        except OSError:
            break

if __name__ == "__main__":
    main()
