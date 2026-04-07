#!/usr/bin/env python3
"""
proxy.py — HTTP/HTTPS proxy for wifi-splitter
Runs on the Mac so traffic goes through Cloudflare WARP before hitting the internet.

iPhone setup (do once per network):
  Settings → Wi-Fi → tap (i) next to ShipShare → Configure Proxy → Manual
    Server: 192.168.2.1
    Port:   8080
    (leave Authentication off)
"""

import socket
import threading
import select
import sys
import signal

LISTEN_HOST = "0.0.0.0"   # listen on all interfaces (bridge100 = 192.168.2.1)
LISTEN_PORT = 8080
BUFFER      = 65536
TIMEOUT     = 30

def relay(src, dst):
    """Bidirectional relay between two sockets until one closes."""
    src.setblocking(False)
    dst.setblocking(False)
    sockets = [src, dst]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, TIMEOUT)
            if exceptional or not readable:
                break
            for sock in readable:
                other = dst if sock is src else src
                try:
                    data = sock.recv(BUFFER)
                    if not data:
                        return
                    other.sendall(data)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    return
    except Exception:
        pass

def handle_connect(client: socket.socket, host: str, port: int):
    """HTTPS tunnel: CONNECT method."""
    try:
        upstream = socket.create_connection((host, port), timeout=TIMEOUT)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        relay(client, upstream)
    except Exception as e:
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        except Exception:
            pass
    finally:
        for s in (client,):
            try: s.close()
            except: pass

def handle_http(client: socket.socket, method: str, url: str,
                http_ver: str, headers: dict, body: bytes):
    """Plain HTTP proxy request."""
    from urllib.parse import urlparse
    parsed  = urlparse(url)
    host    = parsed.hostname or ""
    port    = parsed.port or 80
    path    = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

    # Strip hop-by-hop / proxy headers
    skip = {"proxy-connection", "proxy-authorization", "te",
            "trailers", "transfer-encoding", "upgrade"}
    clean = {k: v for k, v in headers.items() if k.lower() not in skip}

    request = f"{method} {path} {http_ver}\r\n"
    request += "".join(f"{k}: {v}\r\n" for k, v in clean.items())
    request += "\r\n"

    try:
        upstream = socket.create_connection((host, port), timeout=TIMEOUT)
        upstream.sendall(request.encode("latin-1"))
        if body:
            upstream.sendall(body)
        relay(client, upstream)
    except Exception:
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            )
        except Exception:
            pass
    finally:
        try: client.close()
        except: pass

def parse_request(client: socket.socket):
    """Read and parse the HTTP request line + headers."""
    raw = b""
    client.settimeout(TIMEOUT)
    try:
        while b"\r\n\r\n" not in raw:
            chunk = client.recv(4096)
            if not chunk:
                return None
            raw += chunk
            if len(raw) > 1024 * 64:   # 64 KB header limit
                return None
    except socket.timeout:
        return None

    header_block, _, body = raw.partition(b"\r\n\r\n")
    lines = header_block.decode("utf-8", errors="replace").split("\r\n")
    if not lines:
        return None

    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return None

    method   = parts[0]
    url      = parts[1]
    http_ver = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            k, _, v = line.partition(": ")
            headers[k.strip()] = v.strip()

    return method, url, http_ver, headers, body

def handle_client(client: socket.socket):
    try:
        result = parse_request(client)
        if result is None:
            return
        method, url, http_ver, headers, body = result

        if method == "CONNECT":
            host, _, port_str = url.partition(":")
            port = int(port_str) if port_str.isdigit() else 443
            handle_connect(client, host, port)
        else:
            handle_http(client, method, url, http_ver, headers, body)
    except Exception:
        pass
    finally:
        try: client.close()
        except: pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as e:
        print(f"[x] Cannot bind to port {LISTEN_PORT}: {e}")
        print(f"    Is another process using port {LISTEN_PORT}?  lsof -i :{LISTEN_PORT}")
        sys.exit(1)

    server.listen(128)

    # Graceful shutdown on Ctrl-C
    def shutdown(sig, frame):
        print("\n[+] Proxy stopped.")
        server.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[+] Proxy running on {LISTEN_HOST}:{LISTEN_PORT}")
    print()
    print("    On your iPhone:")
    print("    Settings → Wi-Fi → tap (i) next to ShipShare")
    print("    → Configure Proxy → Manual")
    print(f"      Server:  192.168.2.1")
    print(f"      Port:    {LISTEN_PORT}")
    print()
    print("    Press Ctrl-C to stop.")
    print()

    while True:
        try:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
        except OSError:
            break

if __name__ == "__main__":
    main()
