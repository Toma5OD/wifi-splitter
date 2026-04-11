# wifi-splitter

> **Status: Working** — tested on macOS 26 (Darwin 25.x), WARP connected, iPhone over USB. YouTube, WhatsApp, Instagram confirmed working. Snapchat media loads slowly — see [Known Limitations](#known-limitations).

Share a Mac's Cloudflare WARP-protected internet connection to an iPhone over USB — without the ship (or any captive portal) detecting a second device.

## The problem

Some WiFi networks (hotels, ships, venues) restrict internet access — blocking certain sites, throttling, or limiting to one active device per plan. Cloudflare WARP on the Mac tunnels all traffic through Cloudflare, bypassing those restrictions.

The problem is sharing that protected connection to an iPhone. macOS Internet Sharing does NAT the iPhone's traffic through the Mac (the network always sees only **one device** — the Mac's IP), but it sends the iPhone's traffic out through the Mac's normal WiFi connection, **bypassing WARP entirely**. That means the iPhone's traffic hits the network's content filter unencrypted and unprotected — subject to the same blocks and restrictions as if the iPhone were connected directly.

This proxy fixes that: all iPhone TCP is intercepted before it leaves the Mac and routed through WARP, so everything exits as an encrypted Cloudflare tunnel regardless of which device it came from.

## How it works

```
iPhone (USB)
    │
    ▼
bridge100 (192.168.2.x)
    │  pf intercepts all TCP
    ▼
tproxy.py (transparent proxy on Mac)
    │  Mac process → captured by WARP
    ▼
Cloudflare WARP (utun)
    │
    ▼
Cloudflare → internet
```

1. **Internet Sharing** (macOS built-in) gives the iPhone an IP over USB (`bridge100`, `192.168.2.2`). No WiFi needed on the iPhone.
2. **pf rules** intercept all TCP from `bridge100` before it reaches the Internet Sharing NAT, and redirect it to a local proxy port.
3. **tproxy.py** accepts those connections, extracts the original destination via TLS SNI inspection, and opens the upstream connection as a normal Mac process — which Cloudflare WARP tunnels automatically.
4. The network sees one device (the Mac's IP) and one type of traffic: an encrypted Cloudflare tunnel.

QUIC/UDP-443 is blocked at the pf layer so apps (YouTube, etc.) fall back to TCP HTTP/2, which the proxy can handle.

## Requirements

Before starting, make sure:

1. **Cloudflare WARP is connected** on the Mac ([1.1.1.1 app](https://1.1.1.1/)) — check the menu bar icon shows "Connected"
2. **iPhone WiFi is OFF** — the iPhone must not be on the same network as the Mac; all traffic goes over the USB cable
3. **USB cable is plugged in** (USB-C to USB-C or Lightning to USB-C) and iPhone shows "Trust" prompt → tap Trust
4. **Internet Sharing is enabled** on the Mac: System Settings → General → Sharing → Internet Sharing  
   - Share from: your WiFi interface (e.g. en0)  
   - To devices using: iPhone USB

> **WiFi OFF is important.** If iPhone WiFi is on and connected to the same network, its traffic won't go through the Mac proxy — turn it off so the USB cable is the only path.

- macOS (tested on macOS 26 / Darwin 25.x)
  - To devices using: iPhone USB

## Usage

**Terminal 1** — start Internet Sharing (gives iPhone its IP):
```bash
sudo bash wifi-splitter.sh start
```

**Terminal 2** — start the transparent proxy (keep running):
```bash
sudo bash wifi-splitter.sh tproxy
```

That's it. iPhone WiFi can stay **OFF**. All traffic routes through WARP.

### wifi-splitter.sh commands

```bash
sudo bash wifi-splitter.sh start    # enable Internet Sharing (gives iPhone an IP)
sudo bash wifi-splitter.sh tproxy   # start the transparent proxy
sudo bash wifi-splitter.sh stop     # stop Internet Sharing
sudo bash wifi-splitter.sh status   # check service + WARP state
sudo bash wifi-splitter.sh config   # show SSID/password config
```

### tproxy options

By default tproxy runs silently. Pass flags after `tproxy` to enable output:

```bash
sudo bash wifi-splitter.sh tproxy -v      # log every proxied connection
sudo bash wifi-splitter.sh tproxy -s      # print a status line every 30s
sudo bash wifi-splitter.sh tproxy -v -s   # both
```

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Print each connection as it's proxied, e.g. `192.168.2.2:61234 → api.instagram.com:443` |
| `-s`, `--status` | Print a summary line every 30s: WARP state, total proxied, dropped, active connections, iPhone IP |

Status line example:
```
[21:30:00] WARP: Status update: Connected | proxied: 847 | dropped: 12 | active: 3 | iPhone: 192.168.2.2
```

## Files

| File | Purpose |
|------|---------|
| `wifi-splitter.sh` | Main script — start/stop Internet Sharing, launch proxy, status |
| `tproxy.py` | Transparent TCP proxy — pf setup, TLS SNI inspection, WARP routing |
| `proxy.py` | HTTP/HTTPS proxy (manual iPhone config) — alternative if transparent proxy is unavailable |

## Troubleshooting

**WARP shows CF_DNS_PROXY_FAILURE**  
Chrome's built-in Secure DNS is intercepting DNS queries. Fix:  
Chrome → Settings → Privacy & Security → Security → Use secure DNS → **OFF**  
Then reconnect WARP.

**iPhone has no internet after running tproxy**  
1. Check WARP is connected: `warp-cli status`
2. Check Internet Sharing is active: `sudo bash wifi-splitter.sh status`
3. Check bridge100 exists: `ifconfig bridge100`
4. Restart: Ctrl-C tproxy, then `sudo bash wifi-splitter.sh tproxy` again

**"pf rules active" but no connections proxied**  
Run `sudo tcpdump -ni pflog0 -c 5` while loading a page on iPhone — you should see packets going to `192.168.2.1:9999`. If nothing appears, Internet Sharing may have reloaded pf and removed our anchor. Restart tproxy.

## Known Limitations

### Snapchat media loads slowly

Snapchat images and video load noticeably slower through this proxy than when using WARP natively on the iPhone. This is a fundamental architectural constraint, not a bug.

**Why YouTube is fine but Snapchat isn't:**

YouTube streams a video as one long-lived TCP connection — the proxy relays a continuous byte stream with minimal overhead.

Snapchat loads a story as 50–100 parallel small HTTP/2 requests, each to a CDN chunk. Every one of those requests requires its own:
1. TCP connection accepted by the proxy
2. TLS ClientHello parsed to extract the destination hostname (SNI)
3. New upstream TCP connection opened through WARP
4. Data relayed through Python's socket layer in both directions

That per-connection overhead multiplied across 100 parallel chunks is what makes Snapchat feel slow.

**Why it can't be fixed in the proxy:**

To restructure Snapchat's many requests into fewer connections you'd need to intercept the HTTPS content — which means doing a TLS man-in-the-middle attack on your own iPhone. The iPhone would reject the connection immediately because the proxy's certificate isn't trusted by Apple. We can only forward raw bytes; we cannot read or repackage what's inside TLS.

Bypassing the proxy for Snapchat CDN traffic (routing it direct through Internet Sharing's NAT, outside WARP) was tested and made things worse — the ship network interferes with unencrypted Snapchat CDN traffic.

**The root cause** is that native WARP on the iPhone uses a kernel-level WireGuard tunnel optimised for throughput. This proxy is an additional userspace Python relay layered on top of WARP, and every byte passes through it.

## Notes

- DIOCNATLOOK (the pf state table ioctl) is not supported on macOS 26 (`ENOTSUP`). TLS SNI inspection is used instead and covers ~99% of iPhone traffic.
- The proxy binds to `192.168.2.1:9999` (bridge100's IP), not localhost, because macOS pf cannot redirect forwarded packets to the loopback address.
- `/etc/pf.conf` is temporarily modified to add `rdr-anchor "wifi_splitter"` and `anchor "wifi_splitter"` entries. It is restored to its original state when tproxy exits (Ctrl-C).
