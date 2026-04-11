// tproxy.go — Transparent TCP proxy for wifi-splitter (Go implementation)
//
// Functionally identical to tproxy.py but uses goroutines + io.Copy instead
// of Python threads + select loops. Goroutines are ~2KB vs ~8MB for OS
// threads, and io.Copy is a heavily optimised runtime call with no GIL.
// For apps that open 50-100 parallel CDN connections (Snapchat) the
// per-connection overhead is dramatically lower.
//
// Build: go build -o tproxy-go tproxy.go
// Run:   sudo bash wifi-splitter.sh tproxy -go [-v] [-s]

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── Config ───────────────────────────────────────────────────────────────────

const (
	bridgeIF    = "bridge100"
	bridgeNet   = "192.168.2.0/24"
	bridgeIP    = "192.168.2.1"
	proxyPort   = 9999
	anchor      = "wifi_splitter"
	monitorSecs = 30
	warpCLI     = "/usr/local/bin/warp-cli"
	pfConfPath  = "/etc/pf.conf"
	relayBuf    = 256 * 1024 // 256 KB relay buffer per direction
)

var dialTimeout = 30 * time.Second

// ─── Counters and flags ───────────────────────────────────────────────────────

var (
	totalConn   int64
	droppedConn int64
	activeConn  int64
	verbose     bool
)

// ─── pf setup / teardown ─────────────────────────────────────────────────────

var savedPFConf string

func anchorRules() string {
	return fmt.Sprintf(
		"rdr pass log on %s inet proto tcp from %s to any port 443 -> %s port %d\n"+
			"rdr pass log on %s inet proto tcp from %s to any port 80  -> %s port %d\n"+
			"block in quick on %s inet proto udp from %s to any port 443\n",
		bridgeIF, bridgeNet, bridgeIP, proxyPort,
		bridgeIF, bridgeNet, bridgeIP, proxyPort,
		bridgeIF, bridgeNet,
	)
}

func setupPF() error {
	exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()

	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(anchorRules())
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "not loaded") {
		return fmt.Errorf("failed to load anchor rules: %s", out)
	}

	data, err := os.ReadFile(pfConfPath)
	if err != nil {
		return err
	}
	savedPFConf = string(data)

	rdrLine := fmt.Sprintf(`rdr-anchor "%s"`, anchor)
	filterLine := fmt.Sprintf(`anchor "%s"`, anchor)

	if !strings.Contains(savedPFConf, rdrLine) {
		patched := insertAfterLast(savedPFConf, "rdr-anchor ", rdrLine)
		patched = insertAfterLast(patched, "anchor ", filterLine)
		if err := os.WriteFile(pfConfPath, []byte(patched), 0644); err != nil {
			return err
		}
	}

	exec.Command("pfctl", "-f", pfConfPath).Run()
	exec.Command("pfctl", "-e").Run()
	fmt.Printf("[+] pf rules active (anchor: %s)\n", anchor)
	return nil
}

func teardownPF() {
	stopBridgeSniffer()
	exec.Command("pfctl", "-a", anchor, "-F", "all").Run()
	if savedPFConf != "" {
		os.WriteFile(pfConfPath, []byte(savedPFConf), 0644)
		exec.Command("pfctl", "-f", pfConfPath).Run()
	}
	fmt.Println("[+] pf rules restored")
}

// insertAfterLast inserts newLine immediately after the last line whose
// trimmed content starts with prefix.
func insertAfterLast(text, prefix, newLine string) string {
	lines := strings.Split(text, "\n")
	last := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			last = i
		}
	}
	if last < 0 {
		return text + newLine + "\n"
	}
	out := make([]string, 0, len(lines)+1)
	for i, l := range lines {
		out = append(out, l)
		if i == last {
			out = append(out, newLine)
		}
	}
	return strings.Join(out, "\n")
}

// ─── Bridge100 SYN sniffer ────────────────────────────────────────────────────
//
// tcpdump on bridge100 captures SYN packets BEFORE pf redirects them, so we
// see the original destination IP. Used to route ECH / no-SNI TLS connections
// (e.g. WhatsApp MQTT, Instagram) where SNI is unreadable.

var (
	pfDstCache sync.Map // "srcIP:srcPort" → "dstIP:dstPort"
	snifferCmd *exec.Cmd
	snifferMu  sync.Mutex
)

var synPat = regexp.MustCompile(
	`IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)`,
)

func startBridgeSniffer() {
	snifferMu.Lock()
	defer snifferMu.Unlock()
	if snifferCmd != nil {
		return
	}
	cmd := exec.Command("tcpdump", "-ni", bridgeIF, "-l",
		"tcp[tcpflags] == tcp-syn and src net "+bridgeNet)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return
	}
	snifferCmd = cmd
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			m := synPat.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			pfDstCache.Store(m[1]+":"+m[2], m[3]+":"+m[4])
		}
	}()
}

func stopBridgeSniffer() {
	snifferMu.Lock()
	defer snifferMu.Unlock()
	if snifferCmd != nil && snifferCmd.Process != nil {
		snifferCmd.Process.Kill()
		snifferCmd = nil
	}
}

// dstFromSniffer looks up the original destination for a connection using the
// SYN capture cache. Retries briefly to handle processing lag.
func dstFromSniffer(remoteAddr string) (string, int, bool) {
	for i := 0; i < 5; i++ {
		if v, ok := pfDstCache.Load(remoteAddr); ok {
			h, p, err := net.SplitHostPort(v.(string))
			if err == nil {
				port, _ := strconv.Atoi(p)
				return h, port, true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", 0, false
}

// ─── TLS SNI parser ───────────────────────────────────────────────────────────

func tlsSNI(data []byte) string {
	if len(data) < 6 || data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}
	pos := 9 // record(5) + handshake_type(1) + length(3)
	if pos+34 > len(data) {
		return ""
	}
	pos += 2 + 32 // client_version(2) + random(32)
	if pos >= len(data) {
		return ""
	}
	pos += 1 + int(data[pos]) // session_id
	if pos+2 > len(data) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + csLen
	if pos+1 > len(data) {
		return ""
	}
	pos += 1 + int(data[pos]) // compression_methods
	if pos+2 > len(data) {
		return ""
	}
	extEnd := pos + 2 + int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	for pos+4 <= extEnd && pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos:])
		extLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if extType == 0 && pos+5 <= len(data) { // SNI extension (type 0)
			nameLen := int(binary.BigEndian.Uint16(data[pos+3:]))
			if pos+5+nameLen <= len(data) {
				return string(data[pos+5 : pos+5+nameLen])
			}
		}
		pos += extLen
	}
	return ""
}

// ─── Protocol destination parser ─────────────────────────────────────────────

// parseDst inspects firstBytes to determine the upstream destination.
// Returns (host, port, connectMode, ok).
// connectMode=true: firstBytes were an HTTP CONNECT header — do NOT forward them.
// connectMode=false: firstBytes are the start of the real stream — MUST forward them.
func parseDst(data []byte, defaultPort int) (host string, port int, connectMode bool, ok bool) {
	if len(data) == 0 {
		return
	}
	if data[0] == 0x16 { // TLS handshake record
		if sni := tlsSNI(data); sni != "" {
			return sni, defaultPort, false, true
		}
		return // ECH / no SNI — caller falls back to sniffer
	}
	// HTTP
	lines := strings.Split(string(data), "\r\n")
	if len(lines) == 0 {
		return
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return
	}
	method, target := parts[0], parts[1]
	if method == "CONNECT" {
		h, p, err := net.SplitHostPort(target)
		if err != nil {
			h, p = target, "443"
		}
		portNum, _ := strconv.Atoi(p)
		return h, portNum, true, true
	}
	for _, l := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			hostVal := strings.TrimSpace(l[5:])
			if h, p, err := net.SplitHostPort(hostVal); err == nil {
				portNum, _ := strconv.Atoi(p)
				return h, portNum, false, true
			}
			return hostVal, 80, false, true
		}
	}
	return
}

// ─── Relay ────────────────────────────────────────────────────────────────────

// relay bidirectionally copies between a and b.
// If prependToUpstream is non-nil, those bytes are sent to b first (before
// reading from a) — used to forward the TLS ClientHello / HTTP request that
// was already read for inspection.
func relay(a, b net.Conn, prependToUpstream []byte) {
	var wg sync.WaitGroup
	wg.Add(2)

	// a → b
	go func() {
		defer wg.Done()
		buf := make([]byte, relayBuf)
		var src io.Reader = a
		if len(prependToUpstream) > 0 {
			src = io.MultiReader(bytes.NewReader(prependToUpstream), a)
		}
		io.CopyBuffer(b, src, buf)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// b → a
	go func() {
		defer wg.Done()
		buf := make([]byte, relayBuf)
		io.CopyBuffer(a, b, buf)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func setKeepalive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// ─── Connection handler ───────────────────────────────────────────────────────

func handle(conn net.Conn, upstreamPort int) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)
	defer conn.Close()

	peer := conn.RemoteAddr().String()

	// Read first bytes for protocol inspection (not a permanent consume —
	// we forward them to the upstream via io.MultiReader in relay).
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		return
	}
	first := buf[:n]

	var dstHost string
	var dstPort int
	var fwdFirst bool // whether first bytes must be forwarded to upstream

	if host, port, connectMode, ok := parseDst(first, upstreamPort); ok {
		dstHost, dstPort = host, port
		fwdFirst = !connectMode
		if verbose {
			fmt.Printf("[~] %s → %s:%d\n", peer, dstHost, dstPort)
		}
	} else {
		// TLS with unreadable SNI (ECH) — look up original IP from sniffer cache
		h, p, found := dstFromSniffer(peer)
		if !found {
			atomic.AddInt64(&droppedConn, 1)
			if verbose {
				fmt.Printf("[!] %s — no destination found; dropping\n", peer)
			}
			return
		}
		dstHost, dstPort = h, p
		fwdFirst = true // ECH ClientHello must reach the real server
		if verbose {
			fmt.Printf("[#] %s → %s:%d (ECH/no-SNI)\n", peer, dstHost, dstPort)
		}
	}

	upstream, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", dstHost, dstPort), dialTimeout)
	if err != nil {
		if verbose {
			fmt.Printf("[!] %s → %s:%d: %v\n", peer, dstHost, dstPort, err)
		}
		return
	}
	defer upstream.Close()

	setKeepalive(conn)
	setKeepalive(upstream)
	atomic.AddInt64(&totalConn, 1)

	if fwdFirst {
		relay(conn, upstream, first)
	} else {
		// CONNECT: respond 200, then relay without the CONNECT header
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		relay(conn, upstream, nil)
	}
}

// ─── WARP / status monitoring ─────────────────────────────────────────────────

func warpStatus() string {
	out, err := exec.Command(warpCLI, "status").Output()
	if err != nil {
		return "unknown"
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	return strings.TrimSpace(parts[0])
}

func iphoneIP() string {
	out, err := exec.Command("arp", "-n", "192.168.2.2").Output()
	if err == nil && strings.Contains(string(out), "192.168.2.2") &&
		!strings.Contains(string(out), "no entry") {
		return "192.168.2.2"
	}
	return "unknown"
}

func bridgeUp() bool {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Name == bridgeIF {
			return true
		}
	}
	return false
}

func monitorLoop() {
	t := time.NewTicker(monitorSecs * time.Second)
	defer t.Stop()
	for range t.C {
		fmt.Printf("[%s] WARP: %s | proxied: %d | dropped: %d | active: %d | iPhone: %s\n",
			time.Now().Format("15:04:05"),
			warpStatus(),
			atomic.LoadInt64(&totalConn),
			atomic.LoadInt64(&droppedConn),
			atomic.LoadInt64(&activeConn),
			iphoneIP(),
		)
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	v := flag.Bool("v", false, "log every connection")
	vl := flag.Bool("verbose", false, "log every connection")
	s := flag.Bool("s", false, fmt.Sprintf("print status every %ds", monitorSecs))
	sl := flag.Bool("status", false, fmt.Sprintf("print status every %ds", monitorSecs))
	flag.Parse()

	verbose = *v || *vl
	showStatus := *s || *sl

	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "[x] Run as root: sudo bash wifi-splitter.sh tproxy -go")
		os.Exit(1)
	}

	if err := setupPF(); err != nil {
		fmt.Fprintln(os.Stderr, "[x]", err)
		os.Exit(1)
	}
	startBridgeSniffer()

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", proxyPort))
	if err != nil {
		fmt.Fprintln(os.Stderr, "[x] listen:", err)
		teardownPF()
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[+] Shutting down...")
		teardownPF()
		ln.Close()
		os.Exit(0)
	}()

	if !bridgeUp() {
		fmt.Printf("[!] Warning: %s not up — run 'sudo bash wifi-splitter.sh start' first\n", bridgeIF)
	}
	fmt.Printf("[+] Proxy running (Go) — Ctrl-C to stop\n")
	fmt.Printf("    Options: -v (log connections)  -s (status every %ds)  --help\n\n", monitorSecs)

	if showStatus {
		go monitorLoop()
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		go handle(conn, 443)
	}
}
