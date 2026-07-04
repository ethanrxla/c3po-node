package main

import (
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Connection struct {
	Process string `json:"process"`
	CmdLine string `json:"cmdline,omitempty"`
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	State   string `json:"state"`
}

func runNetMon() {
	ticker := time.NewTicker(90 * time.Second)
	for range ticker.C {
		conns := captureConnections()
		if len(conns) > 0 {
			sendNetMon(conns)
		}
	}
}

func captureConnections() []Connection {
	if runtime.GOOS == "windows" {
		return captureWindows()
	}
	return captureLinux()
}

func captureLinux() []Connection {
	out, err := exec.Command("ss", "-tulnp").Output()
	if err != nil {
		return nil
	}
	var conns []Connection
	for _, line := range strings.Split(string(out), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		remote := ""
		if len(f) > 5 {
			remote = f[5]
		}
		conns = append(conns, Connection{
			Proto:  f[0],
			State:  f[1],
			Local:  f[4],
			Remote: remote,
		})
	}
	return conns
}
