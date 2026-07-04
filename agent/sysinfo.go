package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type SystemInfo struct {
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	OSVersion string `json:"os_version"`
	CPUs      int    `json:"cpus"`
	LocalIPs  string `json:"local_ips"`
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	username := getUsername()
	osVersion := getOSVersion()
	ips := getLocalIPs()

	return SystemInfo{
		Hostname:  hostname,
		Username:  username,
		OSVersion: osVersion,
		CPUs:      runtime.NumCPU(),
		LocalIPs:  ips,
	}
}

func getUsername() string {
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func getOSVersion() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "ver")
		hideWindow(cmd)
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	out, err := exec.Command("uname", "-sr").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOOS
}

func getLocalIPs() string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'} | Select-Object -ExpandProperty IPAddress) -join ','")
		hideWindow(cmd)
	} else {
		cmd = exec.Command("hostname", "-I")
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
