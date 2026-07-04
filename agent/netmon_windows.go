//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")

	procQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
)

// TCP states from MIB_TCP_STATE
var tcpStateNames = map[uint32]string{
	1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived",
	5: "Established", 6: "FinWait1", 7: "FinWait2", 8: "CloseWait",
	9: "Closing", 10: "LastAck", 11: "TimeWait", 12: "DeleteTcb",
}

const (
	tcpTableOwnerPIDAll = 5
	afInet              = 2
)

// captureWindows uses iphlpapi + psapi directly — no PowerShell subprocess.
func captureWindows() []Connection {
	pidNames := buildPIDNameMap()
	return getTCPConnections(pidNames)
}

// buildPIDNameMap enumerates all processes and maps PID → short name.
func buildPIDNameMap() map[uint32]string {
	m := make(map[uint32]string)
	pids := make([]uint32, 1024)
	var needed uint32
	err := windows.EnumProcesses(pids, &needed)
	if err != nil {
		return m
	}
	count := needed / 4
	if count > uint32(len(pids)) {
		count = uint32(len(pids))
	}
	for _, pid := range pids[:count] {
		if pid == 0 {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}
		buf := make([]uint16, 260)
		size := uint32(len(buf))
		r, _, _ := procQueryFullProcessImageName.Call(
			uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		windows.CloseHandle(h)
		if r == 0 {
			continue
		}
		full := windows.UTF16ToString(buf[:size])
		// Extract just the base name (last path segment without .exe)
		name := full
		for i := len(full) - 1; i >= 0; i-- {
			if full[i] == '\\' || full[i] == '/' {
				name = full[i+1:]
				break
			}
		}
		// Strip .exe suffix
		if len(name) > 4 && name[len(name)-4:] == ".exe" {
			name = name[:len(name)-4]
		}
		m[pid] = name
	}
	return m
}

// getTCPConnections reads the extended TCP table and returns Connection entries.
func getTCPConnections(pidNames map[uint32]string) []Connection {
	// First call: get required buffer size
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1,
		afInet, tcpTableOwnerPIDAll, 0)
	if size == 0 {
		size = 65536
	}

	buf := make([]byte, size*2) // double to be safe
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, afInet, tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return nil
	}

	// Layout: uint32 numEntries, then numEntries × 24-byte rows
	// Each row: state(4) localAddr(4) localPort(4) remoteAddr(4) remotePort(4) owningPid(4)
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	var conns []Connection
	offset := uint32(4)
	rowSize := uint32(24)
	for i := uint32(0); i < numEntries && offset+rowSize <= uint32(len(buf)); i++ {
		row := buf[offset : offset+rowSize]
		state := binary.LittleEndian.Uint32(row[0:4])
		localAddr := net.IP(row[4:8])
		localPort := binary.BigEndian.Uint16(row[8:10])
		remoteAddr := net.IP(row[12:16])
		remotePort := binary.BigEndian.Uint16(row[16:18])
		owningPID := binary.LittleEndian.Uint32(row[20:24])
		offset += rowSize

		stateName := tcpStateNames[state]
		if stateName == "" {
			stateName = fmt.Sprintf("State%d", state)
		}

		procName := pidNames[owningPID]
		if procName == "" {
			procName = fmt.Sprintf("pid%d", owningPID)
		}

		conns = append(conns, Connection{
			Process: procName,
			Proto:   "TCP",
			Local:   fmt.Sprintf("%s:%d", localAddr, localPort),
			Remote:  fmt.Sprintf("%s:%d", remoteAddr, remotePort),
			State:   stateName,
		})
	}
	return conns
}
