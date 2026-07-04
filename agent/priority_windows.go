//go:build windows

package main

import "golang.org/x/sys/windows"

func setSelfPriority() {
	h, err := windows.GetCurrentProcess()
	if err == nil {
		windows.SetPriorityClass(h, windows.BELOW_NORMAL_PRIORITY_CLASS)
	}
}
