//go:build !windows

package main

import "fmt"

func injectIntoProcess(pid uint32, sc []byte) error {
	return fmt.Errorf("inject not supported on %s", "non-windows")
}

func hollowProcess(targetExe string, sc []byte) error {
	return fmt.Errorf("process hollowing not supported on %s", "non-windows")
}

func handleInject(payload string) (string, error) {
	return "", fmt.Errorf("inject not supported on non-windows")
}
