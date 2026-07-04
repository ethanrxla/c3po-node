//go:build !windows

package main

func runShellcode(_ string) error { return nil }
func amsiBypass() error           { return nil }
