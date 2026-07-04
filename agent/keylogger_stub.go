//go:build !windows

package main

// runKeylogger is a no-op on non-Windows platforms.
func runKeylogger() {}
