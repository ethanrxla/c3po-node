//go:build !windows

package main

func clearLogs() string    { return "not supported on this platform" }
func selfDestruct() string  { return "not supported on this platform" }
func enablePPL() string     { return "not supported on this platform" }
func armBYOVD() string      { return "not supported on this platform" }
