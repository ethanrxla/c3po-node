//go:build !windows

package main

func installPersistence() {}
func isPersisted() bool   { return false }
func removePersistence()  {}
