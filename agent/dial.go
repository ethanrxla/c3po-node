package main

import (
	"net"
	"time"
)

func newDialer(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}
