//go:build !windows || !miner

package main

import "fmt"

type MinerConfig struct {
	Coin    string `json:"coin"`
	Wallet  string `json:"wallet"`
	Pool    string `json:"pool"`
	CPUCap  int    `json:"cpu_cap"`
	GPU     bool   `json:"gpu"`
	IdleOnly bool  `json:"idle_only"`
}

func startMiner(cfg MinerConfig) (string, error) {
	return "", fmt.Errorf("mining not supported on non-windows")
}

func stopMiner() string          { return "not supported" }
func getMinerStatus() string     { return `{"running":false}` }
func sendMinerStats()            {}
func detectMinerHardware() (string, string) { return "", "" }
