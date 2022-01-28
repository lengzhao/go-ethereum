package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"runtime"
	"strings"
)

type Config struct {
	IPCPath          string            `json:"ipc_path,omitempty"`
	AddressRoot      string            `json:"address_root,omitempty"`
	Nodes            map[uint64]string `json:"nodes,omitempty"`
	ShardCommand     string            `json:"shard_command,omitempty"`
	CommandParams    map[string]string `json:"command_params,omitempty"`
	ShardRestartTime int64             `json:"shard_restart_time,omitempty"`
	Bootnodes        []string          `json:"bootnodes,omitempty"`
}

var conf Config

//go:embed default_conf.json
var confData []byte

func init() {
	json.Unmarshal(confData, &conf)
	if runtime.GOOS == "windows" {
		conf.AddressRoot = `\\.\pipe\` + "phenix%d.ipc"
	} else {
		conf.AddressRoot = "./shard%d/phenix%d.ipc"
	}
}

func LoadConfig(fn string) error {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		log.Println("fail to Unmarshal config:", fn, err)
		return err
	}
	return nil
}

func (c *Config) IPCEndpoint() string {
	// Short circuit if IPC has not been enabled
	if c.IPCPath == "" {
		return ""
	}
	// On windows we can only use plain top-level pipes
	if runtime.GOOS == "windows" {
		if strings.HasPrefix(c.IPCPath, `\\.\pipe\`) {
			return c.IPCPath
		}
		return `\\.\pipe\` + c.IPCPath
	}
	return c.IPCPath
}

func (c *Config) GetAddress(shardID *big.Int) string {
	count := strings.Count(c.AddressRoot, "%")
	switch count {
	case 1:
		return fmt.Sprintf(c.AddressRoot, shardID.Uint64())
	case 2:
		return fmt.Sprintf(c.AddressRoot, shardID.Uint64(), shardID.Uint64())
	default:
		return c.AddressRoot
	}
}
