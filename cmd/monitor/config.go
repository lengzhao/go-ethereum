package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Config struct {
	DataDir          string            `json:"data_dir,omitempty"`
	IPCPath          string            `json:"ipc_path,omitempty"`
	AddressRoot      string            `json:"address_root,omitempty"`
	Nodes            map[uint64]string `json:"nodes,omitempty"`
	ShardCommand     string            `json:"shard_command,omitempty"`
	Shards           []uint64          `json:"shards,omitempty"`
	CommandParams    map[string]string `json:"command_params,omitempty"`
	ShardRestartTime int64             `json:"shard_restart_time,omitempty"`
}

var conf Config

func init() {
	// conf.AddressRoot = "./shard_%d/geth/geth.ipc"
	conf.AddressRoot = `\\.\pipe\` + "phenix%d.ipc"
	conf.IPCPath = "phenix_proxy.ipc"
	conf.DataDir = "./"
	conf.Shards = []uint64{1}
	conf.ShardCommand = "./geth"
	LoadConfig("./conf.json")
}

func LoadConfig(fn string) error {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Println("fail to load config:", fn, err)
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
	// Resolve names into the data directory full paths otherwise
	if filepath.Base(c.IPCPath) == c.IPCPath {
		if c.DataDir == "" {
			return filepath.Join(os.TempDir(), c.IPCPath)
		}
		return filepath.Join(c.DataDir, c.IPCPath)
	}
	return c.IPCPath
}

func (c *Config) GetAddress(shardID *big.Int) string {
	return fmt.Sprintf(c.AddressRoot, shardID.Uint64())
}
