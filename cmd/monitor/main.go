// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// monitor
package main

import (
	_ "embed"
	"flag"
	"io/ioutil"
	"os"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

//go:embed shard1.json
var shard1Gen []byte

func main() {
	var (
		verbosity = flag.Int("verbosity", int(log.LvlInfo), "log verbosity (0-5)")
		vmodule   = flag.String("vmodule", "", "log verbosity pattern")
		init      = flag.Bool("init", false, "init the first shard")
		nodeKey   = flag.Bool("nodekey", false, "gen nodekey(node.key)")
		cfg       = flag.Bool("conf", false, "dump config file")
		err       error
	)
	flag.Parse()

	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	glogger.Vmodule(*vmodule)
	log.Root().SetHandler(glogger)

	var exit bool
	if *init {
		fn := "./shard1_gen.json"
		err = ioutil.WriteFile(fn, shard1Gen, 0600)
		if err != nil {
			utils.Fatalf("fail to dump genesis file,file name:%s, %v", fn, err)
		}

		err := initShard(1, fn)
		if err != nil {
			utils.Fatalf("fail to init shard1, %v", err)
		}
		exit = true
	}
	if *nodeKey {
		nodeKey, err := crypto.GenerateKey()
		if err != nil {
			utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA("node.key", nodeKey); err != nil {
			utils.Fatalf("%v", err)
		}
		exit = true
	}
	if *cfg {
		fn := "./conf.json"
		err = ioutil.WriteFile(fn, confData, 0600)
		if err != nil {
			utils.Fatalf("fail to dump config file,file name:%s, %v", fn, err)
		}
		exit = true
	}
	if exit {
		return
	}
	LoadConfig("./conf.json")

	mgr := NewShardManager(conf)
	defer mgr.Stop()
	listener, _, err := rpc.StartIPCEndpoint(conf.IPCEndpoint(), []rpc.API{{
		Namespace: "proxy",
		Version:   "1.0",
		Service:   NewAPI(conf),
		Public:    false,
	}, {
		Namespace: "shards",
		Version:   "1.0",
		Service:   mgr,
		Public:    false,
	}})
	if err != nil {
		utils.Fatalf("StartIPCEndpoint: %v", err)
	}
	log.Info("start monitor", "IPC", conf.IPCEndpoint())
	defer func() {
		listener.Close()
		log.Info("IPC endpoint closed", "url")
	}()

	select {}
}
