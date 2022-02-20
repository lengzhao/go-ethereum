package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/phenix"
	"github.com/ethereum/go-ethereum/log"
)

type ShardManager struct {
	mu          sync.Mutex
	restartTime int64
	shards      map[uint64]*exec.Cmd
	command     string
	param       map[string]string
	stoped      bool
}

//go:embed shard.json.gotmpl
var shardxGen string

func NewShardManager(c Config) *ShardManager {
	var out ShardManager
	out.shards = make(map[uint64]*exec.Cmd)
	out.command = c.ShardCommand
	out.restartTime = c.ShardRestartTime
	if out.restartTime < 5 {
		out.restartTime = 5
	}
	out.param = map[string]string{}
	for k, v := range c.CommandParams {
		out.param[k] = v
	}
	go out.startShard(1)

	return &out
}

func getShardDir(id uint64) string {
	return fmt.Sprintf("shard%d", id)
}

func initShard(id uint64, fn string) error {
	dirName := getShardDir(id)
	cmd := exec.Command(conf.ShardCommand, "init", "--datadir", dirName, fn)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Warn("fail to init shard", "shard", id, "cmd", cmd.String(), "error", err)
		return err
	}
	log.Info("init shard", "id", id, "dir", dirName, "genesis file", fn)
	return nil
}

func (s *ShardManager) startShard(id uint64) error {
	s.mu.Lock()
	_, ok := s.shards[id]
	s.mu.Unlock()
	if ok {
		log.Warn("try to start shard again", "id", id)
		return fmt.Errorf("exist shard:%d", id)
	}
	fn := path.Join(".", fmt.Sprintf("shard%d.log", id))
	var logFile io.Writer
	f, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Warn("fail to open log file:", "file", fn, "error", err)
		logFile = io.Discard
	} else {
		logFile = f
		defer f.Close()
	}
	for {
		params := []string{}
		dir := getShardDir(id)
		params = append(params, "--datadir", dir)
		params = append(params, "--ipcpath", fmt.Sprintf("phenix%d.ipc", id))
		var localParams map[string]string
		data, err := ioutil.ReadFile(path.Join(dir, "conf.json"))
		if err == nil {
			err = json.Unmarshal(data, &localParams)
			if err != nil {
				log.Warn("fail to Unmarshal config of shard:", "id", id, "error", err)
			}
		}
		if len(localParams) == 0 {
			localParams = make(map[string]string)
		}
		for k, v := range s.param {
			if _, ok := localParams[k]; ok {
				continue
			}
			params = append(params, k)
			if v != "" {
				params = append(params, v)
			}
		}
		for k, v := range localParams {
			params = append(params, k)
			if v != "" {
				params = append(params, v)
			}
		}
		cmd := exec.Command(s.command, params...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		s.mu.Lock()
		s.shards[id] = cmd
		s.mu.Unlock()
		log.Info("start shard", "id", id, "cmd", cmd.String())
		err = cmd.Run()
		if err != nil {
			log.Warn("run shard thread:", "id", id, "error", err)
		}
		if s.stoped {
			break
		}
		time.Sleep(time.Duration(s.restartTime) * time.Second)
	}
	return nil
}

func (s *ShardManager) NewShard(ctx context.Context, shardID, chainID, reward, timestamp *big.Int, hash common.Hash) error {
	var extraInfo phenix.ShardInfo
	extraInfo.ID = common.BigToHash(shardID)
	extraInfo.Parent = hash
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, extraInfo)
	extraData := hexutil.Encode(buf.Bytes())
	extraData += strings.Repeat("00", 65)

	type tmplInfo struct {
		ChainID     uint64
		ShardID     uint64
		ShardReward uint64
		Timestamp   string
		ExtraData   string
	}
	var info tmplInfo
	info.ChainID = chainID.Uint64()
	info.ShardID = shardID.Uint64()
	info.ShardReward = reward.Uint64()
	info.Timestamp = timestamp.String()
	info.ExtraData = extraData

	tmpl, err := template.New("shard").Parse(shardxGen)
	if err != nil {
		log.Warn("NewShard parse", "shardID", info.ShardID, "error", err)
		return err
	}

	buf1 := new(bytes.Buffer)
	err = tmpl.Execute(buf1, info)
	if err != nil {
		log.Warn("NewShard Execute", "shardID", info.ShardID, "error", err)
		return err
	}
	fn := fmt.Sprintf("shard%d_Genesis.json", info.ShardID)
	err = ioutil.WriteFile(fn, buf1.Bytes(), 0600)
	if err != nil {
		log.Warn("NewShard WriteFile", "file", fn, "error", err)
		return err
	}
	return initShard(info.ShardID, fn)
}

func (s *ShardManager) StartShard(ctx context.Context, shardID *big.Int) error {
	go s.startShard(shardID.Uint64())
	return nil
}

func (s *ShardManager) StopShard(ctx context.Context, shardID *big.Int) error {
	id := shardID.Uint64()
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd, ok := s.shards[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	delete(s.shards, id)
	err := cmd.Process.Kill()
	if err != nil {
		log.Warn("stop shard:", "id", id, "error", err)
	}
	return nil
}

func (s *ShardManager) Stop() {
	s.stoped = true
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cmd := range s.shards {
		err := cmd.Process.Kill()
		if err != nil {
			log.Warn("stop shard thread:", "id", id, "error", err)
		}
	}
	s.shards = make(map[uint64]*exec.Cmd)
}
