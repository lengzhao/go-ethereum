package main

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

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

func (s *ShardManager) startShard(id uint64) error {
	params := []string{}
	params = append(params, "--datadir", fmt.Sprintf("shard%d", id))
	params = append(params, "--ipcpath", fmt.Sprintf("phenix%d.ipc", id))
	for k, v := range s.param {
		params = append(params, k)
		if v != "" {
			params = append(params, v)
		}
	}
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
		cmd := exec.Command(s.command, params...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		s.mu.Lock()
		s.shards[id] = cmd
		s.mu.Unlock()
		err := cmd.Run()
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
