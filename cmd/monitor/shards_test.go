package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"html/template"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/phenix"
	"github.com/ethereum/go-ethereum/log"
)

func TestShardManager_NewShard(t *testing.T) {
	var extraInfo phenix.ShardInfo
	extraInfo.ID = common.BigToHash(big.NewInt(2))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, extraInfo)
	extraData := hexutil.Encode(buf.Bytes())
	extraData += strings.Repeat("00", 65)

	type TmplInfo struct {
		ChainID     uint64
		ShardID     uint64
		ShardReward uint64
		Timestamp   string
		ExtraData   string
	}
	var info TmplInfo
	info.ChainID = 2
	info.ShardID = 2
	info.ShardReward = 1000
	info.Timestamp = fmt.Sprintf("%d", time.Now().Unix())
	info.ExtraData = extraData

	tmpl, err := template.New("shard").Parse(shardxGen)
	if err != nil {
		log.Warn("NewShard parse", "shardID", info.ShardID, "error", err)
		t.Fatal(err)
	}

	err = tmpl.Execute(os.Stdout, info)
	if err != nil {
		log.Warn("NewShard Execute", "shardID", info.ShardID, "error", err)
		t.Fatal(err)
	}
}
