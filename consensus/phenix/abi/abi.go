package abi

import (
	"bytes"
	_ "embed"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

var (
	//go:embed shard.json
	shardABI []byte
	//go:embed cross_shard.json
	crossShardABI []byte
	//go:embed deployer.json
	deployerABI []byte
	//go:embed miner.json
	minerABI []byte
	//go:embed sys_proxy.json
	sysProxy []byte

	DeployerAddr       = common.HexToAddress("0x0000000000000000000000000000000000000F01")
	ReservedAddr       = common.HexToAddress("0x0000000000000000000000000000000000000f02")
	CrossShardAddr     = common.HexToAddress("0x0000000000000000000000000000000000000F03")
	MinerAddr          = common.HexToAddress("0x0000000000000000000000000000000000000f04")
	ShardAddr          = common.HexToAddress("0x0000000000000000000000000000000000000f05")
	CodeCrossShardAddr = common.HexToAddress("0x0000000000000000000000000000000000000F06")
	CodeMinerAddr      = common.HexToAddress("0x0000000000000000000000000000000000000F07")
	CodeShardAddr      = common.HexToAddress("0x0000000000000000000000000000000000000F08")

	abiMap map[int]abi.ABI
)

const (
	ECrossShard = iota
	EDeployer
	EMiner
	EShard
	ESysProxy
)

func init() {
	abiMap = make(map[int]abi.ABI)
	abiMap[ECrossShard], _ = abi.JSON(bytes.NewReader(crossShardABI))
	abiMap[EDeployer], _ = abi.JSON(bytes.NewReader(deployerABI))
	abiMap[EMiner], _ = abi.JSON(bytes.NewReader(minerABI))
	abiMap[EShard], _ = abi.JSON(bytes.NewReader(shardABI))
	abiMap[ESysProxy], _ = abi.JSON(bytes.NewReader(sysProxy))
}

func GetABI(in int) abi.ABI {
	return abiMap[in]
}
