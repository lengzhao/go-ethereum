package phenix

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var ValidatorsContractAddr = common.HexToAddress("0x0000000000000000000000000000000000000F01")
var systemCallerAddr = common.HexToAddress("0x00000000000000000000000000000000000000F00")

type chainContext struct {
	chainReader consensus.ChainHeaderReader
	engine      consensus.Engine
}

func newChainContext(chainReader consensus.ChainHeaderReader, engine consensus.Engine) *chainContext {
	return &chainContext{
		chainReader: chainReader,
		engine:      engine,
	}
}

// Engine retrieves the chain's consensus engine.
func (cc *chainContext) Engine() consensus.Engine {
	return cc.engine
}

// GetHeader returns the hash corresponding to their hash.
func (cc *chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return cc.chainReader.GetHeader(hash, number)
}

func ReadFromContract(contract common.Address, input []byte, state *state.StateDB, context vm.BlockContext, chainConfig *params.ChainConfig) ([]byte, error) {
	msg := types.NewMessage(systemCallerAddr, &contract, 1, new(big.Int), math.MaxUint64, new(big.Int), new(big.Int), new(big.Int), input, nil, false)
	vmenv := vm.NewEVM(context, core.NewEVMTxContext(msg), state, chainConfig, vm.Config{})
	ret, _, err := vmenv.Call(vm.AccountRef(msg.From()), *msg.To(), msg.Data(), msg.Gas(), msg.Value())
	if err != nil {
		return []byte{}, err
	}

	return ret, nil
}

func ExecuteContract(contract common.Address, input []byte, ti int, state *state.StateDB, context vm.BlockContext, chainConfig *params.ChainConfig) (*types.Receipt, error) {
	nonce := state.GetNonce(systemCallerAddr) + 1
	msg := types.NewMessage(systemCallerAddr, &contract, nonce, new(big.Int), math.MaxUint64, new(big.Int), new(big.Int), new(big.Int), input, nil, false)
	state.SetNonce(systemCallerAddr, nonce)

	h := crypto.Keccak256(systemCallerAddr.Bytes(), encode(nonce))
	ths := common.Hash{}
	ths.SetBytes(h)
	state.Prepare(ths, ti)
	vmenv := vm.NewEVM(context, core.NewEVMTxContext(msg), state, chainConfig, vm.Config{})
	_, _, err := vmenv.Call(vm.AccountRef(msg.From()), *msg.To(), msg.Data(), msg.Gas(), msg.Value())
	state.Finalise(true)

	receipt := &types.Receipt{Type: types.LegacyTxType, PostState: nil, CumulativeGasUsed: 2}
	if err != nil {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = ths
	receipt.GasUsed = 2

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = state.GetLogs(ths, common.Hash{})
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	// receipt.BlockHash = blockHash
	receipt.BlockNumber = context.BlockNumber
	receipt.TransactionIndex = uint(ti)

	return receipt, nil
}

func encode(in interface{}) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, in)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}
