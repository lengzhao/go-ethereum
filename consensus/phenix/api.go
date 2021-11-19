// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package phenix

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
type API struct {
	chain  consensus.ChainHeaderReader
	phenix *Phenix
}

type blockNumberOrHashOrRLP struct {
	*rpc.BlockNumberOrHash
	RLP hexutil.Bytes `json:"rlp,omitempty"`
}

func (sb *blockNumberOrHashOrRLP) UnmarshalJSON(data []byte) error {
	bnOrHash := new(rpc.BlockNumberOrHash)
	// Try to unmarshal bNrOrHash
	if err := bnOrHash.UnmarshalJSON(data); err == nil {
		sb.BlockNumberOrHash = bnOrHash
		return nil
	}
	// Try to unmarshal RLP
	var input string
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	sb.RLP = hexutil.MustDecode(input)
	return nil
}

// GetSigner returns the signer for a specific phenix block.
// Can be called with either a blocknumber, blockhash or an rlp encoded blob.
// The RLP encoded blob can either be a block or a header.
func (api *API) GetSigner(rlpOrBlockNr *blockNumberOrHashOrRLP) (common.Address, error) {
	if len(rlpOrBlockNr.RLP) == 0 {
		blockNrOrHash := rlpOrBlockNr.BlockNumberOrHash
		var header *types.Header
		if blockNrOrHash == nil {
			header = api.chain.CurrentHeader()
		} else if hash, ok := blockNrOrHash.Hash(); ok {
			header = api.chain.GetHeaderByHash(hash)
		} else if number, ok := blockNrOrHash.Number(); ok {
			header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
		}
		return api.phenix.Author(header)
	}
	block := new(types.Block)
	if err := rlp.DecodeBytes(rlpOrBlockNr.RLP, block); err == nil {
		return api.phenix.Author(block.Header())
	}
	header := new(types.Header)
	if err := rlp.DecodeBytes(rlpOrBlockNr.RLP, header); err != nil {
		return common.Address{}, err
	}
	return api.phenix.Author(header)
}
