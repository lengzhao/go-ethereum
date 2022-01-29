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
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
type API struct {
	chain  consensus.ChainHeaderReader
	phenix *Phenix
}

func (api *API) GetLogs(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	data, err := api.phenix.db.Get(append([]byte("phenix-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	var out types.Receipts
	err = rlp.DecodeBytes(data, &out)
	return out, err
}

func (api *API) GetLog(ctx context.Context, hash common.Hash) (*types.Receipt, error) {
	data, err := api.phenix.db.Get(append([]byte("ptx-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	var out types.Receipt
	err = rlp.DecodeBytes(data, &out)
	return &out, err
}
