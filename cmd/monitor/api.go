package main

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// API proxy to other shards
type API struct {
	conf    Config
	clients map[uint64]*ethclient.Client
}

func NewAPI(c Config) *API {
	var out API
	out.conf = c
	out.clients = make(map[uint64]*ethclient.Client)
	return &out
}

func (api *API) getClient(shardID *big.Int) (*ethclient.Client, error) {
	id := shardID.Uint64()
	c, ok := api.clients[id]
	if ok {
		return c, nil
	}
	addr, ok := api.conf.ShardNodes[id]
	if !ok {
		addr = api.conf.GetAddress(shardID)
	}
	client, err := ethclient.Dial(addr)
	if err != nil {
		return nil, err
	}
	api.clients[id] = client

	return client, nil
}

func (api *API) HeaderByHash(ctx context.Context, shardID *big.Int, hash common.Hash) (*types.Header, error) {
	client, err := api.getClient(shardID)
	if err != nil {
		return nil, err
	}

	out, err := client.HeaderByHash(ctx, hash)
	if err != nil {
		client.Close()
		delete(api.clients, shardID.Uint64())
		return nil, err
	}
	return out, nil
}

func (api *API) HeaderByNumber(ctx context.Context, shardID *big.Int, number *big.Int) (*types.Header, error) {
	client, err := api.getClient(shardID)
	if err != nil {
		return nil, err
	}

	out, err := client.HeaderByNumber(ctx, number)
	if err != nil {
		client.Close()
		delete(api.clients, shardID.Uint64())
		return nil, err
	}
	return out, nil
}

func (api *API) StorageAt(ctx context.Context, shardID *big.Int, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	client, err := api.getClient(shardID)
	if err != nil {
		return nil, err
	}
	out, err := client.StorageAt(ctx, account, key, blockNumber)
	if err != nil {
		client.Close()
		delete(api.clients, shardID.Uint64())
		return nil, err
	}
	return out, nil
}

func (api *API) FilterLogs(ctx context.Context, shardID *big.Int, q ethereum.FilterQuery) ([]types.Log, error) {
	client, err := api.getClient(shardID)
	if err != nil {
		return nil, err
	}
	out, err := client.FilterLogs(ctx, q)
	if err != nil {
		client.Close()
		delete(api.clients, shardID.Uint64())
		return nil, err
	}
	return out, nil
}
