package main

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

func TestAPI_HeaderByNumber(t *testing.T) {
	api := NewAPI(conf)
	header, err := api.HeaderByNumber(context.Background(), big.NewInt(1), big.NewInt(100))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("header:", header.Number, header.Coinbase)
}

func TestAPI_HeaderByNumber1(t *testing.T) {
	addr := conf.IPCEndpoint()
	ctx := context.Background()
	c, err := rpc.DialContext(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	var head *types.Header

	err = c.CallContext(ctx, &head, "proxy_headerByNumber", big.NewInt(1), big.NewInt(100))
	if err == nil || head == nil {
		t.Fatal(err)
	}
	// fmt.Println("header:", head.Number, head.Coinbase)
	fmt.Println("header:", head)
}
