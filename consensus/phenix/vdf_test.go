// VDF

//

// Copyright 2019 by KeyFuse

//

// GPLv3 License

// source: https://github.com/keyfuse/vdf

package phenix

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestNewVDFSqrt(t *testing.T) {
	var count int64 = 10000
	x := new(big.Int).SetBytes(crypto.Keccak256([]byte("12345")))
	v := NewVDFSqrt(nil)
	t1 := time.Now()
	vr := v.Delay(count, x)
	d1 := time.Since(t1)
	rst := v.Verify(count, x, vr)
	d2 := time.Since(t1) - d1
	if !rst || d1 < time.Millisecond || 10*d2 > d1 {
		t.Errorf("d1:%d,d2:%d,base:%d,result:%v", d1, d2, d1/d2, rst)
	}
}
