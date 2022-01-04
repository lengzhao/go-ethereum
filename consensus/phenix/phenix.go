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

// Package phenix implements the dpos consensus engine.
package phenix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/phenix/abi"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
)

// Phenix proof-of-authority protocol constants.
var (
	extraShard = 32 * 4                 // Fixed number of extra-data prefix bytes reserved for shard
	extraSeal  = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures

	// emptySigner = common.HexToAddress("0x01")
	emptySigner  = abi.AirDropAddr
	nulSignature = make([]byte, extraSeal)
	shardCreator = common.HexToAddress("0x8a170A0860F8B96F8B8ffBfADd000195Dd0512ae")

	rewardBase = big.NewInt(1e+18)
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")
)

// SignerFn hashes and signs the data to be signed by a backing account.
type SignerFn func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]
	if bytes.Equal(signature, nulSignature) {
		return emptySigner, nil
	}

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(crypto.Keccak256(encodeSigHeader(header)), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

type ShardInfo struct {
	ID         common.Hash
	Parent     common.Hash
	LeftChild  common.Hash
	RightChild common.Hash
}

// Phenix is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Phenix struct {
	chainCfg params.ChainConfig
	config   *params.PhenixConfig // Consensus engine configuration parameters
	db       ethdb.Database       // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	signer  common.Address // Ethereum address of the signing key
	signFn  SignerFn       // Signer function to authorize hashes with
	lock    sync.RWMutex   // Protects the signer fields
	shardID common.Hash
}

// New creates a Phenix proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.ChainConfig, db ethdb.Database) *Phenix {
	// Set any missing consensus parameters to their defaults
	conf := *config.Phenix
	if conf.Epoch == 0 || conf.ShardID == 0 {
		panic("error phenix config")
	}
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)
	log.Info("phenix consensus:", conf)
	// log.Root().SetHandler(log.StdoutHandler)
	return &Phenix{
		chainCfg:   *config,
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		shardID:    common.BigToHash(new(big.Int).SetUint64(conf.ShardID)),
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *Phenix) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
	// return ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Phenix) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *Phenix) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Phenix) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}

	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraShard {
		return errMissingVanity
	}
	if len(header.Extra) < extraShard+extraSeal {
		return errMissingSignature
	}

	v := NewVDFSqrt(nil)
	x := crypto.Keccak256(header.ParentHash[:], header.Coinbase[:])
	rst := v.Verify(params.VDFTime, new(big.Int).SetBytes(x), new(big.Int).SetBytes(header.MixDigest[:]))
	if !rst {
		return errInvalidMixDigest
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in DPoS
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	cap := uint64(0x7fffffffffffffff)
	if header.GasLimit > cap {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, cap)
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify cascading fields
	return c.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *Phenix) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to its parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+c.config.Period != header.Time {
		return errInvalidTimestamp
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}
	if signer != header.Coinbase {
		log.Error("error signer,Coinbase:", header.Coinbase, signer)
		return errUnauthorizedSigner
	}
	if header.Coinbase == emptySigner {
		if header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	} else if c.isvalidator(chain, header.Number.Uint64(), header.Coinbase) {
		if header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
	} else {
		return fmt.Errorf("invalid Coinbase: %s", header.Coinbase.String())
	}
	if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}
	return nil
}

func (c *Phenix) isvalidator(chain consensus.ChainHeaderReader, number uint64, addr common.Address) bool {
	ckNum := (number - 1) / c.config.Epoch * c.config.Epoch

	checkpoint := chain.GetHeaderByNumber(ckNum)
	if checkpoint == nil {
		return false
	}
	signers := make([]common.Address, (len(checkpoint.Extra)-extraShard-extraSeal)/common.AddressLength)
	for i := 0; i < len(signers); i++ {
		copy(signers[i][:], checkpoint.Extra[extraShard+i*common.AddressLength:])
	}
	if len(signers) == 0 {
		return false
	}
	index := (number + 1) % c.config.Epoch
	index = index % uint64(len(signers))
	return signers[index] == addr
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Phenix) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *Phenix) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	// header.Coinbase = emptySigner
	header.Coinbase = c.signer
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	if !c.isvalidator(chain, number, c.signer) {
		header.Coinbase = emptySigner
	}

	// Set the correct difficulty
	header.Difficulty = c.calcDifficulty(chain, header.Number.Uint64(), header.Coinbase)

	var info ShardInfo
	info.ID = c.shardID
	header.Extra, _ = bEncode(info)

	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + c.config.Period
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (c *Phenix) Finalize(
	chain consensus.ChainHeaderReader,
	header *types.Header, state *state.StateDB,
	txs []*types.Transaction,
	uncles []*types.Header) ([]*types.Receipt, error) {

	var out []*types.Receipt
	var err error

	if header.Coinbase == emptySigner && len(txs) > 0 {
		return nil, fmt.Errorf("empty signer,but exist tx")
	}

	err = c.checkExtra(chain, header, state)
	if err != nil {
		return nil, err
	}

	reward := big.NewInt(c.config.Reward)
	reward = reward.Mul(reward, rewardBase)

	state.AddBalance(systemCallerAddr, reward)
	number := header.Number.Uint64()
	// If the block is a checkpoint block, verify the signer list
	if number%c.config.Epoch == 0 {
		signers, err := c.getSignersInContract(chain, header, state)
		if err != nil {
			fmt.Println("fail to getSignersInContract:", err)
			return nil, err
		}
		buffer := make([]byte, len(signers)*common.AddressLength)
		for i, signer := range signers {
			copy(buffer[i*common.AddressLength:], signer[:])
		}
		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraShard:extraSuffix], buffer) {
			fmt.Println("different Extra:")
			return nil, errMismatchingCheckpointSigners
		}
	}

	if number == 1 {
		out, err = c.initSystemContract(chain, header, state)
		if err != nil {
			return nil, err
		}
	}

	if number%c.config.Epoch == c.config.Epoch/2 {
		input, err := abi.GetABI(abi.EMiner).Pack("updateNextMiners")
		if err != nil {
			log.Error("Can't pack data for Miner.updateNextMiners", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ExecuteContract(abi.MinerAddr, input, new(big.Int), state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ExecuteContract", err)
			return nil, err
		}
		out = append(out, result)
	}

	if header.Coinbase != emptySigner {
		input, err := abi.GetABI(abi.EMiner).Pack("reward")
		if err != nil {
			log.Error("Can't pack data for Miner.reward", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ExecuteContract(abi.MinerAddr, input, reward, state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ExecuteContract", err)
			return nil, err
		}
		out = append(out, result)
	}

	//check
	{
		input, err := abi.GetABI(abi.EMiner).Pack("candidateInfos", header.Coinbase)
		if err != nil {
			log.Error("Can't pack data for Miner.reward", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ReadFromContract(abi.MinerAddr, input, state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ExecuteContract", err)
			return nil, err
		}
		ret, err := abi.GetABI(abi.EMiner).Unpack("candidateInfos", result)
		if err != nil {
			fmt.Println("fail to read candidateInfos:", err)
			return nil, err
		}
		// if len(ret) != 1 {
		// 	return nil, errors.New("invalid params length")
		// }
		fmt.Println("balance:", header.Number, ret)
	}

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
	return out, nil
}

func (c *Phenix) initSystemContract(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) ([]*types.Receipt, error) {
	var out []*types.Receipt
	//init crossShard
	{
		input1, err := abi.GetABI(abi.ECrossShard).Pack("init", big.NewInt(int64(c.config.ShardID)))
		if err != nil {
			log.Error("Can't pack data for CrossShard.int", "error", err)
			return nil, err
		}
		input2, err := abi.GetABI(abi.ESysProxy).Pack("upgradeToAndCall", abi.CodeCrossShardAddr, input1)
		if err != nil {
			log.Error("Can't pack data for CrossShard.upgradeToAndCall", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ExecuteContract(abi.CrossShardAddr, input2, new(big.Int), state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ExecuteContract", err)
			return nil, err
		}
		out = append(out, result)
	}
	//init shard_new
	{
		input1, err := abi.GetABI(abi.EShard).Pack("init", big.NewInt(int64(c.config.ShardID)), c.chainCfg.ChainID, shardCreator)
		if err != nil {
			log.Error("Can't pack data for Shard.int", "error", err)
			return nil, err
		}
		input2, err := abi.GetABI(abi.ESysProxy).Pack("upgradeToAndCall", abi.CodeShardAddr, input1)
		if err != nil {
			log.Error("Can't pack data for Shard.upgradeToAndCall", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ExecuteContract(abi.ShardAddr, input2, new(big.Int), state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ExecuteContract", err)
			return nil, err
		}
		out = append(out, result)
	}

	//init miner
	{
		input, err := abi.GetABI(abi.ESysProxy).Pack("upgradeToAndCall", abi.CodeMinerAddr, []byte{})
		if err != nil {
			log.Error("Can't pack data for Miner.upgradeToAndCall", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ExecuteContract(abi.MinerAddr, input, new(big.Int), state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ExecuteContract", err)
			return nil, err
		}
		out = append(out, result)
	}
	return out, nil
}
func (c *Phenix) checkExtra(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	var err error

	var info ShardInfo
	err = bDecode(header.Extra, &info)
	if err != nil {
		return err
	}

	if info.ID != c.shardID {
		return fmt.Errorf("extra-data:error shard id")
	}
	if c.config.ShardID > 1 && info.Parent == (common.Hash{}) {
		return fmt.Errorf("extra-data:empty parent shard")
	}
	return nil
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (c *Phenix) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	number := header.Number.Uint64()
	// log.Info("FinalizeAndAssemble:", number)
	// If the block is a checkpoint block, verify the signer list
	if number%c.config.Epoch == 0 {
		signers, err := c.getSignersInContract(chain, header, state)
		if err != nil {
			return nil, err
		}
		buffer := make([]byte, len(signers)*common.AddressLength)
		for i, signer := range signers {
			copy(buffer[i*common.AddressLength:], signer[:])
		}
		if len(header.Extra) < extraShard {
			header.Extra = make([]byte, extraShard)
		}
		header.Extra = append(header.Extra[:extraShard], buffer...)
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraSeal)...)
	}

	// Finalize block
	rcps, err := c.Finalize(chain, header, state, txs, uncles)
	if err != nil {
		return nil, err
	}
	if len(rcps) > 0 {
		receipts = append(receipts, rcps...)
	}

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Phenix) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Phenix) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if c.config.Period == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the signer fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn
	c.lock.RUnlock()

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Until(time.Unix(int64(header.Time), 0))
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		// wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		delay += time.Duration(rand.Int63n(int64(wiggleTime)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggleTime))
	}
	// log.Info("Seal:", number)
	v := NewVDFSqrt(nil)
	x := crypto.Keccak256(header.ParentHash[:], header.Coinbase[:])
	vr := v.Delay(params.VDFTime, new(big.Int).SetBytes(x))
	header.MixDigest.SetBytes(vr.Bytes())

	if header.Coinbase == emptySigner {
		copy(header.Extra[len(header.Extra)-extraSeal:], make([]byte, extraSeal))
	} else {
		// Sign all the things!
		sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, encodeSigHeader(header))
		if err != nil {
			return err
		}
		copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	}

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
func (c *Phenix) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return c.calcDifficulty(chain, parent.Number.Uint64()+1, c.signer)
}

func (c *Phenix) calcDifficulty(chain consensus.ChainHeaderReader, number uint64, signer common.Address) *big.Int {
	if c.isvalidator(chain, number, signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (c *Phenix) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// Close implements consensus.Engine. It's a noop for phenix as there are no background threads.
func (c *Phenix) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *Phenix) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "phenix",
		Version:   "1.0",
		Service:   &API{chain: chain, phenix: c},
		Public:    false,
	}}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeHeader(hasher, header, true)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func encodeSigHeader(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeHeader(b, header, false)
	return b.Bytes()
}

func encodeHeader(w io.Writer, header *types.Header, isSeal bool) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.Nonce,
	}
	if !isSeal {
		enc = append(enc, header.MixDigest)
	}

	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}

func (c *Phenix) getSignersInContract(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) ([]common.Address, error) {
	var out []common.Address
	for i := int64(0); i < 47; i++ {
		input, err := abi.GetABI(abi.EMiner).Pack("miners", big.NewInt(i))
		if err != nil {
			log.Error("Can't pack data for miners", "error", err)
			return nil, err
		}
		context := core.NewEVMBlockContext(header, newChainContext(chain, c), nil)
		result, err := ReadFromContract(abi.MinerAddr, input, state, context, &c.chainCfg)
		if err != nil {
			log.Error("fail to ReadFromContract", err)
			return nil, err
		}
		ret, err := abi.GetABI(abi.EMiner).Unpack("miners", result)
		if err != nil {
			return nil, err
		}
		if len(ret) != 1 {
			return nil, errors.New("invalid params length")
		}
		addr, ok := ret[0].(common.Address)
		if ok && (addr != common.Address{}) {
			out = append(out, addr)
		}
	}
	// if len(out) == 0 {
	// 	out = append(out, c.signer)
	// }

	return out, nil
}

func bEncode(in interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, in)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func bDecode(in []byte, out interface{}) error {
	return binary.Read(bytes.NewReader(in), binary.BigEndian, out)
}
