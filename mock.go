package main

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"math/big"
	"os"
)

func LoadGenesisConfig(path string) (*core.Genesis, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis file: %v", err)
	}
	defer file.Close()

	var genesis core.Genesis
	if err := json.NewDecoder(file).Decode(&genesis); err != nil {
		return nil, fmt.Errorf("invalid genesis file: %v", err)
	}
	return &genesis, nil
}

// This implements the execution-block-header verification interface, but omits many of the details:
// the mock doesn't fully verify, and sealing work of headers is very limited.
type ExecutionConsensusMock struct {
	// TODO: set terminal total difficulty, and switch from ethash to pos
	pow *ethash.Ethash
	log logrus.Ext1FieldLogger
}

func (e *ExecutionConsensusMock) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (e *ExecutionConsensusMock) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	// Short circuit if the header is known, or its parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	// check we have the parent
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// TODO: not verifying time, difficulty, gas limit, gas usage vs limit, base fee, extra-data, etc.
	return nil
}

func (e *ExecutionConsensusMock) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// nothing fancy, not optimized, this is mostly a mock anyway
	abort := make(chan struct{})
	errorsOut := make(chan error, len(headers))
	go func() {
		for i, h := range headers {
			err := e.VerifyHeader(chain, h, seals[i])
			select {
			case <-abort:
				return
			case errorsOut <- err:
				continue
			}
		}
	}()
	return abort, errorsOut
}

func (e *ExecutionConsensusMock) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// TODO sanity check maybe?
	return nil
}

func (e *ExecutionConsensusMock) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = big.NewInt(0)
	return nil
}

func (e *ExecutionConsensusMock) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// no block rewards, consensus layer does that instead.
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}

func (e *ExecutionConsensusMock) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Finalize block
	e.Finalize(chain, header, state, txs, uncles)

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

func (e *ExecutionConsensusMock) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
	select {
	case results <- block.WithSeal(header):
	default:
		e.log.Warn("Sealing result is not read by miner", "mode", "fake", "sealhash", e.SealHash(block.Header()))
	}
	return nil
}

func (e *ExecutionConsensusMock) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

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
		header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}

func (e *ExecutionConsensusMock) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

func (e *ExecutionConsensusMock) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return nil
}

func (e *ExecutionConsensusMock) Close() error {
	return nil
}

var _ consensus.Engine = (*ExecutionConsensusMock)(nil)

// a hack borrowed from the geth core package
type fakeChainReader struct {
	config *params.ChainConfig
}

// Config returns the chain configuration.
func (cr *fakeChainReader) Config() *params.ChainConfig {
	return cr.config
}

func (cr *fakeChainReader) CurrentHeader() *types.Header                            { return nil }
func (cr *fakeChainReader) GetHeaderByNumber(number uint64) *types.Header           { return nil }
func (cr *fakeChainReader) GetHeaderByHash(hash common.Hash) *types.Header          { return nil }
func (cr *fakeChainReader) GetHeader(hash common.Hash, number uint64) *types.Header { return nil }
func (cr *fakeChainReader) GetBlock(hash common.Hash, number uint64) *types.Block   { return nil }

type MockChain struct {
	log           logrus.Ext1FieldLogger
	gspec         *core.Genesis
	database      ethdb.Database
	execConsensus consensus.Engine
	blockchain    *core.BlockChain
}

func NewMockChain(log logrus.Ext1FieldLogger, genesis *core.Genesis, db ethdb.Database) *MockChain {
	// TODO: real ethash, with very low difficulty
	fakeEthash := ethash.NewFaker()
	execConsensus := &ExecutionConsensusMock{fakeEthash, log}
	blockchain, _ := core.NewBlockChain(db, nil, genesis.Config, execConsensus, vm.Config{}, nil, nil)

	// todo: is overwriting harmful? Maybe do a safety check in case we restart from an existing db?
	genesis.Commit(db)

	return &MockChain{
		log:           log,
		gspec:         genesis,
		database:      db,
		execConsensus: execConsensus,
		blockchain:    blockchain,
	}
}

type TransactionsCreator func(config *params.ChainConfig, bc core.ChainContext, statedb *state.StateDB, header *types.Header, cfg vm.Config) []*types.Transaction

func (c *MockChain) Head() common.Hash {
	return c.blockchain.CurrentBlock().Hash()
}

// Custom block builder, to change more things, fake time more easily, deal with difficulty etc.
func (c *MockChain) AddNewBlock(parentRoot common.Hash, coinbase common.Address, timestamp uint64,
	gasLimit uint64, txsCreator TransactionsCreator, extraData []byte, uncles []*types.Header) (*types.Block, error) {

	parent := c.blockchain.GetHeaderByHash(parentRoot)
	if parent == nil {
		return nil, fmt.Errorf("unknown parent %s", parentRoot)
	}
	config := c.gspec.Config
	statedb, err := state.New(parent.Root, state.NewDatabase(c.database), nil)
	if err != nil {
		panic(err)
	}
	header := &types.Header{
		ParentHash:  parent.Root,
		UncleHash:   common.Hash{}, // updated by sealing
		Coinbase:    coinbase,
		Root:        common.Hash{}, // updated by Finalize, called within FinalizeAndAssemble
		TxHash:      common.Hash{}, // part of assembling
		ReceiptHash: common.Hash{}, // part of assembling
		Bloom:       types.Bloom{}, // part of assembling
		Difficulty:  big.NewInt(1), // technically depends on time in PoW, but not here :')
		Number:      new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:    gasLimit,
		GasUsed:     0, // updated with ApplyTransaction
		Time:        timestamp,
		Extra:       extraData,
		MixDigest:   common.Hash{},      // updated by sealing, if necessary
		Nonce:       types.BlockNonce{}, // updated by sealing, if necessary
		BaseFee:     nil,
	}
	if config.IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(config, parent)
		if !config.IsLondon(parent.Number) {
			parentGasLimit := parent.GasLimit * params.ElasticityMultiplier
			header.GasLimit = core.CalcGasLimit(parentGasLimit, gasLimit)
		}
	}
	receipts := make([]*types.Receipt, 0)
	gasPool := new(core.GasPool).AddGas(header.GasLimit)
	txs := txsCreator(config, c.blockchain, statedb, header, vm.Config{})
	for _, tx := range txs {
		receipt, err := core.ApplyTransaction(config, c.blockchain, &header.Coinbase, gasPool, statedb, header, tx, &header.GasUsed, vm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to apply transaction: %v", err)
		}
		receipts = append(receipts, receipt)
	}

	// Finalize and seal the block
	block, err := c.execConsensus.FinalizeAndAssemble(&fakeChainReader{config}, header, statedb, txs, uncles, receipts)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize and assemble block: %v", err)
	}

	// Write state changes to db
	root, err := statedb.Commit(config.IsEIP158(header.Number))
	if err != nil {
		return nil, fmt.Errorf("state write error: %v", err)
	}
	if err := statedb.Database().TrieDB().Commit(root, false, nil); err != nil {
		return nil, fmt.Errorf("trie write error: %v", err)
	}
	return block, nil
}

func (c *MockChain) Close() error {
	err := c.execConsensus.Close()
	if err != nil {
		c.log.WithError(err).Error("failed closing consensus engine")
	}
	err = c.database.Close()
	if err != nil {
		c.log.WithError(err).Error("failed closing database")
	}
	// TODO: maybe clean up?
	return nil
}