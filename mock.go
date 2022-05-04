package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	mmTypes "mergemock/types"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethdb"
	gethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

// type testAccount struct {
//         pk   *ecdsa.PrivateKey
//         addr common.Address
// }

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
	return nil
}

func (e *ExecutionConsensusMock) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return nil
}

func (e *ExecutionConsensusMock) Close() error {
	return nil
}

var _ consensus.Engine = (*ExecutionConsensusMock)(nil)

type TraceLogConfig struct {
	EnableTrace      bool `ask:"--enable" help:"enable tracing"`
	EnableMemory     bool `ask:"--enable-memory" help:"enable memory capture"`
	DisableStack     bool `ask:"--disable-stack" help:"disable stack capture"`
	DisableStorage   bool `ask:"--disable-storage" help:"disable storage capture"`
	EnableReturnData bool `ask:"--enable-return-data" help:"enable return data capture"`
	Debug            bool `ask:"--debug" help:"print output during capture end"`
	Limit            int  `ask:"--limit" help:"maximum length of output, but zero means unlimited"`
}

type TransactionsCreator struct {
	accounts []TestAccount
	fn       func(*params.ChainConfig, core.ChainContext, *state.StateDB, *types.Header, vm.Config, []TestAccount) []*types.Transaction
}

func (t *TransactionsCreator) Create(config *params.ChainConfig, bc core.ChainContext, statedb *state.StateDB, header *types.Header, cfg vm.Config) []*types.Transaction {
	return t.fn(config, bc, statedb, header, cfg, t.accounts)
}

type MockChain struct {
	chain     *core.BlockChain
	database  ethdb.Database
	engine    consensus.Engine
	gspec     *core.Genesis
	log       logrus.Ext1FieldLogger
	traceOpts *TraceLogConfig
}

func NewDB(dataDir string) (ethdb.Database, error) {
	if dataDir == "" {
		return rawdb.NewMemoryDatabase(), nil
	} else {
		return rawdb.NewLevelDBDatabaseWithFreezer(dataDir, 128, 128, dataDir, "", false)
	}
}

func NewMockChain(log logrus.Ext1FieldLogger, engine consensus.Engine, genesisPath string, db ethdb.Database, traceOpts *TraceLogConfig) (*MockChain, error) {
	// Geth logs some things globally unfortunately.
	// If we were using multiple mocks, we wouldn't know which one is logging what :(
	gethlog.Root().SetHandler(&GethLogger{FieldLogger: log, Adjust: 0})

	genesis, err := LoadGenesisConfig(genesisPath)
	if err != nil {
		return nil, err
	}

	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		_, err := genesis.Commit(db)
		if err != nil {
			return nil, err
		}
	}

	bc, err := core.NewBlockChain(db, nil, genesis.Config, engine, vm.Config{}, nil, nil)
	if err != nil {
		return nil, err
	}

	return &MockChain{
		chain:     bc,
		database:  db,
		engine:    engine,
		gspec:     genesis,
		log:       log,
		traceOpts: traceOpts,
	}, nil
}

func (c *MockChain) Head() common.Hash {
	return c.chain.CurrentBlock().Hash()
}

func (c *MockChain) CurrentHeader() *types.Header {
	return c.chain.CurrentHeader()
}

func (c *MockChain) CurrentTd() *big.Int {
	return c.chain.GetTd(c.Head(), c.CurrentHeader().Number.Uint64())
}

// Custom block builder, to change more things, fake time more easily, deal with difficulty etc.
func (c *MockChain) AddNewBlock(parentHash common.Hash, coinbase common.Address, timestamp uint64, gasLimit uint64, txsCreator TransactionsCreator, prevRandao common.Hash, extraData []byte, uncles []*types.Header, storeBlock bool) (*types.Block, error) {
	parent := c.chain.GetHeaderByHash(parentHash)
	if parent == nil {
		return nil, fmt.Errorf("unknown parent %s", parentHash)
	}
	config := c.gspec.Config
	statedb, err := state.New(parent.Root, state.NewDatabase(c.database), nil)
	if err != nil {
		return nil, err
	}
	header := &types.Header{
		ParentHash: parentHash,
		Coinbase:   coinbase,
		Difficulty: common.Big0,
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   gasLimit,
		Time:       timestamp,
		Extra:      extraData,
		MixDigest:  common.BytesToHash(prevRandao[:]),
	}
	if config.IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(config, parent)
		// At the transition, double the gas limit so the gas target is equal to the old gas limit.
		if !config.IsLondon(parent.Number) {
			header.GasLimit = parent.GasLimit * params.ElasticityMultiplier
		}
	}

	receipts := make([]*types.Receipt, 0)
	gasPool := new(core.GasPool).AddGas(header.GasLimit)
	stl := logger.NewStructLogger(&logger.Config{
		EnableMemory:     c.traceOpts.EnableMemory,
		DisableStack:     c.traceOpts.DisableStack,
		DisableStorage:   c.traceOpts.DisableStorage,
		EnableReturnData: c.traceOpts.EnableReturnData,
		Debug:            c.traceOpts.Debug,
		Limit:            c.traceOpts.Limit,
		Overrides:        nil,
	})
	vmconf := vm.Config{}
	if c.traceOpts.EnableTrace {
		vmconf.Tracer = stl
	}

	txs := txsCreator.Create(config, c.chain, statedb, header, vmconf)
	for i, tx := range txs {
		receipt, err := core.ApplyTransaction(config, c.chain, &header.Coinbase, gasPool, statedb, header, tx, &header.GasUsed, vmconf)
		if err != nil {
			return nil, fmt.Errorf("failed to apply transaction %d: %v", i, err)
		}
		rec, _ := json.MarshalIndent(receipt, "  ", "  ")
		c.log.WithField("receipt_index", i).Debug("receipt:\n" + string(rec))
		receipts = append(receipts, receipt)
	}
	if c.traceOpts.EnableTrace {
		var buf bytes.Buffer
		logger.WriteTrace(&buf, stl.StructLogs())
		c.log.Info("trace:\n" + buf.String())
	}

	header.GasUsed = header.GasLimit - uint64(*gasPool)
	header.Root = statedb.IntermediateRoot(config.IsEIP158(header.Number))
	block := types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil))

	// Write state changes to db
	root, err := statedb.Commit(config.IsEIP158(header.Number))
	if err != nil {
		return nil, fmt.Errorf("state write error: %v", err)
	}
	if err := statedb.Database().TrieDB().Commit(root, false, nil); err != nil {
		return nil, fmt.Errorf("trie write error: %v", err)
	}

	if storeBlock {
		_, err = c.chain.InsertChain(types.Blocks{block})
		if err != nil {
			return nil, fmt.Errorf("failed to insert block into chain")
		}
	}

	return block, nil
}

// Custom block builder, to change more things, fake time more easily, deal with difficulty etc.
func (c *MockChain) MineBlock(parent *types.Header) (*types.Block, error) {
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + 1,
	}

	config := c.gspec.Config
	if config.IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(config, parent)
		// At the transition, double the gas limit so the gas target is equal to the old gas limit.
		if !config.IsLondon(parent.Number) {
			header.GasLimit = parent.GasLimit * params.ElasticityMultiplier
		}
	}

	// Calculate difficulty
	if err := c.engine.Prepare(c.chain, header); err != nil {
		return nil, fmt.Errorf("failed to prepare header for mining: %v", err)
	}

	// Finalize block
	statedb, err := state.New(parent.Root, state.NewDatabase(c.database), nil)
	if err != nil {
		panic(err)
	}
	block, err := c.engine.FinalizeAndAssemble(c.chain, header, statedb, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize and assemble block: %v", err)
	}

	// Seal block
	results := make(chan *types.Block)
	if err := c.engine.Seal(c.chain, block, results, nil); err != nil {
		panic(fmt.Sprintf("failed to seal block: %v", err))
	}
	select {
	case found := <-results:
		block = found
	case <-time.NewTimer(10000 * time.Second).C:
		return nil, fmt.Errorf("sealing result timeout")
	}

	// Write state changes to db
	root, err := statedb.Commit(config.IsEIP158(header.Number))
	if err != nil {
		return nil, fmt.Errorf("state write error: %v", err)
	}
	if err := statedb.Database().TrieDB().Commit(root, false, nil); err != nil {
		return nil, fmt.Errorf("trie write error: %v", err)
	}

	// Insert block into chain
	_, err = c.chain.InsertChain(types.Blocks{block})
	if err != nil {
		return nil, fmt.Errorf("failed to insert block into chain")
	}

	return block, nil
}

func (c *MockChain) ProcessPayload(payload *mmTypes.ExecutionPayloadV1) (*types.Block, error) {
	parent := c.chain.GetHeaderByHash(payload.ParentHash)
	if parent == nil {
		return nil, fmt.Errorf("unknown parent %s", payload.ParentHash)
	}
	config := c.gspec.Config
	statedb, err := state.New(parent.Root, state.NewDatabase(c.database), nil)
	if err != nil {
		panic(err)
	}
	header := &types.Header{
		ParentHash:  parent.Hash(),
		UncleHash:   common.Hash{}, // updated by sealing, if necessary
		Coinbase:    payload.FeeRecipient,
		Root:        common.Hash{}, // state root verified after processing
		TxHash:      common.Hash{}, // part of assembling
		ReceiptHash: common.Hash{}, // receipt root verified after processing
		Bloom:       types.Bloom{}, // bloom verified after processing
		Difficulty:  common.Big0,
		Number:      new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:    uint64(payload.GasLimit),
		GasUsed:     0,                         // updated by processing
		Time:        uint64(payload.Timestamp), // verified against slot
		Extra:       payload.ExtraData,
		MixDigest:   payload.Random,
		Nonce:       types.BlockNonce{},    // updated by sealing, if necessary
		BaseFee:     payload.BaseFeePerGas, // verified by consensus engine (if necessary)
	}
	if config.IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(config, parent)
		// At the transition, double the gas limit so the gas target is equal to the old gas limit.
		if !config.IsLondon(parent.Number) {
			header.GasLimit = parent.GasLimit * params.ElasticityMultiplier
		}
	}
	receipts := make([]*types.Receipt, 0)
	gasPool := new(core.GasPool).AddGas(header.GasLimit)
	stl := logger.NewStructLogger(&logger.Config{
		EnableMemory:     c.traceOpts.EnableMemory,
		DisableStack:     c.traceOpts.DisableStack,
		DisableStorage:   c.traceOpts.DisableStorage,
		EnableReturnData: c.traceOpts.EnableReturnData,
		Debug:            c.traceOpts.Debug,
		Limit:            c.traceOpts.Limit,
		Overrides:        nil,
	})
	vmconf := vm.Config{}
	if c.traceOpts.EnableTrace {
		vmconf.Tracer = stl
	}
	txs := make([]*types.Transaction, 0, len(payload.Transactions))
	for i, otx := range payload.Transactions {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(otx); err != nil {
			return nil, fmt.Errorf("failed to decode tx %d: %v", i, err)
		}
		txs = append(txs, &tx)
		receipt, err := core.ApplyTransaction(config, c.chain, &header.Coinbase, gasPool, statedb, header, &tx, &header.GasUsed, vmconf)
		if err != nil {
			return nil, fmt.Errorf("failed to apply transaction %d: %v", i, err)
		}
		rec, _ := json.MarshalIndent(receipt, "  ", "  ")
		c.log.WithField("receipt_index", i).Debug("receipt:\n" + string(rec))
		receipts = append(receipts, receipt)
	}
	if c.traceOpts.EnableTrace {
		var buf bytes.Buffer
		logger.WriteTrace(&buf, stl.StructLogs())
		c.log.Info("trace:\n" + buf.String())
	}

	// verify state root is correct, and build the block
	stateRoot := statedb.IntermediateRoot(config.IsEIP158(header.Number))
	header.Root = stateRoot
	block := types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))

	h := block.Header()
	c.log.WithFields(map[string]interface{}{
		"blockHash":        block.Hash(),
		"parentHash":       block.ParentHash(),
		"sha3Uncles":       block.UncleHash(),
		"miner":            block.Coinbase(),
		"stateRoot":        block.Root(),
		"transactionsRoot": h.TxHash,
		"receiptsRoot":     block.ReceiptHash(),
		"logsBloom":        block.Bloom(),
		"difficulty":       block.Difficulty(),
		"number":           block.Number(),
		"gasLimit":         block.GasLimit(),
		"gasUsed":          block.GasUsed(),
		"timestamp":        block.Time(),
		"extraData":        hex.EncodeToString(block.Extra()),
		"prevRandao":       block.MixDigest(),
	}).Info("computed block from payload")

	if used := block.GasUsed(); used != uint64(payload.GasUsed) {
		return nil, fmt.Errorf("gas usage difference: %d <> %d", payload.GasUsed, header.GasUsed)
	}
	if receiptHash := block.ReceiptHash(); receiptHash != common.Hash(payload.ReceiptsRoot) {
		return nil, fmt.Errorf("receipt root difference: %s <> %s", receiptHash, payload.ReceiptsRoot)
	}
	if bloom := block.Bloom(); bloom != payload.LogsBloom {
		return nil, fmt.Errorf("logs bloom difference: %s <> %s", bloom, payload.LogsBloom)
	}
	if block.Root() != common.Hash(payload.StateRoot) {
		return nil, fmt.Errorf("state root difference: %s <> %s", stateRoot, payload.StateRoot)
	}
	if hash := block.Hash(); hash != payload.BlockHash {
		return nil, fmt.Errorf("block hash difference: %s <> %s", hash, payload.BlockHash)
	}
	// Write state changes to db
	root, err := statedb.Commit(config.IsEIP158(header.Number))
	if err != nil {
		return nil, fmt.Errorf("state write error: %v", err)
	}
	if err := statedb.Database().TrieDB().Commit(root, false, nil); err != nil {
		return nil, fmt.Errorf("trie write error: %v", err)
	}
	_, err = c.chain.InsertChain(types.Blocks{block})
	if err != nil {
		return nil, fmt.Errorf("failed to insert block into chain")
	}
	return block, nil
}

func (c *MockChain) Close() error {
	err := c.engine.Close()
	if err != nil {
		c.log.WithError(err).Error("Failed closing consensus engine")
	}
	// mock-chain doesn't own the db, it's not closed here.
	return nil
}

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

// func mockRandomValue(seed [32]byte) [32]byte {
//         h := sha256.New()
//         h.Write(seed[:])
//         var random common.Hash
//         copy(random[:], h.Sum(nil))
//         return random
// }
