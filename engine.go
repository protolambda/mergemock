package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"mergemock/api"
	"mergemock/rpc"
	"mergemock/types"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"

	"github.com/sirupsen/logrus"
)

type EngineCmd struct {
	// chain options
	SlotsPerEpoch uint64 `ask:"--slots-per-epoch" help:"Slots per epoch"`
	DataDir       string `ask:"--datadir" help:"Directory to store execution chain data (empty for in-memory data)"`
	GenesisPath   string `ask:"--genesis" help:"Genesis execution-config file"`
	JwtSecretPath string `ask:"--jwt-secret" help:"JWT secret key for authenticated communication"`

	// connectivity options
	ListenAddr    string      `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	WebsocketAddr string      `ask:"--ws-addr" help:"Address to serve /ws endpoint on for websocket JSON-RPC"`
	Cors          []string    `ask:"--cors" help:"List of allowable origins (CORS http header)"`
	Timeout       rpc.Timeout `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	// embed logger options
	LogCmd         `ask:".log" help:"Change logger configuration"`
	TraceLogConfig `ask:".trace" help:"Tracing options"`

	close   chan struct{}
	log     logrus.Ext1FieldLogger
	ctx     context.Context
	backend *EngineBackend
	rpcSrv  *gethRpc.Server
	srv     *http.Server
	wsSrv   *http.Server // upgrades to websocket rpc

	jwtSecret []byte
}

func (c *EngineCmd) Default() {
	c.GenesisPath = "genesis.json"
	c.JwtSecretPath = "jwt.hex"

	c.ListenAddr = "127.0.0.1:8551"
	c.WebsocketAddr = "127.0.0.1:8552"
	c.Cors = []string{"*"}

	c.Timeout.Read = 30 * time.Second
	c.Timeout.ReadHeader = 10 * time.Second
	c.Timeout.Write = 30 * time.Second
	c.Timeout.Idle = 5 * time.Minute
}

func (c *EngineCmd) Help() string {
	return "Run a mock Execution engine."
}

func (c *EngineCmd) Run(ctx context.Context, args ...string) error {
	if err := c.initLogger(ctx); err != nil {
		// Logger wasn't initialized so we can't log. Error out instead.
		return err
	}
	jwt, err := loadJwtSecret(c.JwtSecretPath)
	if err != nil {
		c.log.WithField("err", err).Fatal("Unable to read JWT secret")
	}
	c.jwtSecret = jwt
	c.log.WithField("val", common.Bytes2Hex(c.jwtSecret)).Info("Loaded JWT secret")
	chain, err := c.makeMockChain()
	if err != nil {
		c.log.WithField("err", err).Fatal("Unable to initialize mock chain")
	}
	backend, err := NewEngineBackend(c.log, chain)
	if err != nil {
		c.log.WithField("err", err).Fatal("Unable to initialize backend")
	}
	c.backend = backend
	c.startRPC(ctx)
	go c.RunNode()
	return nil
}

func (c *EngineCmd) RunNode() {
	c.log.Info("started")

	go c.srv.ListenAndServe()
	go c.wsSrv.ListenAndServe()

	for range c.close {
		c.rpcSrv.Stop()
		c.srv.Close()
		c.wsSrv.Close()
		return
		// TODO: any other tasks to run in this loop? mock sync changes?
	}
}

func (c *EngineCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}

func (c *EngineCmd) initLogger(ctx context.Context) error {
	logr, err := c.LogCmd.Create()
	if err != nil {
		return err
	}
	c.log = logr
	c.ctx = ctx
	c.close = make(chan struct{})
	return nil
}

func loadJwtSecret(path string) ([]byte, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	jwt := common.Hex2Bytes(string(raw))
	if len(jwt) != 32 {
		return nil, fmt.Errorf("invalid length, expected 32-byte value")
	}
	return jwt, nil
}

func (c *EngineCmd) makeMockChain() (*MockChain, error) {
	posEngine := &ExecutionConsensusMock{
		pow: nil, // TODO: do we even need this?
		log: c.log,
	}
	db, err := NewDB(c.DataDir)
	if err != nil {
		return nil, fmt.Errorf("unable to open db")
	}
	return NewMockChain(c.log, posEngine, c.GenesisPath, db, &c.TraceLogConfig)
}

func (c *EngineCmd) mockChain() *MockChain {
	return c.backend.mockChain
}

func (c *EngineCmd) startRPC(ctx context.Context) {
	rpcSrv, err := rpc.NewServer("engine", c.backend, true)
	if err != nil {
		c.log.Fatal(err)
	}
	c.rpcSrv = rpcSrv
	c.srv = rpc.NewHTTPServer(ctx, c.log, c.rpcSrv, c.ListenAddr, c.Timeout, c.Cors)
	c.wsSrv = rpc.NewWSServer(ctx, c.log, c.rpcSrv, c.WebsocketAddr, c.jwtSecret, c.Timeout, c.Cors)
}

type EngineBackend struct {
	log              logrus.Ext1FieldLogger
	mockChain        *MockChain
	payloadIdCounter uint64
	recentPayloads   *lru.Cache
}

func NewEngineBackend(log logrus.Ext1FieldLogger, mock *MockChain) (*EngineBackend, error) {
	cache, err := lru.New(10)
	if err != nil {
		return nil, err
	}
	return &EngineBackend{log, mock, 0, cache}, nil
}

func (e *EngineBackend) GetPayloadV1(ctx context.Context, id types.PayloadID) (*types.ExecutionPayloadV1, error) {
	plog := e.log.WithField("payload_id", id)

	payload, ok := e.recentPayloads.Get(id)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpc.Error{Err: fmt.Errorf("unknown payload %d", id), Id: int(api.UnavailablePayload)}
	}

	plog.Info("Consensus client retrieved prepared payload")
	return payload.(*types.ExecutionPayloadV1), nil
}

func (e *EngineBackend) NewPayloadV1(ctx context.Context, payload *types.ExecutionPayloadV1) (*types.PayloadStatusV1, error) {
	log := e.log.WithField("block_hash", payload.BlockHash)
	if !payload.ValidateHash() {
		return &types.PayloadStatusV1{Status: types.ExecutionInvalidBlockHash}, nil
	}
	parent := e.mockChain.chain.GetHeaderByHash(payload.ParentHash)
	if parent == nil {
		log.WithField("parent_hash", payload.ParentHash.String()).Warn("Cannot execute payload, parent is unknown")
		return &types.PayloadStatusV1{Status: types.ExecutionSyncing}, nil
	} else if parent.Difficulty.Cmp(e.mockChain.gspec.Config.TerminalTotalDifficulty) < 0 {
		log.WithField("parent_hash", payload.ParentHash.String()).Warn("Parent block not yet at TTD")
		return &types.PayloadStatusV1{Status: types.ExecutionInvalidTerminalBlock}, nil
	}

	_, err := e.mockChain.ProcessPayload(payload)
	if err != nil {
		log.WithError(err).Error("Failed to execute payload")
		// TODO proper error codes
		return nil, err
	}
	log.Info("Executed payload")
	return &types.PayloadStatusV1{Status: types.ExecutionValid}, nil
}

func (e *EngineBackend) ForkchoiceUpdatedV1(ctx context.Context, heads *types.ForkchoiceStateV1, attributes *types.PayloadAttributesV1) (*types.ForkchoiceUpdatedResult, error) {
	e.log.WithFields(logrus.Fields{
		"head":       heads.HeadBlockHash,
		"safe":       heads.SafeBlockHash,
		"finalized":  heads.FinalizedBlockHash,
		"attributes": attributes,
	}).Info("Forkchoice updated")

	if attributes == nil {
		return &types.ForkchoiceUpdatedResult{PayloadStatus: types.PayloadStatusV1{Status: types.ExecutionValid, LatestValidHash: &heads.HeadBlockHash}}, nil
	}
	idU64 := atomic.AddUint64(&e.payloadIdCounter, 1)
	var id types.PayloadID
	binary.BigEndian.PutUint64(id[:], idU64)

	plog := e.log.WithField("payload_id", id)
	plog.WithField("attributes", attributes).Info("Preparing new payload")

	gasLimit := e.mockChain.gspec.GasLimit
	txsCreator := TransactionsCreator{nil, func(config *params.ChainConfig, bc core.ChainContext,
		statedb *state.StateDB, header *ethTypes.Header, cfg vm.Config, accounts []TestAccount) []*ethTypes.Transaction {
		// empty payload
		// TODO: maybe vary these a little?
		return nil
	}}
	extraData := []byte{}

	bl, err := e.mockChain.AddNewBlock(common.BytesToHash(heads.HeadBlockHash[:]), attributes.SuggestedFeeRecipient, uint64(attributes.Timestamp),
		gasLimit, txsCreator, attributes.PrevRandao, extraData, nil, false)

	if err != nil {
		// TODO: proper error codes
		plog.WithError(err).Error("Failed to create block, cannot build new payload")
		return nil, err
	}

	payload, err := api.BlockToPayload(bl)
	if err != nil {
		plog.WithError(err).Error("Failed to convert block to payload")
		// TODO: proper error codes
		return nil, err
	}

	// store in cache for later retrieval
	e.recentPayloads.Add(id, payload)
	e.recentPayloads.Add(payload.ParentHash, payload)
	fmt.Println("=== added recentPayload", payload.ParentHash.Hex())

	return &types.ForkchoiceUpdatedResult{PayloadStatus: types.PayloadStatusV1{Status: types.ExecutionValid, LatestValidHash: &heads.HeadBlockHash}, PayloadID: &id}, nil
}
