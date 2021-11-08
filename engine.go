package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"

	gethnode "github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type EngineCmd struct {
	// TODO options

	SlotsPerEpoch uint64 `ask:"--slots-per-epoch" help:"Slots per epoch"`

	DataDir     string `ask:"--datadir" help:"Directory to store execution chain data (empty for in-memory data)"`
	GenesisPath string `ask:"--genesis" help:"Genesis execution-config file"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	TraceLogConfig `ask:".trace" help:"Tracing options"`

	ListenAddr    string `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	WebsocketAddr string `ask:"--ws-addr" help:"Address to serve /ws endpoint on for websocket JSON-RPC"`

	Cors []string `ask:"--cors" help:"List of allowable origins (CORS http header)"`

	Timeout struct {
		Read       time.Duration `ask:"--read" help:"Timeout for body reads. None if 0."`
		ReadHeader time.Duration `ask:"--read-header" help:"Timeout for header reads. None if 0."`
		Write      time.Duration `ask:"--write" help:"Timeout for writes. None if 0."`
		Idle       time.Duration `ask:"--idle" help:"Timeout to disconnect idle client connections. None if 0."`
	} `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	rpcSrv *rpc.Server
	srv    *http.Server
	// upgrades to websocket rpc
	wsSrv *http.Server
}

func (c *EngineCmd) Default() {
	c.GenesisPath = "genesis.json"

	c.ListenAddr = "127.0.0.1:8550"
	c.WebsocketAddr = "127.0.0.1:8551"

	c.Cors = []string{"*"}

	c.Timeout.Read = 30 * time.Second
	c.Timeout.ReadHeader = 10 * time.Second
	c.Timeout.Write = 30 * time.Second
	c.Timeout.Idle = 5 * time.Minute
}

func (c *EngineCmd) Help() string {
	return "Run a mock Execution Engine."
}

func (c *EngineCmd) Run(ctx context.Context, args ...string) error {
	logr, err := c.LogCmd.Create()
	if err != nil {
		return err
	}
	c.log = logr
	c.ctx = ctx
	c.close = make(chan struct{})

	posEngine := &ExecutionConsensusMock{
		pow: nil, // TODO: do we even need this?
		log: c.log,
	}

	db, err := NewDB(c.DataDir)
	if err != nil {
		logr.WithField("err", err).Error("Unable to open db")
		os.Exit(1)
	}
	chain, err := NewMockChain(logr, posEngine, c.GenesisPath, db, &c.TraceLogConfig)
	if err != nil {
		logr.WithField("err", err).Error("Unable to initialize mock chain")
		os.Exit(1)
	}

	recentPayloadsCache, err := lru.New(10)
	backend := &EngineBackend{log: logr, mockChain: chain, recentPayloads: recentPayloadsCache}

	c.rpcSrv = rpc.NewServer()
	c.rpcSrv.RegisterName("engine", backend)
	wrappedRpc := gethnode.NewHTTPHandlerStack(c.rpcSrv, c.Cors, nil)

	mux := http.NewServeMux()
	mux.Handle("/", wrappedRpc)
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte("wrong port, use the websocket port"))
		logr.WithField("addr", r.RemoteAddr).Warn("User tried to connect to websocket on HTTP port")
	})

	// log http errors to our logrus logger
	logHttp := logr.WithField("type", "http")

	c.srv = &http.Server{
		Addr:              c.ListenAddr,
		Handler:           mux,
		ReadTimeout:       c.Timeout.Read,
		ReadHeaderTimeout: c.Timeout.ReadHeader,
		WriteTimeout:      c.Timeout.Write,
		IdleTimeout:       c.Timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logHttp.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed connection state")
		},
		ErrorLog: log.New(logHttp.Writer(), "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	wsHandler := c.rpcSrv.WebsocketHandler(c.Cors)

	wsMux := http.NewServeMux()
	wsMux.Handle("/", wsHandler)
	wsMux.Handle("/ws", wsHandler)

	logWs := logr.WithField("type", "ws")

	c.wsSrv = &http.Server{
		Addr:              c.WebsocketAddr,
		Handler:           wsHandler,
		ReadTimeout:       c.Timeout.Read,
		ReadHeaderTimeout: c.Timeout.ReadHeader,
		WriteTimeout:      c.Timeout.Write,
		IdleTimeout:       c.Timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logWs.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed connection state")
		},
		ErrorLog: log.New(logWs.Writer(), "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	go c.RunNode()

	return nil
}

func (c *EngineCmd) RunNode() {
	c.log.Info("started")

	go c.srv.ListenAndServe()
	go c.wsSrv.ListenAndServe()

	for {
		select {
		case <-c.close:
			c.rpcSrv.Stop()
			c.srv.Close()
			c.wsSrv.Close()
			return
			// TODO: any other tasks to run in this loop? mock sync changes?
		}
	}
}

func (c *EngineCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}

type EngineBackend struct {
	payloadIdCounter uint64

	log       logrus.Ext1FieldLogger
	mockChain *MockChain

	recentPayloads *lru.Cache
}

func (e *EngineBackend) GetPayloadV1(ctx context.Context, id PayloadID) (*ExecutionPayload, error) {
	plog := e.log.WithField("payload_id", id)

	payload, ok := e.recentPayloads.Get(id)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpcError{err: fmt.Errorf("unknown payload %d", id), id: UnavailablePayload}
	}

	plog.Info("Consensus client retrieved prepared payload")
	return payload.(*ExecutionPayload), nil
}

func (e *EngineBackend) ExecutePayloadV1(ctx context.Context, payload *ExecutionPayload) (*ExecutePayloadResult, error) {
	log := e.log.WithField("block_hash", payload.BlockHash)
	parent := e.mockChain.chain.GetHeaderByHash(payload.ParentHash)
	if parent == nil {
		log.WithField("parent_hash", payload.ParentHash.String()).Warn("Cannot execute payload, parent is unknown")
		// TODO
		return &ExecutePayloadResult{Status: ExecutionSyncing}, nil
	}

	_, err := e.mockChain.ProcessPayload(payload)
	if err != nil {
		log.WithError(err).Error("Failed to execute payload")
		// TODO proper error codes
		return nil, err
	}
	log.Info("Executed payload")
	return &ExecutePayloadResult{Status: ExecutionValid}, nil
}

func (e *EngineBackend) ForkchoiceUpdatedV1(ctx context.Context, heads *ForkchoiceState, attributes *PayloadAttributes) (*ForkchoiceUpdatedResult, error) {
	e.log.WithFields(logrus.Fields{
		"head":       heads.HeadBlockHash,
		"safe":       heads.SafeBlockHash,
		"finalized":  heads.FinalizedBlockHash,
		"attributes": attributes,
	}).Info("Forkchoice updated")

	if attributes == nil {
		return nil, nil
	}
	idU64 := atomic.AddUint64(&e.payloadIdCounter, 1)
	var id PayloadID
	binary.BigEndian.PutUint64(id[:], idU64)

	plog := e.log.WithField("payload_id", id)
	plog.WithField("attributes", attributes).Info("Preparing new payload")

	gasLimit := e.mockChain.gspec.GasLimit
	txsCreator := TransactionsCreator(func(config *params.ChainConfig, bc core.ChainContext,
		statedb *state.StateDB, header *types.Header, cfg vm.Config) []*types.Transaction {
		// empty payload

		// TODO: maybe vary these a little?
		return nil
	})
	extraData := []byte{}

	bl, err := e.mockChain.AddNewBlock(common.BytesToHash(heads.HeadBlockHash[:]), attributes.FeeRecipient, uint64(attributes.Timestamp),
		gasLimit, txsCreator, extraData, nil, false)

	if err != nil {
		// TODO: proper error codes
		plog.WithError(err).Error("Failed to create block, cannot build new payload")
		return nil, err
	}

	payload, err := BlockToPayload(bl, attributes.Random)
	if err != nil {
		plog.WithError(err).Error("Failed to convert block to payload")
		// TODO: proper error codes
		return nil, err
	}

	// store in cache for later retrieval
	e.recentPayloads.Add(id, payload)

	return &ForkchoiceUpdatedResult{Status: UpdateSuccess, PayloadID: id}, nil
}
