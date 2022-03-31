package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	. "mergemock/api"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

type RelayCmd struct {
	// connectivity options
	ListenAddr string   `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	Cors       []string `ask:"--cors" help:"List of allowable origins (CORS http header)"`
	Timeout    struct {
		Read       time.Duration `ask:"--read" help:"Timeout for body reads. None if 0."`
		ReadHeader time.Duration `ask:"--read-header" help:"Timeout for header reads. None if 0."`
		Write      time.Duration `ask:"--write" help:"Timeout for writes. None if 0."`
		Idle       time.Duration `ask:"--idle" help:"Timeout to disconnect idle client connections. None if 0."`
	} `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	rpcSrv *gethRpc.Server
	srv    *http.Server
}

func (r *RelayCmd) Default() {
	r.ListenAddr = "127.0.0.1:28545"
	r.Cors = []string{"*"}

	r.Timeout.Read = 30 * time.Second
	r.Timeout.ReadHeader = 10 * time.Second
	r.Timeout.Write = 30 * time.Second
	r.Timeout.Idle = 5 * time.Minute
}

func (r *RelayCmd) Help() string {
	return "Run a mock relayer."
}

func (r *RelayCmd) Run(ctx context.Context, args ...string) error {
	if err := r.initLogger(ctx); err != nil {
		// Logger wasn't initialized so we can't log. Error out instead.
		return err
	}
	backend, err := NewRelayBackend(r.log)
	if err != nil {
		r.log.WithField("err", err).Fatal("Unable to initialize backend")
	}
	if err := backend.engine.Run(ctx); err != nil {
		r.log.WithField("err", err).Fatal("Unable to initialize engine")
	}
	r.startRPC(ctx, backend)
	go r.RunNode()
	return nil
}

func (r *RelayCmd) RunNode() {
	r.log.Info("started")
	go r.srv.ListenAndServe()
	for {
		select {
		case <-r.close:
			r.rpcSrv.Stop()
			r.srv.Close()
			return
		}
	}
}

func (r *RelayCmd) Close() error {
	if r.close != nil {
		r.close <- struct{}{}
	}
	return nil
}

func (r *RelayCmd) initLogger(ctx context.Context) error {
	logr, err := r.LogCmd.Create()
	if err != nil {
		return err
	}
	r.log = logr
	r.ctx = ctx
	r.close = make(chan struct{})
	return nil
}

func (r *RelayCmd) startRPC(ctx context.Context, backend *RelayBackend) {
	r.rpcSrv = gethRpc.NewServer()
	r.rpcSrv.RegisterName("relay", backend)
	apis := []gethRpc.API{
		{
			Namespace:     "relay",
			Version:       "1.0",
			Service:       backend,
			Public:        true,
			Authenticated: true,
		},
	}
	if err := node.RegisterApis(apis, []string{"relay"}, r.rpcSrv, false); err != nil {
		r.log.WithField("err", err).Fatal("could not register api")
	}

	httpRpcHandler := node.NewHTTPHandlerStack(r.rpcSrv, r.Cors, nil, nil)
	mux := http.NewServeMux()
	mux.Handle("/", httpRpcHandler)
	mux.HandleFunc("/ws", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte("wrong port, use the websocket port"))
		r.log.WithField("addr", req.RemoteAddr).Warn("User tried to connect to websocket on HTTP port")
	})
	logHttp := r.log.WithField("type", "http")
	r.srv = &http.Server{
		Addr:              r.ListenAddr,
		Handler:           mux,
		ReadTimeout:       r.Timeout.Read,
		ReadHeaderTimeout: r.Timeout.ReadHeader,
		WriteTimeout:      r.Timeout.Write,
		IdleTimeout:       r.Timeout.Idle,
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
}

type RelayBackend struct {
	log              logrus.Ext1FieldLogger
	engine           *EngineCmd
	payloadIdCounter uint64
	recentPayloads   *lru.Cache
}

func NewRelayBackend(log logrus.Ext1FieldLogger) (*RelayBackend, error) {
	engine := &EngineCmd{}
	engine.Default()
	engine.LogCmd.Default()
	engine.ListenAddr = "127.0.0.1:28546"
	engine.WebsocketAddr = "127.0.0.1:28547"
	cache, err := lru.New(10)
	if err != nil {
		return nil, err
	}
	return &RelayBackend{log, engine, 0, cache}, nil
}

func (r *RelayBackend) GetPayloadHeaderV1(ctx context.Context, id PayloadID) (*ExecutionPayloadHeaderV1, error) {
	plog := r.log.WithField("payload_id", id)
	payload, ok := r.recentPayloads.Get(id)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpcError{err: fmt.Errorf("unknown payload %d", id), id: UnavailablePayload}
	}
	plog.Info("Consensus client retrieved prepared payload header")
	return payload.(*ExecutionPayloadHeaderV1), nil
}

func (r *RelayBackend) ProposeBlindedBlockV1(ctx context.Context, block *SignedBlindedBeaconBlock, attributes *SignedBuilderReceipt) (*ExecutionPayloadV1, error) {
	// TODO: The signed messages should be verified. It should ensure that the signed beacon block is for a validator
	// in the expected slot. The attributes should be verified against the relayer's key.
	hash := block.Message.Body.ExecutionPayload.BlockHash
	plog := r.log.WithField("payload_hash", hash)
	payload, ok := r.recentPayloads.Get(hash)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpcError{err: fmt.Errorf("unknown payload %d", hash), id: UnavailablePayload}
	}
	plog.Info("Consensus client retrieved prepared payload header")
	return payload.(*ExecutionPayloadV1), nil
}

func (r *RelayBackend) ForkchoiceUpdatedV1(ctx context.Context, heads *ForkchoiceStateV1, attributes *PayloadAttributesV1) (*ForkchoiceUpdatedResult, error) {
	r.log.WithFields(logrus.Fields{
		"head":       heads.HeadBlockHash,
		"safe":       heads.SafeBlockHash,
		"finalized":  heads.FinalizedBlockHash,
		"attributes": attributes,
	}).Info("Forkchoice updated")

	if attributes == nil {
		return &ForkchoiceUpdatedResult{Status: PayloadStatusV1{Status: ExecutionValid, LatestValidHash: &heads.HeadBlockHash}}, nil
	}
	idU64 := atomic.AddUint64(&r.payloadIdCounter, 1)
	var id PayloadID
	binary.BigEndian.PutUint64(id[:], idU64)

	plog := r.log.WithField("payload_id", id)
	plog.WithField("attributes", attributes).Info("Preparing new payload")

	gasLimit := r.engine.mockChain().gspec.GasLimit
	txsCreator := TransactionsCreator{nil, func(config *params.ChainConfig, bc core.ChainContext,
		statedb *state.StateDB, header *types.Header, cfg vm.Config, accounts []TestAccount) []*types.Transaction {
		// empty payload
		// TODO: maybe vary these a little?
		return nil
	}}
	extraData := []byte{}

	bl, err := r.engine.mockChain().AddNewBlock(common.BytesToHash(heads.HeadBlockHash[:]), attributes.SuggestedFeeRecipient, uint64(attributes.Timestamp),
		gasLimit, txsCreator, attributes.PrevRandao, extraData, nil, false)

	if err != nil {
		// TODO: proper error codes
		plog.WithError(err).Error("Failed to create block, cannot build new payload")
		return nil, err
	}

	payload, err := BlockToPayload(bl)
	if err != nil {
		plog.WithError(err).Error("Failed to convert block to payload")
		// TODO: proper error codes
		return nil, err
	}

	header, err := PayloadToPayloadHeader(payload)
	if err != nil {
		return nil, err
	}

	// Store header by id and full block by hash. This mirrors the retrieval flow.
	r.recentPayloads.Add(id, header)
	r.recentPayloads.Add(bl.Hash(), payload)

	return &ForkchoiceUpdatedResult{Status: PayloadStatusV1{Status: ExecutionValid, LatestValidHash: &heads.HeadBlockHash}, PayloadID: &id}, nil
}
