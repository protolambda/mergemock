package main

import (
	"context"
	"fmt"
	"math/big"
	. "mergemock/api"
	"mergemock/rpc"
	"net/http"
	"time"

	"github.com/flashbots/mev-boost/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

type RelayCmd struct {
	// connectivity options
	ListenAddr string      `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	Cors       []string    `ask:"--cors" help:"List of allowable origins (CORS http header)"`
	Timeout    rpc.Timeout `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	rpcSrv *rpc.Server
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
	srv, err := rpc.NewServer("builder", backend, true)
	if err != nil {
		r.log.Fatal(err)
	}
	r.rpcSrv = srv
	r.srv = rpc.NewHTTPServer(ctx, r.log, r.rpcSrv, r.ListenAddr, r.Timeout, r.Cors)
}

type RelayBackend struct {
	log            logrus.Ext1FieldLogger
	engine         *EngineCmd
	recentPayloads *lru.Cache
}

func NewRelayBackend(log logrus.Ext1FieldLogger) (*RelayBackend, error) {
	engine := &EngineCmd{}
	engine.Default()
	engine.LogCmd.Default()
	engine.ListenAddr = "127.0.0.1:8550"
	engine.WebsocketAddr = "127.0.0.1:8552"
	cache, err := lru.New(10)

	if err != nil {
		return nil, err
	}
	return &RelayBackend{log, engine, cache}, nil
}

func (r *RelayBackend) RegisterValidatorV1(ctx context.Context, message types.RegisterValidatorRequestMessage, signature hexutil.Bytes) (*string, error) {
	res := "OK"
	return &res, nil
}

func (r *RelayBackend) GetHeaderV1(ctx context.Context, slot hexutil.Uint64, pubkey hexutil.Bytes, hash common.Hash) (*types.GetHeaderResponse, error) {
	id := r.engine.backend.mostRecentId
	plog := r.log.WithField("payload_id", id).WithField("hash", hash)
	payload, ok := r.engine.backend.recentPayloads.Get(r.engine.backend.mostRecentId)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpc.Error{Err: fmt.Errorf("unknown payload %d", id), Id: int(UnavailablePayload)}
	}
	payloadHeader, err := PayloadToPayloadHeader(payload.(*ExecutionPayloadV1))
	r.recentPayloads.Add(payloadHeader.BlockHash, payload)
	if err != nil {
		return nil, err
	}
	val := big.NewInt(1)
	plog.Info("Consensus client retrieved prepared payload header")
	return &types.GetHeaderResponse{Message: types.GetHeaderResponseMessage{Header: *payloadHeader, Value: (*hexutil.Big)(val)}}, nil
}

func (r *RelayBackend) GetPayloadV1(ctx context.Context, block types.BlindBeaconBlockV1, signature hexutil.Bytes) (*ExecutionPayloadV1, error) {
	hash := block.Body.ExecutionPayload.BlockHash
	plog := r.log.WithField("blockhash", hash)
	payload, ok := r.recentPayloads.Get(hash)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpc.Error{Err: fmt.Errorf("unknown payload %d", hash), Id: int(UnavailablePayload)}
	}
	plog.Info("Consensus client retrieved prepared payload header")
	return payload.(*ExecutionPayloadV1), nil
}
