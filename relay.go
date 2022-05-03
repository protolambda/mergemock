package main

import (
	"context"
	"fmt"
	. "mergemock/api"
	"mergemock/rpc"
	"mergemock/types"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	lru "github.com/hashicorp/golang-lru"
	"github.com/prysmaticlabs/prysm/shared/bls"
	"github.com/sirupsen/logrus"
)

const (
	UnknownHash         = -32001
	UnknownValidator    = -32002
	UnknownFeeRecipient = -32003
	InvalidSignature    = -32005
)

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

type RelayCmd struct {
	// connectivity options
	ListenAddr string      `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	Cors       []string    `ask:"--cors" help:"List of allowable origins (CORS http header)"`
	Timeout    rpc.Timeout `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close  chan struct{}
	log    *logrus.Logger
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
	log            *logrus.Logger
	engine         *EngineCmd
	recentPayloads *lru.Cache
	pk             types.PublicKey
	sk             bls.SecretKey
}

func NewRelayBackend(log *logrus.Logger) (*RelayBackend, error) {
	engine := &EngineCmd{}
	engine.Default()
	engine.LogCmd.Default()
	engine.ListenAddr = "127.0.0.1:8550"
	engine.WebsocketAddr = "127.0.0.1:8552"
	cache, err := lru.New(10)
	if err != nil {
		return nil, err
	}
	sk, _ := bls.RandKey()
	var pk types.PublicKey
	copy(pk[:], sk.PublicKey().Marshal())
	return &RelayBackend{log, engine, cache, pk, sk}, nil
}

type hashTreeRoot interface {
	HashTreeRoot() ([32]byte, error)
}

func verifySignature(obj hashTreeRoot, pk, s []byte) (bool, error) {
	msg, err := obj.HashTreeRoot()
	if err != nil {
		return false, err
	}
	sig, err := bls.SignatureFromBytes(s)
	if err != nil {
		return false, err
	}
	pubkey, err := bls.PublicKeyFromBytes(pk)
	if err != nil {
		return false, err
	}
	return sig.Verify(pubkey, msg[:]), nil
}

func (r *RelayBackend) RegisterValidatorV1(ctx context.Context, message types.RegisterValidatorRequestMessage, signature hexutil.Bytes) (*string, error) {
	ok, err := verifySignature(&message, message.Pubkey[:], signature)
	if !ok || err != nil {
		log.Error("invalid signature", "err", err)
		return nil, &rpc.Error{Err: fmt.Errorf("invalid signature"), Id: int(InvalidSignature)}
	}
	// TODO: update mapping
	res := "OK"
	return &res, nil
}

func (r *RelayBackend) GetHeaderV1(ctx context.Context, slot hexutil.Uint64, pubkey hexutil.Bytes, parentHash common.Hash) (*types.SignedBuilderBidV1, error) {
	plog := r.log.WithField("parentHash", parentHash)
	payload, ok := r.engine.backend.recentPayloads.Get(parentHash)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpc.Error{Err: fmt.Errorf("unknown hash %d", parentHash), Id: int(UnknownHash)}
	}
	payloadHeader, err := types.PayloadToPayloadHeader(payload.(*types.ExecutionPayloadV1))
	r.recentPayloads.Add(payloadHeader.BlockHash, payload)
	if err != nil {
		return nil, err
	}
	plog.Info("Consensus client retrieved prepared payload header")

	bid := types.BuilderBidV1{Header: payloadHeader, Value: [32]byte{0x1}, Pubkey: r.pk}
	msg, err := bid.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	var sig types.Signature
	tmp := r.sk.Sign(msg[:])
	copy(sig[:], tmp.Marshal())
	return &types.SignedBuilderBidV1{Message: &bid, Signature: sig}, nil
}

func (r *RelayBackend) GetPayloadV1(ctx context.Context, block types.BlindedBeaconBlockV1, signature hexutil.Bytes) (*types.ExecutionPayloadV1, error) {
	hash := block.Body.ExecutionPayloadHeader.BlockHash
	plog := r.log.WithField("blockhash", hash)
	payload, ok := r.recentPayloads.Get(hash)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpc.Error{Err: fmt.Errorf("unknown payload %d", hash), Id: int(UnavailablePayload)}
	}
	plog.Info("Consensus client retrieved prepared payload header")
	return payload.(*types.ExecutionPayloadV1), nil
}
