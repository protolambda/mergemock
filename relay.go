package main

import (
	"context"
	"encoding/json"
	"errors"
	"mergemock/rpc"
	"mergemock/types"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/mux"
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

var (
	errInvalidPubkey    = errors.New("invalid pubkey")
	errInvalidSignature = errors.New("invalid signature")

	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
)

type RelayCmd struct {
	// connectivity options
	ListenAddr string      `ask:"--listen-addr" help:"Address to bind HTTP server to"`
	Cors       []string    `ask:"--cors" help:"List of allowable origins (CORS http header)"`
	Timeout    rpc.Timeout `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close chan struct{}
	log   *logrus.Logger
	ctx   context.Context
	srv   *http.Server
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
	r.startRESTApi(ctx, backend)
	go r.RunNode()
	log.Info("Relay listening on " + r.ListenAddr)
	return nil
}

func (r *RelayCmd) RunNode() {
	r.log.Info("started")
	go r.srv.ListenAndServe()
	for range r.close {
		r.srv.Close()
		return
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

func (r *RelayCmd) startRESTApi(ctx context.Context, backend *RelayBackend) {
	r.srv = &http.Server{
		Addr:    r.ListenAddr,
		Handler: backend.getRouter(),

		ReadTimeout:       r.Timeout.Read,
		ReadHeaderTimeout: r.Timeout.ReadHeader,
		WriteTimeout:      r.Timeout.Write,
		IdleTimeout:       r.Timeout.Idle,
	}
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

func (r *RelayBackend) getRouter() http.Handler {
	router := mux.NewRouter()

	// Add routes
	router.HandleFunc(pathStatus, r.handleStatus).Methods(http.MethodGet)
	router.HandleFunc(pathRegisterValidator, r.handleRegisterValidator).Methods(http.MethodPost)
	router.HandleFunc(pathGetHeader, r.handleGetHeader).Methods(http.MethodGet)

	// Add logging and return router
	loggedRouter := LoggingMiddleware(router, r.log)
	return loggedRouter
}

func (r *RelayBackend) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (r *RelayBackend) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	payload := new(types.RegisterValidatorRequest)
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Message.Pubkey) != 48 {
		http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Signature) != 96 {
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	ok, err := verifySignature(payload.Message, payload.Message.Pubkey[:], payload.Signature)
	if !ok || err != nil {
		r.log.WithError(err).Error("error verifying signature")
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	// TODO: update mapping

	w.WriteHeader(http.StatusOK)
}

func (r *RelayBackend) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot := vars["slot"]
	parentHashHex := vars["parent_hash"]
	pubkey := vars["pubkey"]
	plog := r.log.WithFields(logrus.Fields{
		"slot":       slot,
		"parentHash": parentHashHex,
		"pubkey":     pubkey,
	})
	plog.Info("getHeader")

	payload, ok := r.engine.backend.recentPayloads.Get(common.HexToHash(parentHashHex))
	if !ok {
		plog.Warn("Cannot get unknown payload")
		http.Error(w, "Cannot get unknown payload", http.StatusBadRequest)
		return
	}

	payloadHeader, err := types.PayloadToPayloadHeader(payload.(*types.ExecutionPayloadV1))
	if err != nil {
		plog.Warn("Cannot convert payload to header")
		http.Error(w, "cannot convert payload to header", http.StatusBadRequest)
		return
	}

	r.recentPayloads.Add(payloadHeader.BlockHash, payload)
	plog.Info("Consensus client retrieved prepared payload header")

	bid := types.BuilderBid{
		Header: payloadHeader,
		Value:  [32]byte{0x1},
		Pubkey: r.pk,
	}
	msg, err := bid.HashTreeRoot()
	if err != nil {
		plog.Warn("cannot compute hash tree root")
		http.Error(w, "cannot compute hash tree root", http.StatusBadRequest)
		return
	}
	var sig types.Signature
	tmp := r.sk.Sign(msg[:])
	copy(sig[:], tmp.Marshal())
	response := &types.GetHeaderResponse{
		Version: "bellatrix",
		Data:    &types.SignedBuilderBid{Message: &bid, Signature: sig},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// func (r *RelayBackend) GetHeaderV1(ctx context.Context, slot hexutil.Uint64, pubkey hexutil.Bytes, parentHash common.Hash) (*types.SignedBuilderBidV1, error) {
// 	plog := r.log.WithField("parentHash", parentHash)
// }

// func (r *RelayBackend) GetPayloadV1(ctx context.Context, block types.BlindedBeaconBlockV1, signature hexutil.Bytes) (*types.ExecutionPayloadV1, error) {
// 	hash := block.Body.ExecutionPayloadHeader.BlockHash
// 	plog := r.log.WithField("blockhash", hash)
// 	payload, ok := r.recentPayloads.Get(hash)
// 	if !ok {
// 		plog.Warn("Cannot get unknown payload")
// 		return nil, &rpc.Error{Err: fmt.Errorf("unknown payload %d", hash), Id: int(api.UnavailablePayload)}
// 	}
// 	plog.Info("Consensus client retrieved prepared payload header")
// 	return payload.(*types.ExecutionPayloadV1), nil
// }
