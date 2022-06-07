package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mergemock/rpc"
	"mergemock/types"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
	"github.com/prysmaticlabs/prysm/crypto/bls"
	"github.com/prysmaticlabs/prysm/runtime/version"
	"github.com/sirupsen/logrus"
)

const (
	UnknownHash         = -32001
	UnknownValidator    = -32002
	UnknownFeeRecipient = -32003
	InvalidSignature    = -32005
)

var (
	errInvalidSlot      = errors.New("invalid slot")
	errInvalidHash      = errors.New("invalid hash")
	errInvalidPubkey    = errors.New("invalid pubkey")
	errInvalidSignature = errors.New("invalid signature")
	errInvalidTimestamp = errors.New("invalid timestamp")

	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"
)

type RelayCmd struct {
	// connectivity options
	ListenAddr         string `ask:"--listen-addr" help:"Address to bind relay HTTP server to"`
	EngineListenAddr   string `ask:"--engine-listen-addr" help:"Address to bind engine JSON-RPC server to"`
	EngineListenAddrWs string `ask:"--engine-listen-addr-ws" help:"Address to bind engine JSON-RPC WebSocket server to"`

	// embed timeout and logger options
	Timeout rpc.Timeout `ask:".timeout" help:"Configure timeouts of the HTTP servers"`
	LogCmd  `ask:".log" help:"Change logger configuration"`

	GenesisValidatorsRoot string `ask:"--genesis-validators-root" help:"Root of genesis validators"`

	SecretKey string `ask:"--secret-key" help:"The relay's secret key used to sign payloads"`

	close chan struct{}
	log   *logrus.Logger
	ctx   context.Context
	srv   *http.Server
}

func (r *RelayCmd) Default() {
	r.ListenAddr = "127.0.0.1:28545"
	r.EngineListenAddr = "127.0.0.1:8551"
	r.EngineListenAddrWs = "127.0.0.1:8552"

	r.GenesisValidatorsRoot = "0x0000000000000000000000000000000000000000000000000000000000000000"

	r.Timeout.Read = 30 * time.Second
	r.Timeout.ReadHeader = 10 * time.Second
	r.Timeout.Write = 30 * time.Second
	r.Timeout.Idle = 5 * time.Minute

	sk, _ := bls.RandKey()
	r.SecretKey = hex.EncodeToString(sk.Marshal())
}

func (r *RelayCmd) Help() string {
	return "Run a mock builder relay."
}

func (r *RelayCmd) Run(ctx context.Context, args ...string) error {
	r.ctx = ctx
	r.close = make(chan struct{})
	if err := r.initLogger(ctx); err != nil {
		// Logger wasn't initialized so we can't log. Error out instead.
		return err
	}
	backend, err := NewRelayBackend(r.log, r.EngineListenAddr, r.EngineListenAddrWs, r.GenesisValidatorsRoot, r.SecretKey)
	if err != nil {
		r.log.WithField("err", err).Fatal("Unable to initialize backend")
	}
	if err := backend.engine.Run(ctx); err != nil {
		r.log.WithField("err", err).Fatal("Unable to initialize engine")
	}
	go r.startRESTApi(ctx, backend)
	return nil
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

	r.log.WithField("listenAddr", r.ListenAddr).Info("Relay started")
	go r.srv.ListenAndServe()
	for range r.close {
		r.srv.Close()
		return
	}
}

type RelayBackend struct {
	log    *logrus.Logger
	engine *EngineCmd
	pk     types.PublicKey
	sk     bls.SecretKey

	genesisValidatorsRoot types.Root
	registrations         map[types.PublicKey]*types.RegisterValidatorRequestMessage

	latestPubkey types.PublicKey // cache for pubkey from latest getHeader call
}

func NewRelayBackend(log *logrus.Logger, engineListenAddr, engineListenAddrWs, genesisValidatorsRoot, secretKey string) (*RelayBackend, error) {
	engine := &EngineCmd{}
	engine.Default()
	engine.LogCmd.Default()
	engine.ListenAddr = engineListenAddr
	engine.WebsocketAddr = engineListenAddrWs

	skBytes, err := hex.DecodeString(secretKey)
	if err != nil {
		return nil, err
	}
	sk, err := bls.SecretKeyFromBytes(skBytes)
	if err != nil {
		return nil, err
	}
	var pk types.PublicKey
	copy(pk[:], sk.PublicKey().Marshal())

	registrations := make(map[types.PublicKey]*types.RegisterValidatorRequestMessage)

	return &RelayBackend{
		log:                   log,
		engine:                engine,
		pk:                    pk,
		sk:                    sk,
		genesisValidatorsRoot: types.Root(common.HexToHash(genesisValidatorsRoot)),
		registrations:         registrations,
	}, nil
}

func (r *RelayBackend) getRouter() http.Handler {
	router := mux.NewRouter()

	// Add routes
	router.HandleFunc(pathStatus, r.handleStatus).Methods(http.MethodGet)
	router.HandleFunc(pathRegisterValidator, r.handleRegisterValidator).Methods(http.MethodPost)
	router.HandleFunc(pathGetHeader, r.handleGetHeader).Methods(http.MethodGet)
	router.HandleFunc(pathGetPayload, r.handleGetPayload).Methods(http.MethodPost)

	// Add logging and return router
	loggedRouter := LoggingMiddleware(router, r.log)
	return loggedRouter
}

func (r *RelayBackend) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (r *RelayBackend) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	payload := make([]types.SignedValidatorRegistration, 0)
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, reg := range payload {
		if len(reg.Message.Pubkey) != 48 {
			http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
			return
		}
		if len(reg.Signature) != 96 {
			http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
			return
		}
		ok, err := types.VerifySignature(reg.Message, types.DomainBuilder, reg.Message.Pubkey[:], reg.Signature[:])
		if !ok || err != nil {
			r.log.WithError(err).Error("error verifying signature")
			http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
			return
		}
		if prefs, ok := r.registrations[reg.Message.Pubkey]; ok {
			if prefs.Timestamp <= reg.Message.Timestamp {
				http.Error(w, errInvalidTimestamp.Error(), http.StatusBadRequest)
				return
			}
		}
		// Note, successful registrations are not reverted if an error
		// is encountered on a later validator.
		r.registrations[reg.Message.Pubkey] = reg.Message
	}
	r.log.Info(fmt.Sprintf("registered %d validator(s) successfully\n", len(payload)))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
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

	if _, err := strconv.ParseInt(slot, 10, 64); err != nil {
		http.Error(w, errInvalidSlot.Error(), http.StatusBadRequest)
		return
	}

	if len(pubkey) != 98 {
		http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
		return
	}

	if len(parentHashHex) != 66 {
		http.Error(w, errInvalidHash.Error(), http.StatusBadRequest)
		return
	}

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

	plog.Info("Consensus client retrieved prepared payload header")

	bid := types.BuilderBid{
		Header: payloadHeader,
		Value:  [32]byte{0x1},
		Pubkey: r.pk,
	}
	msg, err := types.ComputeSigningRoot(&bid, types.DomainBuilder)
	if err != nil {
		plog.Warn("cannot compute signing root")
		http.Error(w, "cannot compute signing root", http.StatusBadRequest)
		return
	}
	var sig types.Signature
	tmp := r.sk.Sign(msg[:])
	copy(sig[:], tmp.Marshal())
	response := &types.GetHeaderResponse{
		Version: "bellatrix",
		Data:    &types.SignedBuilderBid{Message: &bid, Signature: sig},
	}

	if err = r.latestPubkey.UnmarshalText([]byte(pubkey)); err != nil {
		plog.Warn("Cannot unmarshal pubkey")
		http.Error(w, "cannot unmarshal pubkey", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (r *RelayBackend) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	plog := r.log.WithField("method", "getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Signature) != 96 {
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	domain := types.ComputeDomain(types.DomainTypeBeaconProposer, version.Bellatrix, &r.genesisValidatorsRoot)
	ok, err := types.VerifySignature(payload.Message, domain, r.latestPubkey[:], payload.Signature[:])
	if !ok || err != nil {
		plog.WithError(err).Error("error verifying signature")
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	parentHashHex := payload.Message.Body.ExecutionPayloadHeader.ParentHash.String()
	_execPayloadEL, ok := r.engine.backend.recentPayloads.Get(common.HexToHash(parentHashHex))
	if !ok {
		plog.Warn("Cannot get unknown payload")
		http.Error(w, "Cannot get unknown payload", http.StatusBadRequest)
		return
	}
	plog.Info(_execPayloadEL)

	execPayload, err := types.ELPayloadToRESTPayload(_execPayloadEL.(*types.ExecutionPayloadV1))
	if err != nil {
		plog.Warn("Cannot convert payload to payloadREST")
		http.Error(w, "cannot convert payload to payloadREST", http.StatusBadRequest)
		return
	}

	response := types.GetPayloadResponse{
		Version: "bellatrix",
		Data:    execPayload,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
