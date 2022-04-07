package main

import (
	"context"
	"fmt"
	. "mergemock/api"
	"mergemock/rpc"
	"net/http"

	"time"

	"github.com/ethereum/go-ethereum/common"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

type RelayCmd struct {
	// connectivity options
	ListenAddr    string      `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	EngineAddr    string      `ask:"--engine" help:"Address of Engine JSON-RPC endpoint to use"`
	Cors          []string    `ask:"--cors" help:"List of allowable origins (CORS http header)"`
	Timeout       rpc.Timeout `ask:".timeout" help:"Configure timeouts of the HTTP servers"`
	JwtSecretPath string      `ask:"--jwt-secret" help:"JWT secret key for authenticated communication"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close     chan struct{}
	log       logrus.Ext1FieldLogger
	ctx       context.Context
	rpcSrv    *rpc.Server
	srv       *http.Server
	jwtSecret []byte
}

func (r *RelayCmd) Default() {
	r.ListenAddr = "127.0.0.1:28545"
	r.EngineAddr = "http://127.0.0.1:8550"
	r.Cors = []string{"*"}
	r.JwtSecretPath = "jwt.hex"

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

	jwt, err := loadJwtSecret(r.JwtSecretPath)
	if err != nil {
		r.log.WithField("err", err).Fatal("Unable to read JWT secret")
	}
	r.jwtSecret = jwt
	r.log.WithField("val", common.Bytes2Hex(r.jwtSecret[:])).Info("Loaded JWT secret")

	// Connect to execution client engine api
	engineClient, err := rpc.DialContext(ctx, r.EngineAddr, r.jwtSecret)
	if err != nil {
		return err
	}

	backend, err := NewRelayBackend(ctx, r.log, engineClient)

	if err != nil {
		r.log.WithField("err", err).Fatal("Unable to initialize backend")
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
	srv, err := rpc.NewServer("relay", backend, true)
	if err != nil {
		r.log.Fatal(err)
	}
	r.rpcSrv = srv
	r.srv = rpc.NewHTTPServer(ctx, r.log, r.rpcSrv, r.ListenAddr, r.Timeout, r.Cors)
}

type RelayBackend struct {
	log              logrus.Ext1FieldLogger
	payloadIdCounter uint64
	recentPayloads   *lru.Cache
	engineClient     *rpc.Client
	ctx              context.Context
}

func NewRelayBackend(ctx context.Context, log logrus.Ext1FieldLogger, engineClient *rpc.Client) (*RelayBackend, error) {
	cache, err := lru.New(10)
	if err != nil {
		return nil, err
	}
	return &RelayBackend{log, 0, cache, engineClient, ctx}, nil
}

func (r *RelayBackend) sendForkchoiceUpdated(latest, safe, final Bytes32, attributes *PayloadAttributesV1) (*ForkchoiceUpdatedResult, error) {
	result, _ := ForkchoiceUpdatedV1(r.ctx, r.engineClient, r.log, latest, safe, final, attributes)
	if result.Status.Status != ExecutionValid {
		return nil, fmt.Errorf("Update not considered valid")
	}
	return &result, nil
}

func (r *RelayBackend) GetPayloadHeaderV1(ctx context.Context, id PayloadID) (*ExecutionPayloadHeaderV1, error) {
	plog := r.log.WithField("payload_id", id)

	payload, err := GetPayloadV1(r.ctx, r.engineClient, r.log, id)
	if err != nil {
		return nil, err
	}

	header, err := PayloadToPayloadHeader(payload)
	if err != nil {
		return nil, err
	}

	r.recentPayloads.Add(id, header)
	r.recentPayloads.Add(payload.BlockHash, payload)

	plog.Info("Consensus client retrieved prepared payload header")
	return header, nil
}

func (r *RelayBackend) ProposeBlindedBlockV1(ctx context.Context, block *SignedBlindedBeaconBlock, attributes *SignedBuilderReceipt) (*ExecutionPayloadV1, error) {
	// TODO: The signed messages should be verified. It should ensure that the signed beacon block is for a validator
	// in the expected slot. The attributes should be verified against the relayer's key.
	hash := block.Message.Body.ExecutionPayload.BlockHash
	plog := r.log.WithField("payload_hash", hash)
	payload, ok := r.recentPayloads.Get(hash)
	if !ok {
		plog.Warn("Cannot get unknown payload")
		return nil, &rpc.Error{Err: fmt.Errorf("unknown payload %d", hash), Id: int(UnavailablePayload)}
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

	return r.sendForkchoiceUpdated(heads.HeadBlockHash, heads.SafeBlockHash, heads.FinalizedBlockHash, attributes)
}
