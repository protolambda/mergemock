package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mergemock/api"
	"mergemock/types"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/prysmaticlabs/prysm/crypto/bls"
	"github.com/prysmaticlabs/prysm/runtime/version"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type testRelayBackend struct {
	*RelayBackend
}

func newTestRelay(t *testing.T) *testRelayBackend {
	relay, err := NewRelayBackend(logrus.New(), "127.0.0.1:38551", "127.0.0.1:38552", "0x1234000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal("unable to create relay")
	}

	testRelay := testRelayBackend{relay}
	testRelay.engine.JwtSecretPath = newJwt(t)
	testRelay.engine.GenesisPath = newGenesis(t)
	return &testRelay
}

func (mr *testRelayBackend) testRequest(t *testing.T, method string, path string, payload any) *httptest.ResponseRecorder {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequest(method, path, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		require.NoError(t, err2)
		req, err = http.NewRequest(method, path, bytes.NewReader(payloadBytes))
	}

	require.NoError(t, err)
	rr := httptest.NewRecorder()
	mr.getRouter().ServeHTTP(rr, req)
	return rr
}

func newKeypair(t *testing.T) (pubkey []byte, privkey bls.SecretKey) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatal("unable to generate bls key pair", err)
	}
	return sk.PublicKey().Marshal(), sk
}

func newJwt(t *testing.T) string {
	path := fmt.Sprintf("%s/jwt.hex", t.TempDir())
	jwt := []byte("ed6588309287e7dbbb0ca2ba8c8be6e6063a72dc0f2235999ee6a751e8459cbc")
	if err := os.WriteFile(path, jwt, 0644); err != nil {
		t.Fatal("unable to write tmp jwt file")
	}
	return path
}

func newGenesis(t *testing.T) string {
	path := fmt.Sprintf("%s/genesis.json", t.TempDir())
	genesis := core.DeveloperGenesisBlock(5, 30_000_000, common.Address{})
	genesis.Config.MergeForkBlock = common.Big0
	genesis.Config.TerminalTotalDifficulty = common.Big0
	buf, err := genesis.MarshalJSON()
	if err != nil {
		t.Fatal("cannot marshal tmp genesis")
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal("unable to write tmp genesis file")
	}
	return path
}

func TestStatusEndpoint(t *testing.T) {
	relay := newTestRelay(t)
	rr := relay.testRequest(t, "GET", "/eth/v1/builder/status", nil)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestValidatorRegistration(t *testing.T) {
	relay := newTestRelay(t)
	pk1, sk1 := newKeypair(t)
	pk2, sk2 := newKeypair(t)

	var pubkey1 types.PublicKey
	var pubkey2 types.PublicKey
	pubkey1.FromSlice(pk1)
	pubkey2.FromSlice(pk2)

	msg1 := &types.RegisterValidatorRequestMessage{
		FeeRecipient: types.Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    uint64(time.Now().Unix()),
		Pubkey:       pubkey1,
	}
	msg2 := &types.RegisterValidatorRequestMessage{
		FeeRecipient: types.Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    uint64(time.Now().Unix()),
		Pubkey:       pubkey2,
	}
	root1, err := types.ComputeSigningRoot(msg1, types.DomainBuilder)
	require.NoError(t, err)
	root2, err := types.ComputeSigningRoot(msg2, types.DomainBuilder)
	require.NoError(t, err)

	// Success
	var sig1 types.Signature
	sig1.FromSlice(sk1.Sign(root1[:]).Marshal())
	var sig2 types.Signature
	sig2.FromSlice(sk2.Sign(root2[:]).Marshal())

	rr := relay.testRequest(t, "POST", "/eth/v1/builder/validators", []types.SignedValidatorRegistration{
		{
			Message:   msg1,
			Signature: sig1,
		},
		{
			Message:   msg2,
			Signature: sig2,
		},
	})
	require.Equal(t, http.StatusOK, rr.Code)

	// Invalid signature
	sig1[len(sig1)-1] = 0x00
	rr = relay.testRequest(t, "POST", "/eth/v1/builder/validators", []types.SignedValidatorRegistration{
		{
			Message:   msg1,
			Signature: sig1,
		},
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, errInvalidSignature.Error()+"\n", rr.Body.String())

	// Old registration
	msg := &types.RegisterValidatorRequestMessage{
		FeeRecipient: types.Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    msg1.Timestamp,
		Pubkey:       pubkey1,
	}
	root, err := types.ComputeSigningRoot(msg, types.DomainBuilder)
	var sig types.Signature
	sig.FromSlice(sk1.Sign(root[:]).Marshal())
	require.NoError(t, err)
	rr = relay.testRequest(t, "POST", "/eth/v1/builder/validators", []types.SignedValidatorRegistration{
		{
			Message:   msg,
			Signature: sig,
		},
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, errInvalidTimestamp.Error()+"\n", rr.Body.String())
}

func TestGetHeader(t *testing.T) {
	ctx := context.Background()
	relay := newTestRelay(t)
	relay.engine.Run(ctx)
	pk, _ := newKeypair(t)
	parent := relay.engine.mockChain().CurrentHeader()
	parentHash := parent.Hash()

	// Initialize engine
	_, err := relay.engine.backend.ForkchoiceUpdatedV1(
		ctx,
		&types.ForkchoiceStateV1{
			HeadBlockHash:      parentHash,
			SafeBlockHash:      parentHash,
			FinalizedBlockHash: parentHash,
		},
		&types.PayloadAttributesV1{
			Timestamp:             parent.Time + 1,
			PrevRandao:            common.Hash{0x01},
			SuggestedFeeRecipient: common.Address{0x02},
		},
	)
	require.NoError(t, err, "unable to initialize engine")

	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/0x%x", 0, parentHash.Hex(), pk)
	rr := relay.testRequest(t, "GET", path, nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	bid := new(types.GetHeaderResponse)
	err = json.Unmarshal(rr.Body.Bytes(), bid)
	require.NoError(t, err)

	require.Equal(t, parentHash[:], bid.Data.Message.Header.ParentHash[:], "didn't build on expected parent")
	domain := types.ComputeDomain(types.DomainTypeBeaconProposer, version.Bellatrix, &relay.genesisValidatorsRoot)
	ok, err := types.VerifySignature(bid.Data.Message, domain, relay.pk[:], bid.Data.Signature[:])
	require.NoError(t, err, "error verifying signature")
	require.True(t, ok, "bid signature not valid")

	require.Equal(t, pk, relay.latestPubkey[:])
}

func TestGetPayload(t *testing.T) {
	ctx := context.Background()
	relay := newTestRelay(t)
	relay.engine.Run(ctx)
	pk, sk := newKeypair(t)
	parent := relay.engine.mockChain().CurrentHeader()
	parentHash := parent.Hash()

	// Initialize engine
	_, err := relay.engine.backend.ForkchoiceUpdatedV1(
		ctx,
		&types.ForkchoiceStateV1{
			HeadBlockHash:      parentHash,
			SafeBlockHash:      parentHash,
			FinalizedBlockHash: parentHash,
		},
		&types.PayloadAttributesV1{
			Timestamp:             parent.Time + 1,
			PrevRandao:            common.Hash{0x01},
			SuggestedFeeRecipient: common.Address{0x02},
		},
	)
	require.NoError(t, err, "unable to initialize engine")

	// Call getHeader to prepare payload
	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/0x%x", 0, parentHash.Hex(), pk)
	rr := relay.testRequest(t, "GET", path, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	bid := new(types.GetHeaderResponse)
	err = json.Unmarshal(rr.Body.Bytes(), bid)
	require.NoError(t, err)

	// Create request payload
	msg := &types.BlindedBeaconBlock{
		Slot:          1,
		ProposerIndex: 2,
		ParentRoot:    types.Root{0x03},
		StateRoot:     types.Root{0x04},
		Body: &types.BlindedBeaconBlockBody{
			Eth1Data: &types.Eth1Data{
				DepositRoot:  types.Root{0x05},
				DepositCount: 5,
				BlockHash:    types.Hash{0x06},
			},
			SyncAggregate: &types.SyncAggregate{
				CommitteeBits:      types.CommitteeBits{0x07},
				CommitteeSignature: types.Signature{0x08},
			},
			ExecutionPayloadHeader: bid.Data.Message.Header,
		},
	}

	// Sign payload
	root, err := types.ComputeSigningRoot(msg, types.ComputeDomain(types.DomainTypeBeaconProposer, version.Bellatrix, &relay.genesisValidatorsRoot))
	require.NoError(t, err)
	sig := sk.Sign(root[:]).Marshal()
	var signature types.Signature
	signature.FromSlice(sig)
	require.Equal(t, sig[:], signature[:])

	// Call getPayload with invalid signature
	rr = relay.testRequest(t, "POST", "/eth/v1/builder/blinded_blocks", types.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: types.Signature{0x09},
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Call getPayload with correct signature
	rr = relay.testRequest(t, "POST", "/eth/v1/builder/blinded_blocks", types.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: signature,
	})

	// Verify getPayload response
	require.Equal(t, http.StatusOK, rr.Code)
	getPayloadResponse := new(types.GetPayloadResponse)
	err = json.Unmarshal(rr.Body.Bytes(), getPayloadResponse)
	require.NoError(t, err)
	require.Equal(t, bid.Data.Message.Header.BlockHash, getPayloadResponse.Data.BlockHash)
}

func TestExecutionPayloadTransformations(t *testing.T) {
	// Test: block -> EL payload -> CL payload -> EL payload -> block -> compare blockhash
	relay := newTestRelay(t)
	relay.engine.Run(context.Background())
	parent := relay.engine.mockChain().CurrentHeader()

	txsCreator := TransactionsCreator{nil, func(config *params.ChainConfig, bc core.ChainContext,
		statedb *state.StateDB, header *ethTypes.Header, cfg vm.Config, accounts []TestAccount) []*ethTypes.Transaction {
		return nil // TODO: create some transactions
	}}

	// Create a block
	block1, err := relay.engine.mockChain().AddNewBlock(parent.Hash(), common.Address{0x02}, 12345, 23456, txsCreator, common.Hash{0x04}, []byte("hello"), nil, false)
	require.NoError(t, err)

	// Transform to EL payload
	payloadEl, err := api.BlockToPayload(block1)
	require.NoError(t, err)

	// Transform EL payload to CL payload
	payloadCl, err := types.ELPayloadToRESTPayload(payloadEl)
	require.NoError(t, err)

	// Transform CL payload back to EL payload
	payloadEl2, err := types.RESTPayloadToELPayload(payloadCl)
	require.NoError(t, err)

	// Create a block from the 'new' EL payload and ensure correctness
	block2, err := relay.engine.mockChain().ProcessPayload(payloadEl2)
	require.NoError(t, err)
	require.Equal(t, block1.Hash(), block2.Hash())
}
