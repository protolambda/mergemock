package main

import (
	"bytes"
	"context"
	"mergemock/types"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prysmaticlabs/prysm/shared/bls/blst"
	bls "github.com/prysmaticlabs/prysm/shared/bls/common"
	"github.com/sirupsen/logrus"
)

func newRelay() *RelayBackend {
	relay, _ := NewRelayBackend(logrus.New())
	return relay
}

func newKeypair() (types.PublicKey, bls.SecretKey) {
	sk, err := blst.RandKey()
	if err != nil {
		panic(err)
	}
	var pk types.PublicKey
	pk.FromSlice(sk.PublicKey().Marshal())
	return pk, sk
}

func TestValidatorRegistration(t *testing.T) {
	relay := newRelay()
	pk, sk := newKeypair()
	msg := types.RegisterValidatorRequestMessage{
		FeeRecipient: [20]byte{0x42},
		GasTarget:    15_000_000,
		Timestamp:    hexutil.Uint64(time.Now().Unix()),
		Pubkey:       pk,
	}
	root, err := msg.HashTreeRoot()
	if err != nil {
		t.Fatal("can't compute root")
	}
	resp, err := relay.RegisterValidatorV1(context.Background(), msg, sk.Sign(root[:]).Marshal())
	if err != nil || (resp == nil || *resp != "OK") {
		t.Fatal("unable to register validator: ", err)
	}
}

func TestGetHeader(t *testing.T) {
	ctx := context.Background()
	relay := newRelay()
	relay.engine.Run(ctx)
	pk, _ := newKeypair()
	parent := relay.engine.mockChain().CurrentHeader()
	parentHash := parent.Hash()

	if _, err := relay.engine.backend.ForkchoiceUpdatedV1(
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
	); err != nil {
		t.Fatal("unable to initialize engine")
	}
	bid, err := relay.GetHeaderV1(ctx, hexutil.Uint64(0), hexutil.Bytes(pk[:]), parentHash)
	if err != nil {
		t.Fatal("unable to get header: ", err)
	}
	// TODO: For some reason, bytes.Equal(a, b) returns false ?
	if bytes.Compare(bid.Message.Header.ParentHash[:], parentHash[:]) != 0 {
		t.Fatal("didn't build on expected parent")
	}
	ok, err := verifySignature(bid.Message, relay.pk[:], bid.Signature[:])
	if err != nil {
		t.Fatal("error verifying signature: ", err)
	}
	if !ok {
		t.Fatal("bid signature not valid")
	}
}
