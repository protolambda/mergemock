package main

import (
	"context"
	"mergemock/types"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prysmaticlabs/prysm/shared/bls/blst"
	"github.com/sirupsen/logrus"
)

func newRelay() *RelayBackend {
	relay, _ := NewRelayBackend(logrus.New())
	return relay
}

func TestValidatorRegistration(t *testing.T) {
	var (
		relay = newRelay()
		pk    types.PublicKey
		sk, _ = blst.RandKey()
	)
	pk.FromSlice(sk.PublicKey().Marshal())
	msg := types.RegisterValidatorRequestMessage{
		FeeRecipient: [20]byte{0x42},
		GasTarget:    15_000_000,
		Timestamp:    hexutil.Uint64(time.Now().Unix()),
		Pubkey:       pk,
	}
	root, _ := msg.HashTreeRoot()
	resp, err := relay.RegisterValidatorV1(context.Background(), msg, sk.Sign(root[:]).Marshal())
	if err != nil || (resp == nil || *resp != "OK") {
		t.Fatal("unable to register validator: ", err)
	}
}
