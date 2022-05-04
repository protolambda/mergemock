package main

import (
	"bytes"
	"context"
	"fmt"
	"mergemock/types"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/prysmaticlabs/prysm/shared/bls/blst"
	bls "github.com/prysmaticlabs/prysm/shared/bls/common"
	"github.com/sirupsen/logrus"
)

func newRelay(t *testing.T) *RelayBackend {
	relay, err := NewRelayBackend(logrus.New())
	if err != nil {
		t.Fatal("unable to create relay")
	}
	relay.engine.JwtSecretPath = newJwt(t)
	relay.engine.GenesisPath = newGenesis(t)
	return relay
}

func newKeypair(t *testing.T) (types.PublicKey, bls.SecretKey) {
	sk, err := blst.RandKey()
	if err != nil {
		t.Fatal("unable to generate bls key pair", err)
	}
	var pk types.PublicKey
	pk.FromSlice(sk.PublicKey().Marshal())
	return pk, sk
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

func TestValidatorRegistration(t *testing.T) {
	relay := newRelay(t)
	pk, sk := newKeypair(t)
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
	relay := newRelay(t)
	relay.engine.Run(ctx)
	pk, _ := newKeypair(t)
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
	if !bytes.Equal(bid.Message.Header.ParentHash[:], parentHash[:]) {
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
