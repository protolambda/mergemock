package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mergemock/types"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prysmaticlabs/prysm/shared/bls"
	"github.com/sirupsen/logrus"
)

func BuilderGetHeader(ctx context.Context, log logrus.Ext1FieldLogger, sk bls.SecretKey, builderAddr string, blockHash common.Hash) (*types.ExecutionPayloadHeader, error) {
	e := log.WithField("blockHash", blockHash)
	e.Debug("getting header")

	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/0x%x", 1, blockHash.Hex(), sk.PublicKey().Marshal())
	url := builderAddr + path
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("builder REST API returned non-200 status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bid := new(types.GetHeaderResponse)
	err = json.Unmarshal(body, bid)
	if err != nil {
		return nil, err
	}

	e.Debug("Received payload")
	return bid.Data.Message.Header, nil
}

func BuilderGetPayload(ctx context.Context, log logrus.Ext1FieldLogger, sk bls.SecretKey, builderAddr string, header *types.ExecutionPayloadHeader) (*types.ExecutionPayloadV1, error) {
	e := log.WithField("block_hash", header.BlockHash)
	e.Debug("sending payload for execution")

	msg := &types.BlindedBeaconBlock{
		Slot:          1,
		ProposerIndex: 1,
		Body: &types.BlindedBeaconBlockBody{
			ExecutionPayloadHeader: header,
		},
	}

	// Sign payload
	root, err := msg.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	sig := sk.Sign(root[:]).Marshal()
	var signature types.Signature
	signature.FromSlice(sig)

	payloadBytes, err := json.Marshal(types.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: signature,
	})
	if err != nil {
		return nil, err
	}

	url := builderAddr + "/eth/v1/builder/blinded_blocks"
	req, err := http.NewRequest("POST", url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("builder REST API returned non-200 status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	getPayloadResponse := new(types.GetPayloadResponse)
	err = json.Unmarshal(body, getPayloadResponse)
	if err != nil {
		return nil, err
	}

	e.Debug("Received proposed payload")
	elPayload, err := types.RESTPayloadToELPayload(getPayloadResponse.Data)
	if err != nil {
		return nil, err
	}

	return elPayload, nil
}
