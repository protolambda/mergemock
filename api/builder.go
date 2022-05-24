package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mergemock/types"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

func BuilderRegisterValidators(ctx context.Context, log *logrus.Logger, builderAddr string, msg []types.SignedValidatorRegistration) error {
	path := "/eth/v1/builder/validators"
	url := builderAddr + path
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("builder REST API rejected validator registration with error: %d", body)
	}
	return nil
}

func BuilderGetHeader(ctx context.Context, log logrus.Ext1FieldLogger, builderAddr string, slot uint64, blockHash common.Hash, pubkey []byte) (*types.ExecutionPayloadHeader, error) {
	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/0x%x", slot, blockHash.Hex(), pubkey)
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

	// Verify signature
	ok, err := types.VerifySignature(bid.Data.Message, types.DomainBuilder, bid.Data.Message.Pubkey[:], bid.Data.Signature[:])
	if !ok || err != nil {
		log.WithError(err).Warn("Failed to verify header signature")
		return nil, errors.New("failed to verify header signature")
	}

	// TODO: we should eventually add a list of "trusted" builders to cross-reference the builder pubkey against
	return bid.Data.Message.Header, nil
}

func BuilderGetPayload(ctx context.Context, log logrus.Ext1FieldLogger, builderAddr string, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) (*types.ExecutionPayloadV1, error) {
	payloadBytes, err := json.Marshal(signedBlindedBeaconBlock)
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

	elPayload, err := types.RESTPayloadToELPayload(getPayloadResponse.Data)
	if err != nil {
		return nil, err
	}

	return elPayload, nil
}
