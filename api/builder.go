package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mergemock/types"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

func BuilderGetHeader(ctx context.Context, log logrus.Ext1FieldLogger, builderAddr string, blockHash common.Hash) (*types.ExecutionPayloadHeader, error) {
	e := log.WithField("blockHash", blockHash)
	e.Debug("getting header")

	pubkey := "0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2"
	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", 1, blockHash.Hex(), pubkey)
	url := builderAddr + path
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
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

func BuilderGetPayload(ctx context.Context, log logrus.Ext1FieldLogger, builderAddr string, header *types.ExecutionPayloadHeader) (*types.ExecutionPayloadV1, error) {
	// e := log.WithField("block_hash", header.BlockHash)
	// e.Debug("sending payload for execution")
	// var result types.ExecutionPayloadV1

	// url := builderAddr + "/eth/v1/builder/blinded_blocks"
	// requestPayload := types.GetPayloadRequest{
	// 	Message: &types.BlindedBeaconBlock{
	// 		Slot:          1,
	// 		ProposerIndex: 1,
	// 		Body: &types.BlindedBeaconBlockBody{
	// 			ExecutionPayloadHeader: header,
	// 		},
	// 	},

	// }

	// err := cl.CallContext(ctx, &result, "builder_getPayloadV1", nil, signature) // TODO: don't send nil for block
	// if err != nil {
	// 	e = e.WithError(err)
	// 	if rpcErr, ok := err.(gethRpc.Error); ok {
	// 		code := ErrorCode(rpcErr.ErrorCode())
	// 		if code != UnavailablePayload {
	// 			e.WithField("code", code).Warn("unexpected error code in propose-payload response")
	// 		} else {
	// 			e.Warn("unavailable payload in propose-payload request")
	// 		}
	// 	} else {
	// 		e.Error("failed to propose payload")
	// 	}
	// 	return nil, err
	// }
	// e.Debug("Received proposed payload")
	return nil, nil
}
