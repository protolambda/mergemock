package api

import (
	"context"
	"mergemock/rpc"

	"github.com/ethereum/go-ethereum/common"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type ExecutionPayloadHeaderV1 struct {
	ParentHash       common.Hash     `json:"parentHash"`
	FeeRecipient     common.Address  `json:"feeRecipient"`
	StateRoot        Bytes32         `json:"stateRoot"`
	ReceiptsRoot     Bytes32         `json:"receiptsRoot"`
	LogsBloom        Bytes256        `json:"logsBloom"`
	PrevRandao       Bytes32         `json:"prevRandao"`
	BlockNumber      Uint64Quantity  `json:"blockNumber"`
	GasLimit         Uint64Quantity  `json:"gasLimit"`
	GasUsed          Uint64Quantity  `json:"gasUsed"`
	Timestamp        Uint64Quantity  `json:"timestamp"`
	ExtraData        BytesMax32      `json:"extraData"`
	BaseFeePerGas    Uint256Quantity `json:"baseFeePerGas"`
	BlockHash        common.Hash     `json:"blockHash"`
	TransactionsRoot Bytes32         `json:"transactionsRoot"`
}

// See https://github.com/flashbots/mev-boost#signedblindedbeaconblock
type SignedBlindedBeaconBlock struct {
	Message   *BlindedBeaconBlock `json:"message"`
	Signature string              `json:"signature"`
}

// See https://github.com/flashbots/mev-boost#blindedbeaconblock
type BlindedBeaconBlock struct {
	Body BlindedBeaconBlockBody `json:"body"`
}

type BlindedBeaconBlockBody struct {
	ExecutionPayload ExecutionPayloadHeaderV1 `json:"execution_payload_header"`
}

func GetPayloadHeader(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, payloadId PayloadID) (*ExecutionPayloadHeaderV1, error) {

	e := log.WithField("payload_id", payloadId)
	e.Debug("getting payload")
	var result ExecutionPayloadHeaderV1
	err := cl.CallContext(ctx, &result, "builder_getPayloadHeaderV1", payloadId)
	if err != nil {
		e = e.WithError(err)
		if rpcErr, ok := err.(gethRpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			if code != UnavailablePayload {
				e.WithField("code", code).Warn("unexpected error code in get-payload response")
			} else {
				e.Warn("unavailable payload in get-payload request")
			}
		} else {
			e.Error("failed to get payload header")
		}
		return nil, err
	}
	e.Debug("Received payload")
	return &result, nil
}

func ProposePayload(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, header *ExecutionPayloadHeaderV1) (*ExecutionPayloadV1, error) {
	e := log.WithField("block_hash", header.BlockHash)
	e.Debug("sending payload for execution")
	var result ExecutionPayloadV1

	beaconBlock := BlindedBeaconBlock{
		Body: BlindedBeaconBlockBody{ExecutionPayload: *header},
	}
	err := cl.CallContext(ctx, &result, "builder_proposeBlindedBlockV1", SignedBlindedBeaconBlock{Message: &beaconBlock})

	if err != nil {
		e = e.WithError(err)
		if rpcErr, ok := err.(gethRpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			if code != UnavailablePayload {
				e.WithField("code", code).Warn("unexpected error code in propose-payload response")
			} else {
				e.Warn("unavailable payload in propose-payload request")
			}
		} else {
			e.Error("failed to propose payload")
		}
		return nil, err
	}
	e.Debug("Received proposed payload")
	return &result, nil
}
