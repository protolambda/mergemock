package api

import (
	"context"
	"mergemock/rpc"
	"mergemock/types"

	"github.com/ethereum/go-ethereum/common"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

func BuilderGetHeader(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, blockHash common.Hash) (*types.ExecutionPayloadHeaderV1, error) {
	e := log.WithField("blockHash", blockHash)
	e.Debug("getting header")
	var result types.GetHeaderResponse

	pubkey := "0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2"
	err := cl.CallContext(ctx, &result, "builder_getHeaderV1", "0x1", pubkey, blockHash.Hex())
	if err != nil {
		e = e.WithError(err)
		if rpcErr, ok := err.(gethRpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			if code != UnavailablePayload {
				e.WithField("code", code).Warn("unexpected error code in get-payload header response")
			} else {
				e.Warn("unavailable payload in get-payload header request")
			}
		} else {
			e.Error("failed to get payload header")
		}
		return nil, err
	}
	e.Debug("Received payload")
	return &result.Message.Header, nil
}

func BuilderGetPayload(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, header *types.ExecutionPayloadHeaderV1) (*types.ExecutionPayloadV1, error) {
	e := log.WithField("block_hash", header.BlockHash)
	e.Debug("sending payload for execution")
	var result types.ExecutionPayloadV1

	signature := "0xab5dc3c47ea96503823f364c4c1bb747560dc8874d90acdd0cbcfe1abc5457a70ab7e8175c074ace44dead2427e6d2353184c61c6eebc3620b8cec1e9115e35e4513369d7a68d7a5dad719cb6f5a85788490f76ca3580758042da4d003ef373f"
	err := cl.CallContext(ctx, &result, "builder_getPayloadV1", nil, signature) // TODO: don't send nil for block
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
