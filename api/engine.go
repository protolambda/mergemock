package api

import (
	"context"
	"fmt"
	"mergemock/rpc"
	"mergemock/types"

	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	gethRpc "github.com/ethereum/go-ethereum/rpc"

	"github.com/sirupsen/logrus"
)

type ErrorCode int

const (
	UnavailablePayload ErrorCode = -32001
)

func GetPayloadV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, payloadId types.PayloadID) (*types.ExecutionPayloadV1, error) {
	e := log.WithField("payload_id", payloadId)
	var result types.ExecutionPayloadV1
	err := cl.CallContext(ctx, &result, "engine_getPayloadV1", payloadId)
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
			e.Error("failed to get payload")
		}
		return nil, err
	}
	e.Debug("Received payload")
	return &result, nil
}

func NewPayloadV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, payload *types.ExecutionPayloadV1) (*types.PayloadStatusV1, error) {
	e := log.WithField("block_hash", payload.BlockHash)
	var result types.PayloadStatusV1
	err := cl.CallContext(ctx, &result, "engine_newPayloadV1", payload)
	if err != nil {
		e.WithError(err).Error("Payload execution failed")
		return nil, err
	}
	e.WithField("status", result.Status).WithField("latestValidHash", result.LatestValidHash).WithField("validationError", result.ValidationError).Debug("Received payload execution result")
	return &result, nil
}

func ForkchoiceUpdatedV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, head, safe, finalized common.Hash, payload *types.PayloadAttributesV1) (types.ForkchoiceUpdatedResult, error) {
	heads := &types.ForkchoiceStateV1{HeadBlockHash: head, SafeBlockHash: safe, FinalizedBlockHash: finalized}

	e := log.WithField("head", head).WithField("safe", safe).WithField("finalized", finalized).WithField("payload", payload)
	e.Debug("Sharing forkchoice-updated signal")

	var result types.ForkchoiceUpdatedResult
	err := cl.CallContext(ctx, &result, "engine_forkchoiceUpdatedV1", &heads, &payload)
	if err == nil {
		e.Debug("Shared forkchoice-updated signal")
		if payload != nil {
			e.WithField("payloadId", result.PayloadID).WithField("status", result.PayloadStatus).Debug("Received payload id")
		}
		return result, nil
	} else {
		e = e.WithError(err)
		if rpcErr, ok := err.(gethRpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			e.WithField("code", code).Warn("Unexpected error code in forkchoice-updated response")
		} else {
			e.Error("Failed to share forkchoice-updated signal")
		}
		return result, err
	}
}

func BlockToPayload(b *ethTypes.Block) (*types.ExecutionPayloadV1, error) {
	extra := b.Extra()
	if len(extra) > 32 {
		return nil, fmt.Errorf("eth2 merge spec limits extra data to 32 bytes in payload, got %d", len(extra))
	}
	txs, err := encodeTransactions(b.Transactions())
	if err != nil {
		return nil, err
	}
	return &types.ExecutionPayloadV1{
		ParentHash:    b.ParentHash(),
		FeeRecipient:  b.Coinbase(),
		StateRoot:     b.Root(),
		ReceiptsRoot:  b.ReceiptHash(),
		LogsBloom:     b.Bloom().Bytes(),
		Random:        b.MixDigest(),
		Number:        b.NumberU64(),
		GasLimit:      b.GasLimit(),
		GasUsed:       b.GasUsed(),
		Timestamp:     b.Time(),
		ExtraData:     extra,
		BaseFeePerGas: b.BaseFee(),
		BlockHash:     b.Hash(),
		Transactions:  txs,
	}, nil
}

func encodeTransactions(txs ethTypes.Transactions) ([][]byte, error) {
	enc := make([][]byte, 0, len(txs))
	for i, tx := range txs {
		txOpaque, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to encode tx %d", i)
		}
		enc = append(enc, txOpaque)
	}
	return enc, nil
}
