package main

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type ErrorCode int

const (
	ActionNotAllowed             = 2
	UnknownBlock       ErrorCode = 4
	UnavailablePayload ErrorCode = 5
)

type Bytes32 [32]byte

func (b *Bytes32) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *Bytes32) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("Bytes32", text, b[:])
}

func (b *Bytes32) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

type Bytes20 [20]byte

func (b *Bytes20) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *Bytes20) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("Bytes32", text, b[:])
}

func (b *Bytes20) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

type Bytes256 [256]byte

func (b *Bytes256) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *Bytes256) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("Bytes32", text, b[:])
}

func (b *Bytes256) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

type Uint64Quantity = hexutil.Uint64

type BytesMax32 []byte

func (b *BytesMax32) UnmarshalJSON(text []byte) error {
	if len(text) > 64+2+2 { // account for delimiter "", and 0x prefix
		return fmt.Errorf("input too long, expected at most 32 hex-encoded, 0x-prefixed, bytes: %x", text)
	}
	return (*hexutil.Bytes)(b).UnmarshalJSON(text)
}

func (b *BytesMax32) UnmarshalText(text []byte) error {
	if len(text) > 64+2 { // account for 0x prefix
		return fmt.Errorf("input too long, expected at most 32 hex-encoded, 0x-prefixed, bytes: %x", text)
	}
	return (*hexutil.Bytes)(b).UnmarshalText(text)
}

func (b BytesMax32) MarshalText() ([]byte, error) {
	return (hexutil.Bytes)(b).MarshalText()
}

type Uint256Quantity = uint256.Int

type Data = hexutil.Bytes

type PayloadID uint64

func (id *PayloadID) UnmarshalJSON(text []byte) error {
	return (*hexutil.Uint64)(id).UnmarshalJSON(text)
}

func (id *PayloadID) UnmarshalText(text []byte) error {
	return (*hexutil.Uint64)(id).UnmarshalText(text)
}

func (id PayloadID) MarshalText() ([]byte, error) {
	return hexutil.Uint64(id).MarshalText()
}

type ExecutionPayload struct {
	ParentHash    Bytes32         `json:"parentHash"`
	Coinbase      Bytes20         `json:"coinbase"`
	StateRoot     Bytes32         `json:"stateRoot"`
	ReceiptRoot   Bytes32         `json:"receiptRoot"`
	LogsBloom     Bytes256        `json:"logsBloom"`
	Random        Bytes32         `json:"random"`
	BlockNumber   Uint64Quantity  `json:"blockNumber"`
	GasLimit      Uint64Quantity  `json:"gasLimit"`
	GasUsed       Uint64Quantity  `json:"gasUsed"`
	Timestamp     Uint64Quantity  `json:"timestamp"`
	ExtraData     BytesMax32      `json:"extraData"`
	BaseFeePerGas Uint256Quantity `json:"baseFeePerGas"`
	BlockHash     Bytes32         `json:"blockHash"`
	// Array of transaction objects, each object is a byte list (DATA) representing
	// TransactionType || TransactionPayload or LegacyTransaction as defined in EIP-2718
	Transactions []Data `json:"transactions"`
}

type PreparePayloadParams struct {
	// hash of the parent block
	ParentHash Bytes32 `json:"parentHash"`
	// value for the timestamp field of the new payload
	Timestamp Uint64Quantity `json:"timestamp"`
	// value for the random field of the new payload
	Random Bytes32 `json:"random"`
	// suggested value for the coinbase field of the new payload
	FeeRecipient Bytes20 `json:"feeRecipient"`
}

type ExecutionPayloadStatus string

const (
	// given payload is valid
	ExecutionValid ExecutionPayloadStatus = "VALID"
	// given payload is invalid
	ExecutionInvalid ExecutionPayloadStatus = "INVALID"
	// sync process is in progress
	ExecutionSyncing ExecutionPayloadStatus = "SYNCING"
)

type ExecutePayloadResult struct {
	// the result of the payload execution
	Status ExecutionPayloadStatus `json:"status"`
}

type ConsensusBlockStatus string

const (
	ConsensusValid   ConsensusBlockStatus = "VALID"
	ConsensusInvalid ConsensusBlockStatus = "INVALID"
)

type ConsensusValidatedParams struct {
	// block hash value of the payload
	BlockHash Bytes32 `json:"blockHash"`
	// result of the payload validation with respect to the proof-of-stake consensus rules
	Status ConsensusBlockStatus `json:"status"`
}

type ForkchoiceUpdatedParams struct {
	// block hash of the head of the canonical chain
	HeadBlockHash Bytes32 `json:"headBlockHash"`
	// block hash of the most recent finalized block
	FinalizedBlockHash Bytes32 `json:"finalizedBlockHash"`
}

func PreparePayload(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger,
	params *PreparePayloadParams) (payloadId PayloadID, err error) {

	e := log.WithField("params", params)
	e.Trace("preparing payload")
	err = cl.CallContext(ctx, &payloadId, "engine_preparePayload", params)
	if err != nil {
		e = e.WithError(err)
		if rpcErr, ok := err.(rpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			if code == UnknownBlock {
				e.Warn("prepare-payload request referenced unknown block")
			} else if code == ActionNotAllowed {
				e.Warn("prepare-payload request was not allowed. Is the engine syncing?")
			} else {
				e.WithField("code", code).Warn("unexpected error code in prepare-payload response")
			}
		} else {
			e.Error("failed to get payload")
		}
		return 0, err
	}
	e.WithField("payload_id", payloadId).Trace("prepared payload")
	return
}

func GetPayload(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger,
	payloadId PayloadID) (*ExecutionPayload, error) {

	e := log.WithField("payload_id", payloadId)
	e.Trace("getting payload")
	var result ExecutionPayload
	err := cl.CallContext(ctx, &result, "engine_getPayload", payloadId)
	if err != nil {
		e = e.WithError(err)
		if rpcErr, ok := err.(rpc.Error); ok {
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
	e.Trace("Received payload")
	return &result, nil
}

func ExecutePayload(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger,
	payload *ExecutionPayload) (ExecutionPayloadStatus, error) {

	e := log.WithField("payload", payload)
	e.Trace("sending payload for execution")
	var result ExecutePayloadResult
	err := cl.CallContext(ctx, &result, "engine_executePayload", payload)
	if err != nil {
		e.WithError(err).Error("payload execution failed")
		return "", err
	}
	e.Trace("Received payload execution result")
	return result.Status, nil
}

func ConsensusValidated(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, blockHash Bytes32, status ConsensusBlockStatus) error {
	params := ConsensusValidatedParams{BlockHash: blockHash, Status: status}

	e := log.WithField("block_hash", blockHash).WithField("status", status)
	e.Trace("sharing consensus-validated signal")

	err := cl.CallContext(ctx, nil, "engine_consensusValidated", params)
	if err == nil || err == rpc.ErrNoResult {
		e.Trace("shared consensus-validated signal")
		return nil
	} else {
		e = e.WithError(err)
		if rpcErr, ok := err.(rpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			if code != UnknownBlock {
				e.WithField("code", code).Warn("unexpected error code in consensus-validated response")
			} else {
				e.Info("unknown block in consensus-validated signal")
			}
		} else {
			e.Error("failed to share consensus-validated signal")
		}
		return err
	}
}

func ForkchoiceUpdated(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, head Bytes32, finalized Bytes32) error {
	params := ForkchoiceUpdatedParams{HeadBlockHash: head, FinalizedBlockHash: finalized}

	e := log.WithField("head", head).WithField("finalized", finalized)
	e.Trace("sharing forkchoice-updated signal")

	err := cl.CallContext(ctx, nil, "engine_forkchoiceUpdated", params)
	if err == nil || err == rpc.ErrNoResult {
		e.Trace("shared forkchoice-updated signal")
		return nil
	} else {
		e = e.WithError(err)
		if rpcErr, ok := err.(rpc.Error); ok {
			code := ErrorCode(rpcErr.ErrorCode())
			if code != UnknownBlock {
				e.WithField("code", code).Warn("unexpected error code in forkchoice-updated response")
			} else {
				e.Info("unknown block in forkchoice-updated signal")
			}
		} else {
			e.Error("failed to share forkchoice-updated signal")
		}
		return err
	}
}
