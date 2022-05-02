package api

import (
	"context"
	"fmt"
	"math/big"
	"mergemock/rpc"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/sirupsen/logrus"
)

type ErrorCode int
type PayloadID beacon.PayloadID

const (
	UnavailablePayload ErrorCode = -32001
)

//go:generate go run github.com/fjl/gencodec -type PayloadAttributesV1 -field-override payloadAttributesMarshalling -out gen_blockparams.go
type PayloadAttributesV1 struct {
	Timestamp             uint64         `json:"timestamp"`
	PrevRandao            common.Hash    `json:"prevRandao"`
	SuggestedFeeRecipient common.Address `json:"suggestedFeeRecipient"`
}

type payloadAttributesMarshalling struct {
	Timestamp hexutil.Uint64
}

//go:generate go run github.com/fjl/gencodec -type ExecutionPayloadV1 -field-override executionPayloadMarshalling -out gen_ep.go
type ExecutionPayloadV1 struct {
	ParentHash    common.Hash    `json:"parentHash"    gencodec:"required"`
	FeeRecipient  common.Address `json:"feeRecipient"  gencodec:"required"`
	StateRoot     common.Hash    `json:"stateRoot"     gencodec:"required"`
	ReceiptsRoot  common.Hash    `json:"receiptsRoot"  gencodec:"required"`
	LogsBloom     []byte         `json:"logsBloom"     gencodec:"required"`
	Random        common.Hash    `json:"prevRandao"    gencodec:"required"`
	Number        uint64         `json:"blockNumber"   gencodec:"required"`
	GasLimit      uint64         `json:"gasLimit"      gencodec:"required"`
	GasUsed       uint64         `json:"gasUsed"       gencodec:"required"`
	Timestamp     uint64         `json:"timestamp"     gencodec:"required"`
	ExtraData     []byte         `json:"extraData"     gencodec:"required"`
	BaseFeePerGas *big.Int       `json:"baseFeePerGas" gencodec:"required"`
	BlockHash     common.Hash    `json:"blockHash"     gencodec:"required"`
	Transactions  [][]byte       `json:"transactions"  gencodec:"required"`
}

type executionPayloadMarshalling struct {
	Number        hexutil.Uint64
	GasLimit      hexutil.Uint64
	GasUsed       hexutil.Uint64
	Timestamp     hexutil.Uint64
	BaseFeePerGas *hexutil.Big
	ExtraData     hexutil.Bytes
	LogsBloom     hexutil.Bytes
	Transactions  []hexutil.Bytes
}

func (params *ExecutionPayloadV1) ValidateHash() bool {
	txs, err := decodeTransactions(params.Transactions)
	if err != nil {
		return false
	}
	header := &types.Header{
		ParentHash:  params.ParentHash,
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    params.FeeRecipient,
		Root:        params.StateRoot,
		TxHash:      types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
		ReceiptHash: params.ReceiptsRoot,
		Bloom:       types.BytesToBloom(params.LogsBloom),
		Difficulty:  common.Big0,
		Number:      new(big.Int).SetUint64(params.Number),
		GasLimit:    params.GasLimit,
		GasUsed:     params.GasUsed,
		Time:        params.Timestamp,
		BaseFee:     params.BaseFeePerGas,
		Extra:       params.ExtraData,
		MixDigest:   params.Random,
	}
	return header.Hash() == common.Hash(params.BlockHash)
}

type ExecutePayloadStatus string

const (
	// given payload is valid
	ExecutionValid ExecutePayloadStatus = "VALID"
	// given payload is invalid
	ExecutionInvalid ExecutePayloadStatus = "INVALID"
	// sync process is in progress
	ExecutionSyncing ExecutePayloadStatus = "SYNCING"
	// payload didn't exetend canonical chain, and therefore wasn't executed
	ExecutionAccepted ExecutePayloadStatus = "ACCEPTED"
	// payload did not match provided block hash
	ExecutionInvalidBlockHash ExecutePayloadStatus = "INVALID_BLOCK_HASH"
	// payload is built on parent block that does not meet ttd
	ExecutionInvalidTerminalBlock ExecutePayloadStatus = "INVALID_TERMINAL_BLOCK"
)

type PayloadStatusV1 struct {
	Status          ExecutePayloadStatus `json:"status"`
	LatestValidHash *common.Hash         `json:"latestValidHash"`
	ValidationError string               `json:"validationError"`
}

type ForkchoiceStateV1 struct {
	HeadBlockHash      common.Hash `json:"headBlockHash"`
	SafeBlockHash      common.Hash `json:"safeBlockHash"`
	FinalizedBlockHash common.Hash `json:"finalizedBlockHash"`
}

type ForkchoiceUpdatedResult struct {
	PayloadStatus PayloadStatusV1 `json:"payloadStatus"`
	PayloadID     *PayloadID      `json:"payloadId"`
}

func GetPayloadV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, payloadId PayloadID) (*ExecutionPayloadV1, error) {
	e := log.WithField("payload_id", payloadId)
	var result ExecutionPayloadV1
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

func NewPayloadV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, payload *ExecutionPayloadV1) (*PayloadStatusV1, error) {
	e := log.WithField("block_hash", payload.BlockHash)
	var result PayloadStatusV1
	err := cl.CallContext(ctx, &result, "engine_newPayloadV1", payload)
	if err != nil {
		e.WithError(err).Error("Payload execution failed")
		return nil, err
	}
	e.WithField("status", result.Status).WithField("latestValidHash", result.LatestValidHash).WithField("validationError", result.ValidationError).Debug("Received payload execution result")
	return &result, nil
}

func ForkchoiceUpdatedV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, head, safe, finalized common.Hash, payload *PayloadAttributesV1) (ForkchoiceUpdatedResult, error) {
	heads := &ForkchoiceStateV1{HeadBlockHash: head, SafeBlockHash: safe, FinalizedBlockHash: finalized}

	e := log.WithField("head", head).WithField("safe", safe).WithField("finalized", finalized).WithField("payload", payload)
	e.Debug("Sharing forkchoice-updated signal")

	var result ForkchoiceUpdatedResult
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

func BlockToPayload(b *types.Block) (*ExecutionPayloadV1, error) {
	extra := b.Extra()
	if len(extra) > 32 {
		return nil, fmt.Errorf("eth2 merge spec limits extra data to 32 bytes in payload, got %d", len(extra))
	}
	txs, err := encodeTransactions(b.Transactions())
	if err != nil {
		return nil, err
	}
	return &ExecutionPayloadV1{
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

func decodeTransactions(enc [][]byte) ([]*types.Transaction, error) {
	var txs = make([]*types.Transaction, len(enc))
	for i, encTx := range enc {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(encTx); err != nil {
			return nil, fmt.Errorf("invalid transaction %d: %v", i, err)
		}
		txs[i] = &tx
	}
	return txs, nil
}

func encodeTransactions(txs types.Transactions) ([][]byte, error) {
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
