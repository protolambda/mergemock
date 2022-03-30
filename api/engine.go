package api

import (
	"context"
	"fmt"
	"math/big"
	"mergemock/rpc"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/holiman/uint256"

	"github.com/sirupsen/logrus"
)

type ErrorCode int

const (
	UnavailablePayload ErrorCode = -32001
)

type Bytes32 [32]byte

func (b *Bytes32) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *Bytes32) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("Bytes32", text, b[:])
}

func (b Bytes32) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

func (b Bytes32) String() string {
	return hexutil.Encode(b[:])
}

type Bytes256 [256]byte

func (b *Bytes256) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *Bytes256) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("Bytes32", text, b[:])
}

func (b Bytes256) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

func (b Bytes256) String() string {
	return hexutil.Encode(b[:])
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

func (b BytesMax32) String() string {
	return hexutil.Encode(b)
}

type Uint256Quantity = uint256.Int

type Data = hexutil.Bytes

type PayloadID [8]byte

func (b *PayloadID) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *PayloadID) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("PayloadID", text, b[:])
}

func (b PayloadID) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

func (b PayloadID) String() string {
	return hexutil.Encode(b[:])
}

type ExecutionPayloadV1 struct {
	ParentHash    common.Hash     `json:"parentHash"`
	FeeRecipient  common.Address  `json:"feeRecipient"`
	StateRoot     Bytes32         `json:"stateRoot"`
	ReceiptsRoot  Bytes32         `json:"receiptsRoot"`
	LogsBloom     Bytes256        `json:"logsBloom"`
	PrevRandao    Bytes32         `json:"prevRandao"`
	BlockNumber   Uint64Quantity  `json:"blockNumber"`
	GasLimit      Uint64Quantity  `json:"gasLimit"`
	GasUsed       Uint64Quantity  `json:"gasUsed"`
	Timestamp     Uint64Quantity  `json:"timestamp"`
	ExtraData     BytesMax32      `json:"extraData"`
	BaseFeePerGas Uint256Quantity `json:"baseFeePerGas"`
	BlockHash     common.Hash     `json:"blockHash"`
	// Array of transaction objects, each object is a byte list (DATA) representing
	// TransactionType || TransactionPayload or LegacyTransaction as defined in EIP-2718
	Transactions []Data `json:"transactions"`
}

func (p *ExecutionPayloadV1) ValidateHash() bool {
	txs, err := decodeTransactions(p.Transactions)
	if err != nil {
		return false
	}
	header := &types.Header{
		ParentHash:  p.ParentHash,
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    p.FeeRecipient,
		Root:        common.Hash(p.StateRoot),
		TxHash:      types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
		ReceiptHash: common.Hash(p.ReceiptsRoot),
		Bloom:       types.Bloom(p.LogsBloom),
		Difficulty:  common.Big0,
		Number:      new(big.Int).SetInt64(int64(p.BlockNumber)),
		GasLimit:    uint64(p.GasLimit),
		GasUsed:     uint64(p.GasUsed),
		Time:        uint64(p.Timestamp),
		Extra:       p.ExtraData,
		MixDigest:   common.Hash(p.PrevRandao),
		BaseFee:     p.BaseFeePerGas.ToBig(),
	}
	if header.Hash() != common.Hash(p.BlockHash) {
		return false
	}
	return true
}

type PayloadAttributesV1 struct {
	// value for the timestamp field of the new payload
	Timestamp Uint64Quantity `json:"timestamp"`
	// value for the previous randao field of the new payload
	PrevRandao Bytes32 `json:"prevRandao"`
	// suggested value for the coinbase field of the new payload
	SuggestedFeeRecipient common.Address `json:"suggestedFeeRecipient"`
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
	// the result of the payload execution
	Status ExecutePayloadStatus `json:"status"`
	// the hash of the most recent valid block in the branch defined by payload and its ancestors
	LatestValidHash *Bytes32 `json:"latestValidHash"`
	// additional details on the result
	ValidationError string `json:"validationError"`
}

type ForkchoiceStateV1 struct {
	// block hash of the head of the canonical chain
	HeadBlockHash Bytes32 `json:"headBlockHash"`
	// safe block hash in the canonical chain
	SafeBlockHash Bytes32 `json:"safeBlockHash"`
	// block hash of the most recent finalized block
	FinalizedBlockHash Bytes32 `json:"finalizedBlockHash"`
}

type ForkchoiceUpdatedResult struct {
	// the result of the payload execution
	Status PayloadStatusV1 `json:"payloadStatus"`
	// the payload id if requested
	PayloadID *PayloadID `json:"payloadId"`
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

func ForkchoiceUpdatedV1(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, head, safe, finalized Bytes32, payload *PayloadAttributesV1) (ForkchoiceUpdatedResult, error) {
	heads := &ForkchoiceStateV1{HeadBlockHash: head, SafeBlockHash: safe, FinalizedBlockHash: finalized}

	e := log.WithField("head", head).WithField("safe", safe).WithField("finalized", finalized).WithField("payload", payload)
	e.Debug("Sharing forkchoice-updated signal")

	var result ForkchoiceUpdatedResult
	err := cl.CallContext(ctx, &result, "engine_forkchoiceUpdatedV1", &heads, &payload)
	if err == nil {
		e.Debug("Shared forkchoice-updated signal")
		if payload != nil {
			e.WithField("payloadId", result.PayloadID).WithField("status", result.Status).Debug("Received payload id")
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

func BlockToPayload(bl *types.Block) (*ExecutionPayloadV1, error) {
	extra := bl.Extra()
	if len(extra) > 32 {
		return nil, fmt.Errorf("eth2 merge spec limits extra data to 32 bytes in payload, got %d", len(extra))
	}
	baseFee, overflow := uint256.FromBig(bl.BaseFee())
	if overflow {
		return nil, fmt.Errorf("overflowing base fee")
	}
	txs := bl.Transactions()
	txsEncoded := make([]Data, 0, len(txs))
	for i, tx := range txs {
		txOpaque, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to encode tx %d", i)
		}
		txsEncoded = append(txsEncoded, txOpaque)
	}
	return &ExecutionPayloadV1{
		ParentHash:    bl.ParentHash(),
		FeeRecipient:  bl.Coinbase(),
		StateRoot:     Bytes32(bl.Root()),
		ReceiptsRoot:  Bytes32(bl.ReceiptHash()),
		LogsBloom:     Bytes256(bl.Bloom()),
		PrevRandao:    Bytes32(bl.MixDigest()),
		BlockNumber:   Uint64Quantity(bl.NumberU64()),
		GasLimit:      Uint64Quantity(bl.GasLimit()),
		GasUsed:       Uint64Quantity(bl.GasUsed()),
		Timestamp:     Uint64Quantity(bl.Time()),
		ExtraData:     BytesMax32(extra),
		BaseFeePerGas: Uint256Quantity(*baseFee),
		BlockHash:     bl.Hash(),
		Transactions:  txsEncoded,
	}, nil
}

func DecodeTransactions(enc []Data) ([]*types.Transaction, error) {
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
