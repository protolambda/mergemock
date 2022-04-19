package api

import (
	"context"
	"encoding/json"
	"math/big"
	"mergemock/rpc"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/fjl/gencodec -type ExecutionPayloadHeaderV1 -field-override executionPayloadHeaderMarshalling -out gen_edh.go

// ExecutableDataV1 structure described at https://github.com/ethereum/execution-apis/src/engine/specification.md
type ExecutionPayloadHeaderV1 struct {
	ParentHash       common.Hash    `json:"parentHash"    gencodec:"required"`
	FeeRecipient     common.Address `json:"feeRecipient"  gencodec:"required"`
	StateRoot        common.Hash    `json:"stateRoot"     gencodec:"required"`
	ReceiptsRoot     common.Hash    `json:"receiptsRoot"  gencodec:"required"`
	LogsBloom        []byte         `json:"logsBloom"     gencodec:"required"`
	Random           common.Hash    `json:"prevRandao"    gencodec:"required"`
	Number           uint64         `json:"blockNumber"   gencodec:"required"`
	GasLimit         uint64         `json:"gasLimit"      gencodec:"required"`
	GasUsed          uint64         `json:"gasUsed"       gencodec:"required"`
	Timestamp        uint64         `json:"timestamp"     gencodec:"required"`
	ExtraData        []byte         `json:"extraData"     gencodec:"required"`
	BaseFeePerGas    *big.Int       `json:"baseFeePerGas" gencodec:"required"`
	BlockHash        common.Hash    `json:"blockHash"     gencodec:"required"`
	TransactionsRoot common.Hash    `json:"transactionsRoot"  gencodec:"required"`
}

// JSON type overrides for executableData.
type executionPayloadHeaderMarshalling struct {
	Number        hexutil.Uint64
	GasLimit      hexutil.Uint64
	GasUsed       hexutil.Uint64
	Timestamp     hexutil.Uint64
	BaseFeePerGas *hexutil.Big
	ExtraData     hexutil.Bytes
	LogsBloom     hexutil.Bytes
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

type SignedBuilderReceipt struct {
	Message   *BuilderReceipt `json:"message"`
	Signature string          `json:"signature"`
}

type BuilderReceipt struct {
	PayloadHeader    ExecutionPayloadHeaderV1 `json:"execution_payload_header"`
	FeeRecipientDiff uint256.Int              `json:"feeRecipientDiff"`
}

func BuilderGetHeader(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, blockHash common.Hash) (*ExecutionPayloadHeaderV1, error) {
	e := log.WithField("blockHash", blockHash)
	e.Debug("getting payload")
	var result GetHeaderResponse

	err := cl.CallContext(ctx, &result, "builder_getHeaderV1", blockHash)
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

func BuilderGetPayload(ctx context.Context, cl *rpc.Client, log logrus.Ext1FieldLogger, header *ExecutionPayloadHeaderV1) (*ExecutionPayloadV1, error) {
	e := log.WithField("block_hash", header.BlockHash)
	e.Debug("sending payload for execution")
	var result ExecutionPayloadV1

	beaconBlock := BlindedBeaconBlock{
		Body: BlindedBeaconBlockBody{ExecutionPayload: *header},
	}

	// TODO: SSZ-encode SignedBlindedBeaconBlock
	encoded_block, err := json.Marshal(SignedBlindedBeaconBlock{Message: &beaconBlock})
	if err != nil {
		e.WithError(err).Warn("unable to marshal beacon block")
		return nil, err
	}

	err = cl.CallContext(ctx, &result, "builder_getPayloadV1", string(encoded_block))
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

func PayloadToPayloadHeader(p *ExecutionPayloadV1) (*ExecutionPayloadHeaderV1, error) {
	txs, err := decodeTransactions(p.Transactions)
	if err != nil {
		return nil, err
	}
	return &ExecutionPayloadHeaderV1{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		Random:           p.Random,
		Number:           p.Number,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        p.ExtraData,
		BaseFeePerGas:    (*big.Int)(p.BaseFeePerGas),
		BlockHash:        p.BlockHash,
		TransactionsRoot: types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
	}, nil
}
