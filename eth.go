package main

import (
	"context"
	"errors"
	"mergemock/rpc"
	"mergemock/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/node"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
)

type EthBackend struct {
	chain *core.BlockChain
}

func NewEthBackend(chain *core.BlockChain) *EthBackend {
	return &EthBackend{
		chain: chain,
	}
}
func (b *EthBackend) Register(srv *rpc.Server) error {
	srv.RegisterName("eth", b)
	return node.RegisterApis([]rpc.API{
		{
			Namespace:     "eth",
			Version:       "1.0",
			Service:       b,
			Public:        true,
			Authenticated: false,
		},
	}, []string{"eth"}, srv, false)
}

// Based on https://github.com/ethereum/go-ethereum/blob/16701c51697e28986feebd122c6a491e4d9ac0e7/internal/ethapi/api.go#L1200
func (b *EthBackend) rpcMarshalBlock(ctx context.Context, block *ethTypes.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields, err := types.RPCMarshalBlock(block, inclTx, fullTx, b.chain.Config())
	if err != nil {
		return nil, err
	}
	if inclTx {
		fields["totalDifficulty"] = (*hexutil.Big)(b.chain.GetTd(block.Hash(), block.NumberU64()))
	}
	return fields, err
}

func (b *EthBackend) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block := b.chain.GetBlockByHash(hash)
	if block == nil {
		return nil, errors.New("unknown block")
	}
	return b.rpcMarshalBlock(ctx, block, true, fullTx)
}

func (b *EthBackend) GetBlockByNumber(ctx context.Context, number gethRpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	switch number {
	case gethRpc.PendingBlockNumber:
		return nil, errors.New("not implemented")
	case gethRpc.LatestBlockNumber:
		block := b.chain.CurrentBlock()
		if block == nil {
			block = b.chain.Genesis()
		}
		return b.rpcMarshalBlock(ctx, block, true, fullTx)
	default:
		block := b.chain.GetBlockByNumber(uint64(number))
		if block == nil {
			return nil, errors.New("unknown block")
		}
		return b.rpcMarshalBlock(ctx, block, true, fullTx)
	}
}
