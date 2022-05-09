package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecutionPayloadHeader(t *testing.T) {
	baseFeePerGas := U256Str{}
	baseFeePerGas[31] = 0x08

	h := ExecutionPayloadHeader{
		ParentHash:       Hash{0x01},
		FeeRecipient:     Address{0x02},
		StateRoot:        Root{0x03},
		ReceiptsRoot:     Root{0x04},
		LogsBloom:        Bloom{0x05},
		Random:           Hash{0x06},
		Number:           5001,
		GasLimit:         5002,
		GasUsed:          5003,
		Timestamp:        5004,
		ExtraData:        Hash{0x07},
		BaseFeePerGas:    baseFeePerGas,
		BlockHash:        Hash{0x09},
		TransactionsRoot: Root{0x0a},
	}
	b, err := json.Marshal(h)
	require.NoError(t, err)

	expectedJSON := `{"parent_hash":"0x0100000000000000000000000000000000000000000000000000000000000000","fee_recipient":"0x0200000000000000000000000000000000000000","state_root":[3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"receipts_root":[4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"logs_bloom":"0x05000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x0600000000000000000000000000000000000000000000000000000000000000","block_number":"5001","gas_limit":"5002","gas_used":"5003","timestamp":"5004","extra_data":"0x0700000000000000000000000000000000000000000000000000000000000000","base_fee_per_gas":"8","block_hash":"0x0900000000000000000000000000000000000000000000000000000000000000","transactions_root":[10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	require.JSONEq(t, expectedJSON, string(b))

	h2 := new(ExecutionPayloadHeader)
	err = json.Unmarshal(b, h2)
	require.NoError(t, err)
	require.Equal(t, h.ParentHash, h2.ParentHash)
}
