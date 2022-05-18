package types

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
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
		BlockNumber:      5001,
		GasLimit:         5002,
		GasUsed:          5003,
		Timestamp:        5004,
		ExtraData:        []byte{0x07},
		BaseFeePerGas:    baseFeePerGas,
		BlockHash:        Hash{0x09},
		TransactionsRoot: Root{0x0a},
	}
	b, err := json.Marshal(h)
	require.NoError(t, err)

	expectedJSON := `{
        "parent_hash": "0x0100000000000000000000000000000000000000000000000000000000000000",
        "fee_recipient": "0x0200000000000000000000000000000000000000",
        "state_root": "0x0300000000000000000000000000000000000000000000000000000000000000",
        "receipts_root": "0x0400000000000000000000000000000000000000000000000000000000000000",
        "logs_bloom": "0x05000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "prev_randao": "0x0600000000000000000000000000000000000000000000000000000000000000",
        "block_number": "5001",
        "gas_limit": "5002",
        "gas_used": "5003",
        "timestamp": "5004",
        "extra_data": "0x07",
        "base_fee_per_gas": "8",
        "block_hash": "0x0900000000000000000000000000000000000000000000000000000000000000",
        "transactions_root": "0x0a00000000000000000000000000000000000000000000000000000000000000"
    }`
	require.JSONEq(t, expectedJSON, string(b))

	// Now unmarshal it back and compare to original
	h2 := new(ExecutionPayloadHeader)
	err = json.Unmarshal(b, h2)
	require.NoError(t, err)
	require.Equal(t, h.ParentHash, h2.ParentHash)

	p, err := h2.HashTreeRoot()
	require.NoError(t, err)
	rootHex := fmt.Sprintf("%x", p)
	require.Equal(t, "7b7fd346d2b66aab2efce23959d7f90f36ff31a944ba867ae1c2827f85b2fbe5", rootHex)
}

func TestBlindedBeaconBlock(t *testing.T) {
	parentHash := Hash{0xa1}
	blockHash := Hash{0xa1}
	feeRecipient := Address{0xb1}

	msg := &BlindedBeaconBlock{
		Slot:          1,
		ProposerIndex: 2,
		ParentRoot:    Root{0x03},
		StateRoot:     Root{0x04},
		Body: &BlindedBeaconBlockBody{
			Eth1Data: &Eth1Data{
				DepositRoot:  Root{0x05},
				DepositCount: 5,
				BlockHash:    Hash{0x06},
			},
			ProposerSlashings: []*ProposerSlashing{},
			AttesterSlashings: []*AttesterSlashing{},
			Attestations:      []*Attestation{},
			Deposits:          []*Deposit{},
			VoluntaryExits:    []*VoluntaryExit{},
			SyncAggregate:     &SyncAggregate{CommitteeBits{0x07}, Signature{0x08}},
			ExecutionPayloadHeader: &ExecutionPayloadHeader{
				ParentHash:       parentHash,
				FeeRecipient:     feeRecipient,
				StateRoot:        Root{0x09},
				ReceiptsRoot:     Root{0x0a},
				LogsBloom:        Bloom{0x0b},
				Random:           Hash{0x0c},
				BlockNumber:      5001,
				GasLimit:         5002,
				GasUsed:          5003,
				Timestamp:        5004,
				ExtraData:        []byte{0x0d},
				BaseFeePerGas:    IntToU256(123456789),
				BlockHash:        blockHash,
				TransactionsRoot: Root{0x0e},
			},
		},
	}

	// Get HashTreeRoot
	root, err := msg.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "b3b6844756cbf0fdd996cb20a1439bfb59a640cdae1604dbd8a81c7c993a6a6b", fmt.Sprintf("%x", root))

	// Marshalling
	b, err := json.Marshal(msg)
	require.NoError(t, err)
	// fmt.Println(string(b))

	expectedJSON := `{
        "slot": "1",
        "proposer_index": "2",
        "parent_root": "0x0300000000000000000000000000000000000000000000000000000000000000",
        "state_root": "0x0400000000000000000000000000000000000000000000000000000000000000",
        "body": {
            "randao_reveal": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "eth1_data": {
                "deposit_root": "0x0500000000000000000000000000000000000000000000000000000000000000",
                "deposit_count": "5",
                "block_hash": "0x0600000000000000000000000000000000000000000000000000000000000000"
            },
            "graffiti": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "proposer_slashings": [],
            "attester_slashings": [],
            "attestations": [],
            "deposits": [],
            "voluntary_exits": [],
            "sync_aggregate": {
                "sync_committee_bits": "0x07000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "sync_committee_signature": "0x080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            },
            "execution_payload_header": {
                "parent_hash": "0xa100000000000000000000000000000000000000000000000000000000000000",
                "fee_recipient": "0xb100000000000000000000000000000000000000",
                "state_root": "0x0900000000000000000000000000000000000000000000000000000000000000",
                "receipts_root": "0x0a00000000000000000000000000000000000000000000000000000000000000",
                "logs_bloom": "0x0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "prev_randao": "0x0c00000000000000000000000000000000000000000000000000000000000000",
                "block_number": "5001",
                "gas_limit": "5002",
                "gas_used": "5003",
                "timestamp": "5004",
                "extra_data": "0x0d",
                "base_fee_per_gas": "123456789",
                "block_hash": "0xa100000000000000000000000000000000000000000000000000000000000000",
                "transactions_root": "0x0e00000000000000000000000000000000000000000000000000000000000000"
            }
        }
    }`
	require.JSONEq(t, expectedJSON, string(b))

	// Now unmarshal it back and compare to original
	msg2 := new(BlindedBeaconBlock)
	err = json.Unmarshal(b, msg2)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)

	// HashTreeRoot
	p, err := msg2.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "b3b6844756cbf0fdd996cb20a1439bfb59a640cdae1604dbd8a81c7c993a6a6b", fmt.Sprintf("%x", p))
}

func TestExecutionPayloadREST(t *testing.T) {
	parentHash := Hash{0xa1}
	blockHash := Hash{0xa1}
	feeRecipient := Address{0xb1}

	tx1hex := "0xcdc2b165e82ed1fe09aae28fccee2199946baf6b4503ca7e6f19aaa95a92b766dce6d968024a68d97ee178082928142430d4"
	tx1 := new(hexutil.Bytes)
	tx1.UnmarshalText([]byte(tx1hex))

	msg := &ExecutionPayloadREST{
		ParentHash:    parentHash,
		FeeRecipient:  feeRecipient,
		StateRoot:     Root{0x09},
		ReceiptsRoot:  Root{0x0a},
		LogsBloom:     Bloom{0x0b},
		Random:        Hash{0x0c},
		BlockNumber:   5001,
		GasLimit:      5002,
		GasUsed:       5003,
		Timestamp:     5004,
		ExtraData:     []byte{0x0d},
		BaseFeePerGas: IntToU256(123456789),
		BlockHash:     blockHash,
		Transactions:  []hexutil.Bytes{*tx1},
	}

	// Marshalling
	b, err := json.Marshal(msg)
	require.NoError(t, err)
	fmt.Println(string(b))

	expectedJSON := `{
        "parent_hash": "0xa100000000000000000000000000000000000000000000000000000000000000",
        "fee_recipient": "0xb100000000000000000000000000000000000000",
        "state_root": "0x0900000000000000000000000000000000000000000000000000000000000000",
        "receipts_root": "0x0a00000000000000000000000000000000000000000000000000000000000000",
        "logs_bloom": "0x0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "prev_randao": "0x0c00000000000000000000000000000000000000000000000000000000000000",
        "block_number": "5001",
        "gas_limit": "5002",
        "gas_used": "5003",
        "timestamp": "5004",
        "extra_data": "0x0d",
        "base_fee_per_gas": "123456789",
        "block_hash": "0xa100000000000000000000000000000000000000000000000000000000000000",
        "transactions": [
            "0xcdc2b165e82ed1fe09aae28fccee2199946baf6b4503ca7e6f19aaa95a92b766dce6d968024a68d97ee178082928142430d4"
        ]
    }`
	require.JSONEq(t, expectedJSON, string(b))

	// Now unmarshal it back and compare to original
	msg2 := new(ExecutionPayloadREST)
	err = json.Unmarshal(b, msg2)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)

	// Check converting to EL style and back
	elMsg, err := RESTPayloadToELPayload(msg2)
	require.NoError(t, err)
	clMsg, err := ELPayloadToRESTPayload(elMsg)
	require.NoError(t, err)
	require.Equal(t, msg, clMsg)
}

func TestExecutionPayloadV1(t *testing.T) {
	msgEl1 := &ExecutionPayloadV1{
		ParentHash:    common.Hash{0x01},
		FeeRecipient:  common.Address{0x02},
		StateRoot:     common.Hash{0x09},
		ReceiptsRoot:  common.Hash{0x0a},
		LogsBloom:     types.Bloom{0x0b},
		Random:        common.Hash{0x0c},
		Number:        5001,
		GasLimit:      5002,
		GasUsed:       5003,
		Timestamp:     5004,
		ExtraData:     []byte{0x0d},
		BaseFeePerGas: big.NewInt(1234567),
		BlockHash:     common.Hash{0xa1},
		Transactions:  [][]byte{{0x01}},
	}

	// Convert EL -> CL
	msgCl, err := ELPayloadToRESTPayload(msgEl1)
	require.NoError(t, err)

	// Convert CL -> EL
	msgEl2, err := RESTPayloadToELPayload(msgCl)
	require.NoError(t, err)

	// Make sure everything is still the same
	require.Equal(t, msgEl1, msgEl2)
}

func TestMerkelizeTxs(t *testing.T) {
	txs := transactions{}
	root, err := txs.HashTreeRoot()
	require.NoError(t, err)
	expected := "7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1"
	require.Equal(t, expected, common.Bytes2Hex(root[:]))
}

func TestMerkelizePayload(t *testing.T) {
	input := `{"slot":"1","proposer_index":"7","parent_root":"0x7c1018e636481b7813e68a00af9f52f0d344f89eed431bb8a50618e2bc212dc6","state_root":"0xbaa15a02568c3e0442652c616f50cb60e8e11e86e2858fa7994e67a4017d6d3e","body":{"randao_reveal":"0xb6ea50c6ab03f159a893414161b2fb6d2ec61dc82868b13520acc180fc2d9b0d2d841d467295dbbae0e81bee7d3022060750f64879e5a3f0755380aa97710893d3e8cf2edac09e684c893999e3ef94f19231edf5b4fa46afe90ea1fb6b6c9e64","eth1_data":{"deposit_root":"0x23090150015e4c9d0c7ba87f97087375cdf19d6e2caeedc994d7c445b3460119","deposit_count":"32","block_hash":"0xccaf66b50e791f95d4b50bae4de28af9396824e7c29f99aeba19414fdf72673f"},"graffiti":"0x0000000000000000000000000000000000000000000000000000000000000000","proposer_slashings":[],"attester_slashings":[],"attestations":[{"aggregation_bits":"0x03","data":{"slot":"0","index":"0","beacon_block_root":"0x7c1018e636481b7813e68a00af9f52f0d344f89eed431bb8a50618e2bc212dc6","source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":"0","root":"0x7c1018e636481b7813e68a00af9f52f0d344f89eed431bb8a50618e2bc212dc6"}},"signature":"0xae9ec2c1bf76ec5a5d78c2a252dfb66a00f2828b3000d5b052f189064a836a864379afd3ce82f45517ff3a3b15b1c38d1551edde6352c07948e59596bdc97abd0be2cf27c6562bfb20cbacde37fab37eda7e5d1f73622e7e7fe1472a2bbd158a"}],"deposits":[],"voluntary_exits":[],"sync_aggregate":{"sync_committee_bits":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","sync_committee_signature":"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"execution_payload_header":{"parent_hash":"0xccaf66b50e791f95d4b50bae4de28af9396824e7c29f99aeba19414fdf72673f","fee_recipient":"0x0000000000000000000000000000000000000000","state_root":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receipts_root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0xccaf66b50e791f95d4b50bae4de28af9396824e7c29f99aeba19414fdf72673f","block_number":"1","gas_limit":"30000000","gas_used":"0","timestamp":"1652735778","extra_data":"0x","base_fee_per_gas":"7","block_hash":"0x2244ab321090e7f53b51328d64d2a02f03ff9aa65f37208ec404cac8867a9dc3","transactions_root":"0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1"}}}`
	var block BlindedBeaconBlock
	err := json.Unmarshal([]byte(input), &block)
	require.NoError(t, err)

	root, err := block.Body.ExecutionPayloadHeader.HashTreeRoot()
	require.NoError(t, err)
	expected := []byte{117, 152, 122, 157, 27, 94, 22, 199,
		27, 202, 147, 171, 213, 66, 199, 100,
		182, 125, 183, 226, 81, 32, 96, 115,
		59, 213, 30, 7, 226, 30, 117, 206}
	require.Equal(t, expected, root[:])

	// TODO still not working
	// root, err = block.HashTreeRoot()
	// require.NoError(t, err)
	// expected = []byte{135, 181, 122, 105, 50, 30, 194, 30,
	//         138, 131, 163, 159, 47, 15, 136, 90,
	//         59, 233, 187, 221, 184, 7, 148, 179,
	//         178, 112, 12, 60, 248, 35, 10, 161}
	// require.Equal(t, expected, root[:])
}
