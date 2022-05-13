package types

import (
	"testing"

	"github.com/prysmaticlabs/prysm/shared/bls/blst"
	"github.com/stretchr/testify/require"
)

func TestVerifySignatureManualPk(t *testing.T) {
	msg2 := RegisterValidatorRequestMessage{
		FeeRecipient: Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    1652369368,
		Pubkey:       PublicKey{0x0d},
	}
	root2, err := msg2.HashTreeRoot()
	require.NoError(t, err)

	// Verify expected signature with manual pk
	pkBytes := make([]byte, 32)
	pkBytes[0] = 0x01
	sk2, err := blst.SecretKeyFromBytes(pkBytes)
	require.NoError(t, err)
	sig2 := sk2.Sign(root2[:]).Marshal()
	var signature2 Signature
	signature2.FromSlice(sig2)
	require.Equal(t, "0x8e09a0ae7af113da2043001cc19fb1b3b24bbe022c1b8050ba2297ad1186f4217dd7095edad1d16d83d10f3297883d9e1674c81da95f10d3358c5afdb2500279e720b32879219c9a3b33415239bf46a66cd92b9d1750a6dd7cc7ec936a357128", signature2.String())
}
