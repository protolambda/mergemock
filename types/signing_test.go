package types

import (
	"testing"

	"github.com/prysmaticlabs/prysm/crypto/bls"
	"github.com/stretchr/testify/require"
)

func newKeypair(t *testing.T) (pubkey []byte, privkey bls.SecretKey) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatal("unable to generate bls key pair", err)
	}
	return sk.PublicKey().Marshal(), sk
}

func TestVerifySignature(t *testing.T) {
	pk, sk := newKeypair(t)
	msg := &RegisterValidatorRequestMessage{
		FeeRecipient: Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    1652369368,
		Pubkey:       PublicKey{0x0d},
	}
	domain := ComputeApplicationDomain(0x01)
	root, err := ComputeSigningRoot(msg, domain)
	require.NoError(t, err)

	sig := sk.Sign(root[:])
	ok, err := VerifySignature(msg, domain, pk, sig.Marshal())
	require.NoError(t, err)
	require.True(t, ok)
}
