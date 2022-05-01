package types

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Signature [96]byte
type PublicKey [48]byte
type Address [20]byte
type Hash [32]byte
type Root Hash
type CommitteeBits [64]byte
type Bloom [256]byte

var (
	ErrLength = fmt.Errorf("incorrect byte length")
)

func (s Signature) MarshalText() ([]byte, error) {
	return hexutil.Bytes(s[:]).MarshalText()
}

func (s *Signature) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(s[:])
	b.UnmarshalJSON(input)
	if len(b) != 96 {
		return ErrLength
	}
	return nil
}

func (s *Signature) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(s[:])
	b.UnmarshalText(input)
	if len(b) != 96 {
		return ErrLength
	}
	return nil

}

func (s Signature) String() string {
	return hexutil.Bytes(s[:]).String()
}

func (s *Signature) FromSlice(x []byte) {
	copy(s[:], x)
}

func (p PublicKey) MarshalText() ([]byte, error) {
	return hexutil.Bytes(p[:]).MarshalText()
}

func (p *PublicKey) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(p[:])
	b.UnmarshalJSON(input)
	if len(b) != 48 {
		return ErrLength
	}
	return nil
}

func (p *PublicKey) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(p[:])
	b.UnmarshalText(input)
	if len(b) != 48 {
		return ErrLength
	}
	return nil

}

func (p PublicKey) String() string {
	return hexutil.Bytes(p[:]).String()
}

func (p *PublicKey) FromSlice(x []byte) {
	copy(p[:], x)
}

func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}

func (a *Address) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(a[:])
	b.UnmarshalJSON(input)
	if len(b) != 20 {
		return ErrLength
	}
	return nil
}

func (a *Address) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(a[:])
	b.UnmarshalText(input)
	if len(b) != 20 {
		return ErrLength
	}
	return nil

}

func (a Address) String() string {
	return hexutil.Bytes(a[:]).String()
}

func (a *Address) FromSlice(x []byte) {
	copy(a[:], x)
}

func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

func (h *Hash) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(h[:])
	b.UnmarshalJSON(input)
	if len(b) != 32 {
		return ErrLength
	}
	return nil
}

func (h *Hash) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(h[:])
	b.UnmarshalText(input)
	if len(b) != 32 {
		return ErrLength
	}
	return nil

}

func (h Hash) String() string {
	return hexutil.Bytes(h[:]).String()
}

func (c CommitteeBits) MarshalText() ([]byte, error) {
	return hexutil.Bytes(c[:]).MarshalText()
}

func (c *CommitteeBits) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(c[:])
	b.UnmarshalJSON(input)
	if len(b) != 64 {
		return ErrLength
	}
	return nil
}

func (c *CommitteeBits) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(c[:])
	b.UnmarshalText(input)
	if len(b) != 64 {
		return ErrLength
	}
	return nil

}

func (c CommitteeBits) String() string {
	return hexutil.Bytes(c[:]).String()
}

func (c *CommitteeBits) FromSlice(x []byte) {
	copy(c[:], x)
}

func (b Bloom) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

func (b *Bloom) UnmarshalJSON(input []byte) error {
	buf := hexutil.Bytes(b[:])
	buf.UnmarshalJSON(input)
	if len(b) != 256 {
		return ErrLength
	}
	return nil
}

func (b *Bloom) UnmarshalText(input []byte) error {
	buf := hexutil.Bytes(b[:])
	buf.UnmarshalText(input)
	if len(b) != 256 {
		return ErrLength
	}
	return nil

}

func (b Bloom) String() string {
	return hexutil.Bytes(b[:]).String()
}

func (b *Bloom) FromSlice(x []byte) {
	copy(b[:], x)
}
