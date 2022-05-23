package types

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

var (
	ErrLength = fmt.Errorf("incorrect byte length")
)

type Signature [96]byte

func (s Signature) MarshalText() ([]byte, error) {
	return hexutil.Bytes(s[:]).MarshalText()
}

func (s *Signature) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalJSON(input)
	if err != nil {
		return err
	}
	if len(b) != 96 {
		return ErrLength
	}
	s.FromSlice(b)
	return nil
}

func (s *Signature) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalText(input)
	if err != nil {
		return err
	}
	if len(b) != 96 {
		return ErrLength
	}
	s.FromSlice(b)
	return nil

}

func (s Signature) String() string {
	return hexutil.Bytes(s[:]).String()
}

func (s *Signature) FromSlice(x []byte) {
	copy(s[:], x)
}

type PublicKey [48]byte

func (p PublicKey) MarshalText() ([]byte, error) {
	return hexutil.Bytes(p[:]).MarshalText()
}

func (p *PublicKey) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(p[:])
	b.UnmarshalJSON(input)
	if len(b) != 48 {
		return ErrLength
	}
	p.FromSlice(b)
	return nil
}

func (p *PublicKey) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(p[:])
	b.UnmarshalText(input)
	if len(b) != 48 {
		return ErrLength
	}
	p.FromSlice(b)
	return nil

}

func (p PublicKey) String() string {
	return hexutil.Bytes(p[:]).String()
}

func (p *PublicKey) FromSlice(x []byte) {
	copy(p[:], x)
}

type Address [20]byte

func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}

func (a *Address) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(a[:])
	b.UnmarshalJSON(input)
	if len(b) != 20 {
		return ErrLength
	}
	a.FromSlice(b)
	return nil
}

func (a *Address) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(a[:])
	b.UnmarshalText(input)
	if len(b) != 20 {
		return ErrLength
	}
	a.FromSlice(b)
	return nil

}

func (a Address) String() string {
	return hexutil.Bytes(a[:]).String()
}

func (a *Address) FromSlice(x []byte) {
	copy(a[:], x)
}

type Hash [32]byte
type Root = Hash

func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

func (h *Hash) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(h[:])
	b.UnmarshalJSON(input)
	if len(b) != 32 {
		return ErrLength
	}
	h.FromSlice(b)
	return nil
}

func (h *Hash) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(h[:])
	b.UnmarshalText(input)
	if len(b) != 32 {
		return ErrLength
	}
	h.FromSlice(b)
	return nil

}

func (h *Hash) FromSlice(x []byte) {
	copy(h[:], x)
}

func (h Hash) String() string {
	return hexutil.Bytes(h[:]).String()
}

type CommitteeBits [64]byte

func (c CommitteeBits) MarshalText() ([]byte, error) {
	return hexutil.Bytes(c[:]).MarshalText()
}

func (c *CommitteeBits) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(c[:])
	b.UnmarshalJSON(input)
	if len(b) != 64 {
		return ErrLength
	}
	c.FromSlice(b)
	return nil
}

func (c *CommitteeBits) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(c[:])
	b.UnmarshalText(input)
	if len(b) != 64 {
		return ErrLength
	}
	c.FromSlice(b)
	return nil

}

func (c CommitteeBits) String() string {
	return hexutil.Bytes(c[:]).String()
}

func (c *CommitteeBits) FromSlice(x []byte) {
	copy(c[:], x)
}

type Bloom [256]byte

func (b Bloom) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

func (b *Bloom) UnmarshalJSON(input []byte) error {
	buf := hexutil.Bytes(b[:])
	buf.UnmarshalJSON(input)
	if len(b) != 256 {
		return ErrLength
	}
	b.FromSlice(buf)
	return nil
}

func (b *Bloom) UnmarshalText(input []byte) error {
	buf := hexutil.Bytes(b[:])
	buf.UnmarshalText(input)
	if len(b) != 256 {
		return ErrLength
	}
	b.FromSlice(buf)
	return nil
}

func (b Bloom) String() string {
	return hexutil.Bytes(b[:]).String()
}

func (b *Bloom) FromSlice(x []byte) {
	copy(b[:], x)
}

type U256Str Hash // encodes/decodes to string, not hex

func reverse(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	for i := len(dst)/2 - 1; i >= 0; i-- {
		opp := len(dst) - 1 - i
		dst[i], dst[opp] = dst[opp], dst[i]
	}
	return dst
}

func (n U256Str) MarshalText() ([]byte, error) {
	return []byte(new(big.Int).SetBytes(reverse(n[:])).String()), nil
}

func (n *U256Str) UnmarshalJSON(input []byte) error {
	if len(input) < 2 {
		return ErrLength
	}
	x := new(big.Int)
	err := x.UnmarshalJSON(input[1 : len(input)-1])
	if err != nil {
		return err
	}
	copy(n[:], reverse(x.FillBytes(n[:])))
	return nil
}

func (n *U256Str) UnmarshalText(input []byte) error {
	x := new(big.Int)
	err := x.UnmarshalText(input)
	if err != nil {
		return err
	}
	copy(n[:], reverse(x.FillBytes(n[:])))
	return nil

}

func (n *U256Str) String() string {
	return new(big.Int).SetBytes(reverse(n[:])).String()
}

func (n *U256Str) FromSlice(x []byte) {
	copy(n[:], x)
}

func IntToU256(i uint64) (ret U256Str) {
	s := fmt.Sprint(i)
	ret.UnmarshalText([]byte(s))
	return
}

type ExtraData []byte

func (e ExtraData) MarshalText() ([]byte, error) {
	return hexutil.Bytes(e).MarshalText()
}

func (e *ExtraData) UnmarshalJSON(input []byte) error {
	var buf = make(hexutil.Bytes, 0)
	buf.UnmarshalJSON(input)
	if len(buf) > 32 {
		return ErrLength
	}
	e.FromSlice(buf)
	return nil
}

func (e *ExtraData) UnmarshalText(input []byte) error {
	var buf hexutil.Bytes
	buf.UnmarshalText(input)
	if len(buf) > 32 {
		return ErrLength
	}
	e.FromSlice(buf)
	return nil
}

func (e ExtraData) String() string {
	return hexutil.Bytes(e).String()
}

func (e *ExtraData) FromSlice(x []byte) {
	tmp := make([]byte, len(x))
	copy(tmp, x)
	*e = tmp
}
