package types

import (
	"encoding/binary"

	"github.com/prysmaticlabs/prysm/crypto/bls"
)

type Domain [32]byte
type DomainType uint32

var (
	DomainBuilder Domain
)

const (
	DomainTypeBeaconProposer DomainType = 0x00000000
	DomainTypeAppBuilder     DomainType = 0x00000001
)

func init() {
	DomainBuilder = ComputeApplicationDomain(DomainTypeAppBuilder)
}

type SigningData struct {
	Root   Root   `ssz-size:"32"`
	Domain Domain `ssz-size:"32"`
}

type forkData struct {
	CurrentVersion        uint32
	GenesisValidatorsRoot Root `ssz-size:"32"`
}

type HashTreeRoot interface {
	HashTreeRoot() ([32]byte, error)
}

func ComputeDomain(dt DomainType, forkVersion uint32, genesisValidatorsRoot *Root) [32]byte {
	if genesisValidatorsRoot == nil {
		var tmp Root
		genesisValidatorsRoot = &tmp
	}
	forkDataRoot, _ := (&forkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: *genesisValidatorsRoot,
	}).HashTreeRoot()

	var domain [32]byte
	binary.LittleEndian.PutUint32(domain[0:4], uint32(dt))
	copy(domain[4:], forkDataRoot[0:28])

	return domain
}

func ComputeApplicationDomain(dt DomainType) [32]byte {
	return ComputeDomain(dt, 0, nil)
}

func ComputeSigningRoot(obj HashTreeRoot, d Domain) ([32]byte, error) {
	var zero [32]byte
	root, err := obj.HashTreeRoot()
	if err != nil {
		return zero, err
	}
	signingData := SigningData{root, d}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return zero, err
	}
	return msg, nil
}

func VerifySignature(obj HashTreeRoot, d Domain, pk, s []byte) (bool, error) {
	msg, err := ComputeSigningRoot(obj, d)
	if err != nil {
		return false, err
	}
	sig, err := bls.SignatureFromBytes(s)
	if err != nil {
		return false, err
	}
	pubkey, err := bls.PublicKeyFromBytes(pk)
	if err != nil {
		return false, err
	}
	return sig.Verify(pubkey, msg[:]), nil
}
