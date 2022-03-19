package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const DefaultRNGSeed = 1234

type RNG struct {
	*rand.Rand
}

func (i *RNG) String() string {
	return fmt.Sprintf("%d", DefaultRNGSeed)
}

func (i *RNG) Set(s string) error {
	seed, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return err
	}
	*i = RNG{rand.New(rand.NewSource(seed))}
	return nil
}

func (i *RNG) Type() string {
	return "RNG"
}

type TestAccount struct {
	pk   *ecdsa.PrivateKey
	addr common.Address
}

type TestAccounts struct {
	accounts []TestAccount
}

func (t *TestAccounts) String() string {
	all := make([]string, 0, len(t.accounts))
	for _, a := range t.accounts {
		all = append(all, a.addr.String())
	}
	return strings.Join(all, ",")
}

func (t *TestAccounts) Set(s string) error {
	keys := strings.Split(s, ",")
	t.accounts = make([]TestAccount, 0, len(keys))
	for _, hex := range keys {
		pk, err := crypto.HexToECDSA(hex)
		if err != nil {
			return fmt.Errorf("failed interpret hex private key: %s", err)
		}
		t.accounts = append(t.accounts, TestAccount{pk, crypto.PubkeyToAddress(pk.PublicKey)})
	}
	return nil
}

func (t *TestAccounts) Type() string {
	return "TestAccount"
}

type ConsensusBehavior struct {
	RNG          RNG          `ask:"--rng" help:"seed the RNG with an integer number"`
	TestAccounts TestAccounts `ask:"--test-accounts" help:"comma-seperated list of hex encoded private key for an account to send test transactions from"`
	Freq         struct {
		GapSlot            float64 `ask:"--gap" help:"How often an execution block is missing"`
		ProposalFreq       float64 `ask:"--proposal" help:"How often the engine gets to propose a block"`
		FailedProposalFreq float64 `ask:"--ignore" help:"How often the payload produced by the engine does not become canonical"`
		Finality           float64 `ask:"--finality" help:"How often an epoch succeeds to finalize"`
		ReorgFreq          float64 `ask:"--reorg" help:"Frequency of chain reorgs"`
		InvalidHashFreq    float64 `ask:"--invalid-hash" help:"Frequency of invalid payload hashes"`
		// TODO more fun
	} `ask:".freq" help:"Modify frequencies of certain behavior"`
	ReorgMaxDepth uint64 `ask:"--reorg-max-depth" help:"Max depth of a chain reorg"`
}

func (b *ConsensusBehavior) Default() {
	b.RNG = RNG{rand.New(rand.NewSource(DefaultRNGSeed))}
	b.Freq.GapSlot = 0.05
	b.Freq.ProposalFreq = 0.5
	b.Freq.FailedProposalFreq = 0.1
	b.Freq.Finality = 0.1
	b.ReorgMaxDepth = 64
	b.Freq.ReorgFreq = 0.05
	b.Freq.InvalidHashFreq = 0.01
}
