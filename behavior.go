package main

import (
	"fmt"
	"math/rand"
	"strconv"
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

type ConsensusBehavior struct {
	RNG  RNG `ask:"--rng" help:"seed the RNG with an integer number"`
	Freq struct {
		GapSlot            float64 `ask:"--gap" help:"How often an execution block is missing"`
		ProposalFreq       float64 `ask:"--proposal" help:"How often the engine gets to propose a block"`
		FailedProposalFreq float64 `ask:"--ignore" help:"How often the payload produced by the engine does not become canonical"`
		Finality           float64 `ask:"--finality" help:"How often an epoch succeeds to finalize"`
		ReorgFreq          float64 `ask:"--reorg" help:"Frequency of chain reorgs"`
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
}
