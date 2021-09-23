package main

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"math"
	"time"
)

type ConsensusCmd struct {
	PastGenesis   time.Duration `ask:"--past-genesis" help:"Time past genesis (can be negative for pre-genesis)"`
	SlotTime      time.Duration `ask:"--slot-time" help:"Time per slot"`
	SlotsPerEpoch uint64        `ask:"--slots-per-epoch" help:"Slots per epoch"`
	// TODO ideas:
	// - % random gap slots (= missing beacon blocks)
	// - % random finality

	// embed logger options
	LogCmd `ask:".log"`

	close chan struct{}
}

func (c *ConsensusCmd) Default() {
	c.SlotTime = time.Second * 12
	c.SlotsPerEpoch = 32
	c.LogLvl = "info"
}

func (c *ConsensusCmd) Help() string {
	return "Run a mock Consensus client."
}

func (c *ConsensusCmd) Run(ctx context.Context, args ...string) error {
	log, err := c.LogCmd.Create()
	if err != nil {
		return err
	}
	if c.SlotTime < 50*time.Millisecond {
		return fmt.Errorf("slot time %s is too small", c.SlotTime.String())
	}

	c.close = make(chan struct{})

	go c.RunNode(log)

	return nil
}

func (c *ConsensusCmd) RunNode(log *logrus.Logger) {
	log.Info("started")

	genesisTime := time.Now().Add(-c.PastGenesis)

	slotsPastGenesis := c.PastGenesis / c.SlotTime
	if slotsPastGenesis > 0 {
		// TODO: simulate data since genesis
	}

	slots := time.NewTicker(c.SlotTime)
	// align ticker with genesis
	slots.Reset(c.PastGenesis % c.SlotTime)
	defer slots.Stop()

	for {
		select {
		case tick := <-slots.C:
			// 52 bits is plenty
			slot := int64(math.Round(float64(tick.Sub(genesisTime)) / float64(c.SlotTime)))
			if slot < 0 {
				// before genesis...
				if slot >= -10.0 {
					log.WithField("remaining_slots", -slot).Info("counting down to genesis...")
				}
				continue
			}

			log.WithField("slot", slot).Info("slot trigger")

			// TODO: simulate new payload for execution layer
		case <-c.close:
			log.Info("closing consensus mock node")
		}
	}

}

func (c *ConsensusCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}
