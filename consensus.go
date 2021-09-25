package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/rpc"
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

	EngineAddr string `ask:"--engine" help:"Address of Engine JSON-RPC endpoint to use"`

	// embed logger options
	LogCmd `ask:".log"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	engine *rpc.Client
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

	client, err := rpc.DialContext(ctx, c.EngineAddr)
	if err != nil {
		return err
	}

	c.log = log
	c.engine = client
	c.ctx = ctx
	c.close = make(chan struct{})

	go c.RunNode()

	return nil
}

func (c *ConsensusCmd) RunNode() {
	c.log.Info("started")

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
					c.log.WithField("remaining_slots", -slot).Info("counting down to genesis...")
				}
				continue
			}

			c.log.WithField("slot", slot).Info("slot trigger")

			//id, err := PreparePayload(c.ctx, c.engine, c.log.WithField("slot", slot), &PreparePayloadParams{TODO})

			// TODO: simulate new payload for execution layer
		case <-c.close:
			c.log.Info("closing consensus mock node")
			c.engine.Close()
		}
	}
}

func (c *ConsensusCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}
