package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/core/state"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type ConsensusCmd struct {
	BeaconGenesisTime uint64        `ask:"--beacon-genesis-time" help:"Beacon genesis time"`
	SlotTime          time.Duration `ask:"--slot-time" help:"Time per slot"`
	SlotsPerEpoch     uint64        `ask:"--slots-per-epoch" help:"Slots per epoch"`
	// TODO ideas:
	// - % random gap slots (= missing beacon blocks)
	// - % random finality

	EngineAddr  string `ask:"--engine" help:"Address of Engine JSON-RPC endpoint to use"`
	DataDir     string `ask:"--datadir" help:"Directory to store execution chain data (empty for in-memory data)"`
	GenesisPath string `ask:"--genesis" help:"Genesis execution-config file"`

	// embed consensus behaviors
	ConsensusBehavior `ask:"."`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	engine *rpc.Client

	mockChain *MockChain
}

func (c *ConsensusCmd) Default() {
	c.BeaconGenesisTime = uint64(time.Now().Unix()) + 5

	c.EngineAddr = "http://127.0.0.1:8550"

	c.GenesisPath = "genesis.json"

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

	var db ethdb.Database
	if c.DataDir == "" {
		db = rawdb.NewMemoryDatabase()
	} else {
		db, err = rawdb.NewLevelDBDatabaseWithFreezer(c.DataDir, 128, 128, c.DataDir, "", false)
		if err != nil {
			return err
		}
	}

	genesis, err := LoadGenesisConfig(c.GenesisPath)
	if err != nil {
		return err
	}

	c.mockChain = NewMockChain(log, c.BeaconGenesisTime, c.SlotTime, genesis, db)

	c.log = log
	c.engine = client
	c.ctx = ctx
	c.close = make(chan struct{})

	go c.RunNode()

	return nil
}

func (c *ConsensusCmd) RunNode() {
	c.log.Info("started")

	// TODO: simulate data since genesis

	slots := time.NewTicker(c.SlotTime)
	// align ticker with genesis
	//slots.Reset(c.PastGenesis % c.SlotTime) // TODO
	defer slots.Stop()

	genesisTime := time.Unix(int64(c.mockChain.beaconGenesisTimestamp), 0)

	for {
		select {
		case tick := <-slots.C:
			// 52 bits is plenty
			signedSlot := int64(math.Round(float64(tick.Sub(genesisTime)) / float64(c.SlotTime)))
			if signedSlot < 0 {
				// before genesis...
				if signedSlot >= -10.0 {
					c.log.WithField("remaining_slots", -signedSlot).Info("counting down to genesis...")
				}
				continue
			}
			slot := uint64(signedSlot)

			// TODO: fake some forking by not always building on the latest payload
			parent := c.mockChain.Head()
			slotLog := c.log.WithField("slot", slot)
			slotLog.WithField("previous", parent).Info("slot trigger")

			if c.RNG.Float64() < c.Freq.GapSlot {
				// gap slot
				slotLog.Info("mocking gap slot, no payload execution here")
			} else {
				if c.RNG.Float64() < c.Freq.ProposalFreq {
					// try get a block from the engine, we're a proposer!
					slotLog.Info("proposing block with engine")

					// in main loop, avoid concurrent randomness for reproducibility
					var random32 Bytes32
					c.RNG.Read(random32[:])

					// when we produce the payload, but fail to get it into the chain
					consensusProposalFail := c.RNG.Float64() < c.Freq.FailedProposalFreq

					coinbase := common.Address{0x13, 0x37}

					go c.mockProposal(slotLog, parent, slot, coinbase, random32, consensusProposalFail)
				} else {
					// build a block, without using the engine, and insert it into the engine
					slotLog.Info("mocking outside world, creating block without engine")

					// TODO: different proposers, gas limit (target in london) changes, etc.
					coinbase := common.Address{1}
					timestamp := c.mockChain.SlotTimestamp(slot)
					gasLimit := c.mockChain.gspec.GasLimit
					extraData := []byte("proto says hi")
					uncleBlocks := []*types.Header{} // none in proof of stake
					creator := TransactionsCreator(dummyTxCreator)

					block, err := c.mockChain.AddNewBlock(parent, coinbase, timestamp, gasLimit, creator, extraData, uncleBlocks, true)
					if err != nil {
						slotLog.WithError(err).Errorf("failed to add block")
						continue
					}

					slotLog.WithField("blockhash", block.Hash()).Info("built external block")

					// don't wait for the engine in the main loop
					go c.mockExecution(slotLog, block)
				}

				// TODO: signal head changes

				// TODO: signal finality changes
			}

		case <-c.close:
			c.log.Info("closing consensus mock node")
			c.engine.Close()
			c.mockChain.Close()
		}
	}
}

func (c *ConsensusCmd) mockProposal(log logrus.Ext1FieldLogger, parent common.Hash, slot uint64, coinbase common.Address, random32 Bytes32, consensusFail bool) {
	payload, err := c.mockPrep(log, parent, slot, random32, coinbase)
	if err != nil {
		log.WithError(err).Error("failed to prepare and get payload, failed proposal")
		return
	}

	if consensusFail {
		log.Info("mocking a failed proposal on consensus-side, ignoring produced payload of engine")
	} else {
		if err := c.mockChain.ValidateTimestamp(uint64(payload.Timestamp), slot); err != nil {
			log.WithError(err).Error("payload has bad timestamp")
			return
		}
		bl, err := c.mockChain.ProcessPayload(payload)
		if err != nil {
			log.WithError(err).Error("failed to process execution payload from engine")
			return
		} else {
			log.WithField("blockhash", bl.Hash()).Info("processed payload in consensus mock world")
		}

		// send it back to execution layer for execution
		ctx, _ := context.WithTimeout(c.ctx, time.Second*20)
		execStatus, err := ExecutePayload(ctx, c.engine, log, payload)
		if err != nil {
			log.WithError(err).Error("failed to execute payload")
		} else if execStatus == ExecutionValid {
			log.WithField("blockhash", bl.Hash()).Info("processed payload in engine")
		} else if execStatus == ExecutionInvalid {
			log.WithField("blockhash", bl.Hash()).Error("engine just produced payload and failed to execute it after!")
		} else {
			log.WithField("status", execStatus).Error("unrecognized execution status")
		}
	}
}

func (c *ConsensusCmd) mockPrep(log logrus.Ext1FieldLogger, parent common.Hash, slot uint64, random Bytes32, feeRecipient common.Address) (*ExecutionPayload, error) {
	ctx, _ := context.WithTimeout(c.ctx, time.Second*20)
	params := &PreparePayloadParams{
		ParentHash:   parent,
		Timestamp:    Uint64Quantity(c.mockChain.SlotTimestamp(slot)),
		Random:       random,
		FeeRecipient: feeRecipient,
	}
	id, err := PreparePayload(ctx, c.engine, log, params)
	if err != nil {
		return nil, err
	}

	return GetPayload(ctx, c.engine, log, id)
}

func (c *ConsensusCmd) mockExecution(log logrus.Ext1FieldLogger, block *types.Block) {
	ctx, _ := context.WithTimeout(c.ctx, time.Second*20)

	// derive the random 32 bytes from the block hash for mocking ease
	payload, err := BlockToPayload(block, mockRandomValue(block.Hash()))

	if err != nil {
		log.WithError(err).Error("failed to convert execution block to execution payload")
		return
	}

	ExecutePayload(ctx, c.engine, log, payload)
}

func dummyTxCreator(config *params.ChainConfig, bc core.ChainContext, statedb *state.StateDB, header *types.Header, cfg vm.Config) []*types.Transaction {
	// TODO create some more txs
	var (
		key, _ = crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		signer = types.NewLondonSigner(config.ChainID)
	)

	txdata := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(addr),
		To:        &addr,
		Gas:       30000,
		GasFeeCap: new(big.Int).Mul(big.NewInt(5), big.NewInt(params.GWei)),
		GasTipCap: big.NewInt(2),
		Data:      []byte{},
	}
	tx := types.NewTx(txdata)
	tx, _ = types.SignTx(tx, signer, key)

	return []*types.Transaction{tx}
}

func (c *ConsensusCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}
