package main

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"mergemock/p2p"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/p2p/enode"
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
	EthashDir   string `ask:"--ethashdir" help:"Directory to store ethash data"`
	GenesisPath string `ask:"--genesis" help:"Genesis execution-config file"`
	Enode       string `ask:"--node" help:"Enode of execution client, required to insert pre-merge blocks."`
	Ttd         uint64 `ask:"--ttd" help:"The terminal total difficulty for the merge"`

	// embed consensus behaviors
	ConsensusBehavior `ask:"."`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	TraceLogConfig `ask:".trace" help:"Tracing options"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	engine *rpc.Client
	db     ethdb.Database

	ethashCfg ethash.Config
	peer      *p2p.Conn

	mockChain *MockChain
}

func (c *ConsensusCmd) Default() {
	c.BeaconGenesisTime = uint64(time.Now().Unix()) + 5
	c.EngineAddr = "http://127.0.0.1:8550"
	c.GenesisPath = "genesis.json"
	c.Enode = ""
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

	// Connect to execution client engine api
	client, err := rpc.DialContext(ctx, c.EngineAddr)
	if err != nil {
		return err
	}

	c.ethashCfg = ethash.Config{
		PowMode:        ethash.ModeNormal,
		DatasetDir:     c.EthashDir,
		CacheDir:       c.EthashDir,
		DatasetsInMem:  1,
		DatasetsOnDisk: 2,
		CachesInMem:    2,
		CachesOnDisk:   3,
	}

	db, err := NewDB(c.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open new db: %v", err)
	}

	c.log = log
	c.engine = client
	c.db = db
	c.ctx = ctx
	c.close = make(chan struct{})

	go c.RunNode()

	return nil
}

func (c *ConsensusCmd) SlotTimestamp(slot uint64) uint64 {
	return c.BeaconGenesisTime + uint64((time.Duration(slot) * c.SlotTime).Seconds())
}

func (c *ConsensusCmd) ValidateTimestamp(timestamp uint64, slot uint64) error {
	expectedTimestamp := c.BeaconGenesisTime + uint64((time.Duration(slot) * c.SlotTime).Seconds())
	if timestamp != expectedTimestamp {
		return fmt.Errorf("wrong timestamp: got %d, expected %d", timestamp, expectedTimestamp)
	}
	return nil
}

func (c *ConsensusCmd) proofOfWorkPrelogue(log logrus.Ext1FieldLogger) (transitionBlock uint64, err error) {
	// Create a temporary chain around the db, with ethash consensus, to run through the POW part.
	engine := ethash.New(c.ethashCfg, nil, false)

	mc, err := NewMockChain(log, engine, c.GenesisPath, c.db, &c.TraceLogConfig)
	if err != nil {
		return 0, fmt.Errorf("unable to initialize mock chain: %v", err)
	}

	// Dial the peer to feed the POW blocks to
	n, err := enode.Parse(enode.ValidSchemes, c.Enode)
	if err != nil {
		return 0, fmt.Errorf("malformatted enode address (%q): %v", c.Enode, err)
	}
	peer, err := p2p.Dial(n)
	if err != nil {
		return 0, fmt.Errorf("unable to connect to client: %v", err)
	}
	if err := peer.Peer(mc.chain, nil); err != nil {
		return 0, fmt.Errorf("unable to peer with client: %v", err)
	}
	ctx, cancelPeer := context.WithCancel(c.ctx)
	defer cancelPeer()

	// keep peer connection alive until after the transition
	go peer.KeepAlive(ctx, log)

	defer mc.Close()
	defer engine.Close()

	// Send pre-transition blocks
	for {
		parent := mc.CurrentHeader()

		if c.RNG.Float64() < c.Freq.ReorgFreq {
			parent = c.calcReorgTarget(mc.chain, parent.Number.Uint64(), 0)
		}

		// build a block, without using the engine, and insert it into the engine
		block, err := mc.MineBlock(parent)
		if err != nil {
			return 0, fmt.Errorf("failed to mine block: %v", err)
		}

		// announce block
		newBlock := eth.NewBlockPacket{Block: block, TD: mc.CurrentTd()}
		if err := peer.Write66(&newBlock, 23); err != nil {
			return 0, fmt.Errorf("failed to msg peer: %v", err)
		}

		// check if terminal total difficulty is reached
		ttd := new(big.Int).SetUint64(c.Ttd)
		td := mc.CurrentTd()
		log.WithField("td", td).WithField("ttd", ttd).Debug("Comparing TD to terminal TD")
		if td.Cmp(ttd) >= 0 {
			log.Info("Terminal total difficulty reached, transitioning to POS")
			return mc.CurrentHeader().Number.Uint64(), nil
		}
	}
}

func (c *ConsensusCmd) RunNode() {
	var (
		genesisTime     = time.Unix(int64(c.BeaconGenesisTime), 0)
		slots           = time.NewTicker(c.SlotTime)
		transitionBlock = uint64(0)
		finalizedHash   = common.Hash{}
		nextFinalized   = common.Hash{}
		posEngine       = &ExecutionConsensusMock{
			pow: ethash.New(c.ethashCfg, nil, false),
			log: c.log,
		}
		payloadId = make(chan PayloadID)
	)
	defer slots.Stop()

	// Run PoW prelouge if peered with client
	if c.Enode != "" {
		var err error
		nr, err := c.proofOfWorkPrelogue(c.log.WithField("transitioned", false))
		if err != nil {
			c.log.WithField("err", err).Error("Failed to complete POW-prologue")
			os.Exit(1)
		}
		transitionBlock = nr
	} else {
		c.log.Info("No peer, skipping pre-merge transition simulation, starting in POS mode")
	}

	// Initialize mock chain with existing db
	mc, err := NewMockChain(c.log, posEngine, c.GenesisPath, c.db, &c.TraceLogConfig)
	if err != nil {
		c.log.WithField("err", err).Error("Unable to initialize mock chain")
		os.Exit(1)
	}
	c.mockChain = mc

	for {
		select {
		case tick := <-slots.C:
			signedSlot := int64(math.Round(float64(tick.Sub(genesisTime)) / float64(c.SlotTime)))
			if signedSlot < 0 {
				// before genesis...
				if signedSlot >= -10.0 {
					c.log.WithField("remaining_slots", -signedSlot).Info("Counting down to genesis...")
				}
				continue
			}
			if signedSlot == 0 {
				c.log.WithField("slot", 0).Info("Genesis!")
				continue
			}
			slot := uint64(signedSlot)
			if slot%c.SlotsPerEpoch == 0 {
				last := finalizedHash
				finalizedHash = nextFinalized
				nextFinalized = c.mockChain.CurrentHeader().Hash()
				c.log.WithField("slot", slot).WithField("last", last).WithField("new", finalizedHash).WithField("next", nextFinalized).Info("Finalized block updated")
			}

			// Gap slot
			if c.RNG.Float64() < c.Freq.GapSlot {
				c.log.WithField("slot", slot).Info("Mocking gap slot, no payload execution here")
				// empty pending proposal
				select {
				case <-payloadId:
				default:
				}
				continue
			}

			// Fake some forking by building on an ancestor
			parent := c.mockChain.CurrentHeader()
			if c.RNG.Float64() < c.Freq.ReorgFreq {
				min := transitionBlock
				if final := c.mockChain.chain.GetHeaderByHash(finalizedHash); final != nil {
					num := final.Number.Uint64()
					if min < num {
						min = num
					}
				}
				parent = c.calcReorgTarget(c.mockChain.chain, parent.Number.Uint64(), min)
			}

			slotLog := c.log.WithField("slot", slot)
			slotLog.WithField("previous", parent.Hash()).Info("Slot trigger")

			// If we're proposing, get a block from the engine!
			select {
			case id := <-payloadId:
				slotLog.Info("Update forkchoice to block built by engine")
				go c.mockProposal(slotLog, id, slot, false)
				continue
			default:
				// Not proposing a block
			}

			// Build a block, without using the engine, and insert it into the engine
			slotLog.Debug("Mocking external block")

			// TODO: different proposers, gas limit (target in london) changes, etc.
			coinbase := common.Address{1}
			timestamp := c.SlotTimestamp(slot)
			gasLimit := parent.GasLimit
			extraData := []byte("proto says hi")
			uncleBlocks := []*types.Header{}
			creator := TransactionsCreator(dummyTxCreator)

			block, err := c.mockChain.AddNewBlock(parent.Hash(), coinbase, timestamp, gasLimit, creator, [32]byte{}, extraData, uncleBlocks, true)
			if err != nil {
				slotLog.WithError(err).Errorf("Failed to add block")
				continue
			}

			slotLog.WithField("blockhash", block.Hash()).Debug("Built external block")

			go func(log logrus.Ext1FieldLogger, block *types.Block, final Bytes32) {
				c.mockExecution(log, block)
				latest := Bytes32(block.Hash())
				// Note: head and safe hash are set to the same hash,
				// until forkchoice updates are more attestation-weight aware.
				var payload *PayloadAttributesV1
				if c.RNG.Float64() < c.Freq.ProposalFreq {
					// proposing next slot!
					payload = c.makePayloadAttributes(slot + 1)
				}
				result, _ := ForkchoiceUpdatedV1(c.ctx, c.engine, c.log, latest, final, final, payload)
				if result.PayloadID != nil {
					payloadId <- *result.PayloadID
				}
			}(slotLog, block, Bytes32(finalizedHash))

		case <-c.close:
			c.log.Info("Closing consensus mock node")
			c.engine.Close()

			if err := c.mockChain.Close(); err != nil {
				c.log.WithError(err).Error("Failed closing mock chain")
			}

			if err := c.db.Close(); err != nil {
				c.log.WithError(err).Error("Failed closing database")
			}
		}
	}
}

func (c *ConsensusCmd) mockProposal(log logrus.Ext1FieldLogger, payloadId PayloadID, slot uint64, consensusFail bool) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*20)
	defer cancel()
	payload, err := GetPayloadV1(c.ctx, c.engine, log, payloadId)
	if err != nil {
		log.WithError(err).Error("Failed to get payload")
		return
	}
	if err := c.ValidateTimestamp(uint64(payload.Timestamp), slot); err != nil {
		log.WithError(err).Error("Payload has bad timestamp")
		return
	}
	if consensusFail {
		log.Debug("Mocking a failed proposal on consensus-side, ignoring produced payload of engine")
		return
	}

	block, err := c.mockChain.ProcessPayload(payload)
	if err != nil {
		log.WithError(err).Error("Failed to process execution payload from engine")
		return
	} else {
		log.WithField("blockhash", block.Hash()).Debug("Processed payload in consensus mock world")
	}

	// Send it back to execution layer for execution
	res, err := NewPayloadV1(ctx, c.engine, log, payload)
	if err != nil {
		log.WithError(err).Error("Failed to execute payload")
	} else if res.Status == ExecutionValid {
		log.WithField("blockhash", block.Hash()).Debug("Processed payload in engine")
	} else if res.Status == ExecutionInvalid {
		log.WithField("blockhash", block.Hash()).Error("Engine just produced payload and failed to execute it after!")
	} else {
		log.WithField("status", res.Status).Error("Unrecognized execution status")
	}
}

func (c *ConsensusCmd) mockExecution(log logrus.Ext1FieldLogger, block *types.Block) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*20)
	defer cancel()

	// derive the random 32 bytes from the block hash for mocking ease
	payload, err := BlockToPayload(block)

	if err != nil {
		log.WithError(err).Error("Failed to convert execution block to execution payload")
		return
	}

	NewPayloadV1(ctx, c.engine, log, payload)
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

func (c *ConsensusCmd) calcReorgTarget(chain *core.BlockChain, parent uint64, min uint64) *types.Header {
	depth := c.RNG.Float64() * float64(c.ReorgMaxDepth)
	target := uint64(math.Max(float64(parent)-depth, float64(min)))
	return chain.GetHeaderByNumber(target)
}

func (c *ConsensusCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}

func (c *ConsensusCmd) makePayloadAttributes(slot uint64) *PayloadAttributesV1 {
	var random Bytes32
	c.RNG.Read(random[:])
	return &PayloadAttributesV1{
		Timestamp:             Uint64Quantity(c.SlotTimestamp(slot)),
		Random:                random,
		SuggestedFeeRecipient: common.Address{0x13, 0x37},
	}
}
