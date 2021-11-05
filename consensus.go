package main

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"mergemock/p2p"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
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
	Enode       string `ask:"--node" help:"Enode of execution client"`
	Ttd         uint64 `ask:"--ttd" help:"The terminal total difficulty for the merge"`

	// embed consensus behaviors
	ConsensusBehavior `ask:"."`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	TraceLogConfig `ask:".trace" help:"Tracing options"`

	close        chan struct{}
	log          logrus.Ext1FieldLogger
	ctx          context.Context
	engine       *rpc.Client
	peer         *p2p.Conn
	ethashConfig ethash.Config

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

	// Connect to execution client engine api
	client, err := rpc.DialContext(ctx, c.EngineAddr)
	if err != nil {
		return err
	}

	c.ethashConfig = ethash.Config{
		PowMode:        ethash.ModeNormal,
		DatasetDir:     c.EthashDir,
		CacheDir:       c.EthashDir,
		DatasetsInMem:  1,
		DatasetsOnDisk: 2,
		CachesInMem:    2,
		CachesOnDisk:   3,
	}
	engine := ethash.New(c.ethashConfig, nil, false)
	mc, err := NewMockChain(log, engine, c.GenesisPath, c.DataDir, &c.TraceLogConfig)
	if err != nil {
		log.WithField("err", err).Error("Unable to initialize mock chain")
		os.Exit(1)
	}

	peer, err := p2p.Dial(enode.MustParse(c.Enode))
	if err != nil {
		log.WithField("err", err).Error("Unable to connect to client")
		os.Exit(1)
	}
	if err := peer.Peer(mc.chain, nil); err != nil {
		log.WithField("err", err).Error("Unable to peer with client")
		os.Exit(1)
	}
	go peer.KeepAlive(log)

	c.mockChain = mc
	c.log = log
	c.engine = client
	c.peer = peer
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

func (c *ConsensusCmd) RunNode() {
	// TODO: simulate data since genesis

	var (
		genesisTime     = time.Unix(int64(c.BeaconGenesisTime), 0)
		slots           = time.NewTicker(c.SlotTime)
		transitionBlock = &types.Header{}
	)

	// align ticker with genesis
	//slots.Reset(c.PastGenesis % c.SlotTime) // TODO
	defer slots.Stop()

	// Send pre-transition blocks
	for {
		parent := c.mockChain.CurrentHeader()

		if c.RNG.Float64() < c.Freq.ReorgFreq {
			parent = c.calcReorgTarget(parent.Number.Uint64(), 0)
		}

		// build a block, without using the engine, and insert it into the engine
		block, err := c.mockChain.MineBlock(parent)
		if err != nil {
			c.log.WithField("err", err).Error("Failed to mine block")
			c.mockChain.Close()
			os.Exit(1)
		}

		// announce block
		newBlock := eth.NewBlockPacket{Block: block, TD: c.mockChain.CurrentTd()}
		if err := c.peer.Write66(&newBlock, 23); err != nil {
			c.log.WithField("err", err).Error("Failed to msg peer")
			os.Exit(1)
		}

		// check if terminal total difficulty is reached
		ttd := new(big.Int).SetUint64(c.Ttd)
		td := c.mockChain.CurrentTd()
		c.log.WithField("td", td).WithField("ttd", ttd).Debug("Comparing TD to terminal TD")
		if td.Cmp(ttd) >= 0 {
			c.log.Info("Terminal total difficulty reached, transitioning to POS")
			transitionBlock = c.mockChain.CurrentHeader()
			break
		}
	}

	c.engine.Close()
	c.mockChain.Close()

	engine := &ExecutionConsensusMock{
		pow: ethash.New(c.ethashConfig, nil, false),
		log: c.log,
	}
	mc, err := NewMockChain(c.log, engine, c.GenesisPath, c.DataDir, &c.TraceLogConfig)
	if err != nil {
		c.log.WithField("err", err).Error("Unable to initialize mock chain")
		os.Exit(1)
	}
	c.mockChain = mc

	for {
		select {
		case tick := <-slots.C:
			// 52 bits is plenty
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

			// TODO: fake some forking by not always building on the latest payload
			parent := c.mockChain.CurrentHeader()
			if c.RNG.Float64() < c.Freq.ReorgFreq {
				parent = c.calcReorgTarget(parent.Number.Uint64(), transitionBlock.Number.Uint64())
			}

			slotLog := c.log.WithField("slot", slot)
			slotLog.WithField("previous", parent.Hash()).Info("Slot trigger")

			if c.RNG.Float64() < c.Freq.GapSlot {
				// gap slot
				slotLog.Info("Mocking gap slot, no payload execution here")
			} else {
				var (
					block *types.Block
					err   error
				)
				if c.RNG.Float64() < c.Freq.ProposalFreq {
					// try get a block from the engine, we're a proposer!
					slotLog.Info("Proposing block with engine")

					// in main loop, avoid concurrent randomness for reproducibility
					var random32 Bytes32
					c.RNG.Read(random32[:])

					// when we produce the payload, but fail to get it into the chain
					consensusProposalFail := c.RNG.Float64() < c.Freq.FailedProposalFreq

					coinbase := common.Address{0x13, 0x37}

					go func() {
						c.mockProposal(slotLog, parent.Hash(), slot, coinbase, random32, consensusProposalFail)
					}()
				} else {
					// build a block, without using the engine, and insert it into the engine
					slotLog.Debug("Mocking external block")

					// TODO: different proposers, gas limit (target in london) changes, etc.
					coinbase := common.Address{1}
					timestamp := c.SlotTimestamp(slot)
					gasLimit := c.mockChain.gspec.GasLimit
					extraData := []byte("proto says hi")
					uncleBlocks := []*types.Header{} // none in proof of stake
					creator := TransactionsCreator(dummyTxCreator)

					block, err = c.mockChain.AddNewBlock(parent.Hash(), coinbase, timestamp, gasLimit, creator, extraData, uncleBlocks, true)
					if err != nil {
						slotLog.WithError(err).Errorf("Failed to add block")
						continue
					}

					slotLog.WithField("blockhash", block.Hash()).Debug("Built external block")

					go func() {
						c.mockExecution(slotLog, block)
						latest := Bytes32(block.Hash())
						ForkchoiceUpdated(c.ctx, c.engine, c.log, latest, latest, latest, nil)
					}()
				}
			}

		case <-c.close:
			c.log.Info("Closing consensus mock node")
			c.engine.Close()
			c.mockChain.Close()
		}
	}
}

func (c *ConsensusCmd) mockProposal(log logrus.Ext1FieldLogger, parent common.Hash, slot uint64, coinbase common.Address, random32 Bytes32, consensusFail bool) {
	payload, err := c.mockPrep(log, parent, slot, random32, coinbase)
	if err != nil {
		log.WithError(err).Error("Failed to prepare and get payload, failed proposal")
		return
	}

	if consensusFail {
		log.Debug("Mocking a failed proposal on consensus-side, ignoring produced payload of engine")
		return
	} else {
		if err := c.ValidateTimestamp(uint64(payload.Timestamp), slot); err != nil {
			log.WithError(err).Error("Payload has bad timestamp")
			return
		}
		block, err := c.mockChain.ProcessPayload(payload)
		if err != nil {
			log.WithError(err).Error("Failed to process execution payload from engine")
			return
		} else {
			log.WithField("blockhash", block.Hash()).Debug("Processed payload in consensus mock world")
		}

		// send it back to execution layer for execution
		ctx, cancel := context.WithTimeout(c.ctx, time.Second*20)
		defer cancel()
		res, err := ExecutePayload(ctx, c.engine, log, payload)
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
}

func (c *ConsensusCmd) mockPrep(log logrus.Ext1FieldLogger, parent common.Hash, slot uint64, random Bytes32, feeRecipient common.Address) (*ExecutionPayload, error) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*20)
	defer cancel()

	attributes := PayloadAttributes{
		Timestamp:    Uint64Quantity(c.SlotTimestamp(slot)),
		Random:       random,
		FeeRecipient: feeRecipient,
	}
	latest := Bytes32(parent)
	res, err := ForkchoiceUpdated(c.ctx, c.engine, c.log, latest, latest, latest, &attributes)
	if err != nil {
		log.WithError(err).Error("Failed to prepare and get payload, failed proposal")
		return nil, err
	}
	if res.Status == UpdateSyncing {
		log.Warn("Failed to prepare and get payload, execution client syncing")
		return nil, fmt.Errorf("execution client syncing")
	}

	return GetPayload(ctx, c.engine, log, res.PayloadID)
}

func (c *ConsensusCmd) mockExecution(log logrus.Ext1FieldLogger, block *types.Block) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*20)
	defer cancel()

	// derive the random 32 bytes from the block hash for mocking ease
	payload, err := BlockToPayload(block, mockRandomValue(block.Hash()))

	if err != nil {
		log.WithError(err).Error("Failed to convert execution block to execution payload")
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

func (c *ConsensusCmd) calcReorgTarget(parent uint64, min uint64) *types.Header {
	depth := c.RNG.Float64() * float64(c.ReorgMaxDepth)
	target := uint64(math.Max(float64(parent)-depth, float64(min)))
	return c.mockChain.chain.GetHeaderByNumber(target)
}

func (c *ConsensusCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}
