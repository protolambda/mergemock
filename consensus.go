package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
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
	PastGenesis   time.Duration `ask:"--past-genesis" help:"Time past genesis (can be negative for pre-genesis)"`
	SlotTime      time.Duration `ask:"--slot-time" help:"Time per slot"`
	SlotsPerEpoch uint64        `ask:"--slots-per-epoch" help:"Slots per epoch"`
	// TODO ideas:
	// - % random gap slots (= missing beacon blocks)
	// - % random finality

	EngineAddr  string `ask:"--engine" help:"Address of Engine JSON-RPC endpoint to use"`
	DataDir     string `ask:"--datadir" help:"Directory to store chain data (empty for in-memory data)"`
	GenesisPath string `ask:"--genesis" help:"Genesis config file"`

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	engine *rpc.Client

	gspec      *core.Genesis
	database   ethdb.Database
	blockchain *core.BlockChain
}

func (c *ConsensusCmd) Default() {
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

	c.database = db
	c.initGensis()
	blockchain, _ := core.NewBlockChain(c.database, nil, c.gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
	c.blockchain = blockchain

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
	//slots.Reset(c.PastGenesis % c.SlotTime) // TODO
	defer slots.Stop()

	var (
		key, _ = crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		signer = types.NewLondonSigner(common.Big1)
		faker  = ethash.NewFaker()
	)

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
			state, _ := c.blockchain.State()

			blocks, _ := core.GenerateChain(c.gspec.Config, c.blockchain.CurrentBlock(), faker, c.database, 1, func(i int, b *core.BlockGen) {
				b.SetCoinbase(common.Address{1})

				txdata := &types.DynamicFeeTx{
					ChainID:   c.gspec.Config.ChainID,
					Nonce:     state.GetNonce(addr),
					To:        &addr,
					Gas:       30000,
					GasFeeCap: new(big.Int).Mul(big.NewInt(5), big.NewInt(params.GWei)),
					GasTipCap: big.NewInt(2),
					Data:      []byte{},
				}
				tx := types.NewTx(txdata)
				tx, _ = types.SignTx(tx, signer, key)

				b.AddTx(tx)
			})

			if _, err := c.blockchain.InsertChain(blocks); err != nil {
				panic(err)
			}

			/*
				basefee := &uint256.NewInt(7)
				payload := ExecutionPayload{
					ParentHash:    Bytes32{},
					Coinbase:      Bytes20{},
					StateRoot:     Bytes32{},
					ReceiptRoot:   Bytes32{},
					LogsBloom:     Bytes256{},
					Random:        Bytes32{},
					BlockNumber:   Uint64Quantity(0),
					GasLimit:      Uint64Quantity(30000000),
					GasUsed:       Uint64Quantity(21000),
					Timestamp:     Uint64Quantity(0),
					ExtraData:     BytesMax32{},
					BaseFeePerGas: Uint256Quantity(basefee),
					BlockHash:     Bytes32{},
					Transactions:  hexutil.Bytes([]byte{}),
				}

				id, err := PreparePayload(c.ctx, c.engine, c.log.WithField("slot", slot), &PreparePayloadParams{TODO})
			*/

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

func (c *ConsensusCmd) initGensis() (*types.Block, error) {
	file, err := os.Open(c.GenesisPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	gspec := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(gspec); err != nil {
		return nil, fmt.Errorf("Invalid genesis file: %v", err)
	}

	c.gspec = gspec

	return gspec.Commit(c.database)
}
