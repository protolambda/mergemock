# MergeMock

Experimental debug tooling, mocking the execution engine and consensus node for
testing.

**work in progress**

## Quick Start

To get started, build `mergemock` and download the `genesis.json`.

```console
$ go build . mergemock
$ wget https://gist.githubusercontent.com/lightclient/799c727e826483a2804fc5013d0d3e3d/raw/2e8824fa8d9d9b040f351b86b75c66868fb9b115/genesis.json
$ ./mergemock engine
$ ./mergemock consensus --slot-time=4s
```

## Usage

### `engine`

```console
$ mergemock engine --help

Run a mock Execution Engine.

  --past-genesis              Time past genesis (can be negative for pre-genesis) (default: 0s) (type: duration)
  --slot-time                 Time per slot (default: 0s) (type: duration)
  --slots-per-epoch           Slots per epoch (default: 0) (type: uint64)
  --datadir                   Directory to store execution chain data (empty for in-memory data) (type: string)
  --genesis                   Genesis execution-config file (type: string)
  --listen-addr               Address to bind RPC HTTP server to (default: 127.0.0.1:8550) (type: string)
  --ws-addr                   Address to serve /ws endpoint on for websocket JSON-RPC (default: 127.0.0.1:8551) (type: string)
  --cors                      List of allowable origins (CORS http header) (default: *) (type: stringSlice)

# log
Change logger configuration

  --log.level                 Log level: trace, debug, info, warn/warning, error, fatal, panic. Capitals are accepted too. (default: info) (type: string)
  --log.color                 Color the log output. Defaults to true if terminal is detected. (default: true) (type: bool)
  --log.format                Format the log output. Supported formats: 'text', 'json' (default: text) (type: string)
  --log.timestamps            Timestamp format in logging. Empty disables timestamps. (default: 2006-01-02T15:04:05Z07:00) (type: string)

# timeout
Configure timeouts of the HTTP servers

  --timeout.read              Timeout for body reads. None if 0. (default: 30s) (type: duration)
  --timeout.read-header       Timeout for header reads. None if 0. (default: 10s) (type: duration)
  --timeout.write             Timeout for writes. None if 0. (default: 30s) (type: duration)
  --timeout.idle              Timeout to disconnect idle client connections. None if 0. (default: 5m0s) (type: duration)
```


### `consensus`

```console
$ mergemock consensus --help

Run a mock Consensus client.

  --past-genesis              Time past genesis (can be negative for pre-genesis) (default: 0s) (type: duration)
  --slot-time                 Time per slot (default: 12s) (type: duration)
  --slots-per-epoch           Slots per epoch (default: 32) (type: uint64)
  --engine                    Address of Engine JSON-RPC endpoint to use (default: http://127.0.0.1:8550) (type: string)
  --datadir                   Directory to store execution chain data (empty for in-memory data) (type: string)
  --genesis                   Genesis execution-config file (default: genesis.json) (type: string)
  --rng                       seed the RNG with an integer number (default: 1234) (type: RNG)

# freq
Modify frequencies of certain behavior

  --freq.gap                  How often an execution block is missing (default: 0.05) (type: float64)
  --freq.proposal             How often the engine gets to propose a block (default: 0.2) (type: float64)
  --freq.ignore               How often the payload produced by the engine does not become canonical (default: 0.1) (type: float64)
  --freq.finality             How often an epoch succeeds to finalize (default: 0.1) (type: float64)

# log
Change logger configuration

  --log.level                 Log level: trace, debug, info, warn/warning, error, fatal, panic. Capitals are accepted too. (default: info) (type: string)
  --log.color                 Color the log output. Defaults to true if terminal is detected. (default: true) (type: bool)
  --log.format                Format the log output. Supported formats: 'text', 'json' (default: text) (type: string)
  --log.timestamps            Timestamp format in logging. Empty disables timestamps. (default: 2006-01-02T15:04:05Z07:00) (type: string)
```

## Behaviour

### Execution Engine Mock

Consensus clients that desire to test their use of the Engine API will benefit
from a "mocked" execution engine. Mocking the Engine API from the execution
side is relatively straightforward since the transition is an opaque process to
the consensus client.

#### [`engine_preparePayload`][engine_preparePayload]

* Creates an [`ExecutionPayload`][ExecutionPayload] object with the request's
  parameters.
  * `receiptRoot` is a random hash.
  * `extraData` is a random value.
  * `gasLimit` is a random value between `29,000,000` and `31,000,000`.
  * `gasUsed` is a random value between `21,000 * len(txs)` and `gasLimit`.
  * `baseFee` is a random value greater than `7`.
  * `transactions` is an array of between 0 and 100 random transactions.
* A unique identifier that internally maps to the payload is returned.

#### [`engine_getPayload`][engine_getPayload]

* Returns the `ExecutionPayload` associated with the `PayloadId`

#### [`engine_executePayload`][engine_executePayload]

* Returns the status of the execution.

#### [`engine_consensusValidated`][engine_consensusValidated]

* Essentially a no-op.

#### [`engine_forkchoiceUpdated`][engine_forkchoiceUpdated]

* Essentially a no-op.
* TODO: what should the mock do if this is called to finalize a 
  block that is already the ancestor of a finalized block?

#### Ideas for CLI args to improve mocking

* A CLI flag to simulate "syncing", so all RPC methods return values as if the
  client were currently syncing.
* A CLI arg of "known" header hashes (or just headers?) to text error code `4:
  Unknown header`. 
* A CLI arg of "valid" / "invalid" header hashes.
* A CLI arg of percentile values to determine the probability of certain errors
  happening.

### Consensus Client Mock

Mocking the consensus client is more involved. As the driver of the execution
engine, it needs to be more intelligent with its requests.

The general idea is to simulate slots and epochs of configurable intervals and
lengths. With a basic slot cycle, the rest of the behaviour can be defined to
occur based on some probability factor.

The most difficult method to model will likely be `engine_executePayload` since
it can't just use random transactions. To actually provide a "real" chain to
the execution engine, it will probably be best if `mergemock` also maintains a
copy of the chain and applies transfer txs to it to get a new transition.

#### Rough Order of Operation

1. Slot begins.
2. Determine if `mergemock` will propose this slot.
3. If yes, call `engine_preparePayload`.
    3a. After a short period of time, call `engine_getPayload`.
4. If no, generate an `ExecutionPayload` and call `engine_executePayload`.
    4a. Call `engine_consensusValidated`.
5. `engine_forkchoiceUpdated` is called.
    * Question: Is this called at this point to update the head to the
    parent block (if proposing) and to the newly executed block if not?

#### Probability Configuration

* `proposal` -- the probability that the consensus client executes the
  `engine_preparePayload`, `engine_getPayload` flow.
* `missed_proposal` -- the probability the consensus client's proposal is not
  built upon. This basically means the `engine_forkchoiceUpdated` is called
  with a new head hash that orphans the proposal.
* `invalid_payload` -- the probability that an
  [`ExecutionPayload`][ExecutionPayload] is valid. The consensus client can
  construct "invalid" payloads in numerous ways; one of the easier ones may be
  to just set the `state_root` to `0x000..000`.

#### Other Configuration

* `slot_time` -- the time between slots.
* `epoch_length` -- number of slots in an epoch.
* `finalization_offset` -- the number of epochs to wait before announcing to
  the execution engine a finalized block.

## License

MIT, see [`LICENSE`](./LICENSE) file.

[engine_preparePayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_preparepayload
[engine_getPayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_getpayload
[engine_executePayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_executepayload
[engine_consensusValidated]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_consensusvalidated
[engine_forkchoiceUpdated]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_forkchoiceupdated
[ExecutionPayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#ExecutionPayload
