# MergeMock

Experimental debug tooling, mocking the execution engine and consensus node for
testing.

**work in progress**

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
* Question: what happens if this is called to finalize a block that is already
  the ancestor of a finalized block?

#### Ideas for CLI args to improve mocking
* A CLI flag to simulate "syncing", so all RPC methods return values as if the
  client were currently syncing.
* A CLI arg of "known" header hashes (or just headers?) to text error code `4:
  Unknown header`. 
* A CLI arg of "valid" / "invalid" header hashes.
* A CLI arg of percentile values to determine the probability of certain errors happening.

## License

MIT, see [`LICENSE`](./LICENSE) file.


[engine_preparePayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_preparepayload
[engine_getPayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_getpayload
[engine_executePayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_executepayload
[engine_consenusValidated]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_consensusvalidated
[engine_forkchoiceUpdated]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#engine_forkchoiceupdated
[ExecutionPayload]: https://github.com/ethereum/execution-apis/blob/main/src/engine/interop/specification.md#ExecutionPayload
