# MergeMock

Experimental debug tooling, mocking the execution engine and consensus node for testing.


## Quick Start

To get started, build `mergemock` and download the `genesis.json`.

```bash
$ wget https://gist.githubusercontent.com/lightclient/799c727e826483a2804fc5013d0d3e3d/raw/2e8824fa8d9d9b040f351b86b75c66868fb9b115/genesis.json
$ openssl rand -hex 32 | tr -d "\n" > jwt.hex

# Build
$ go build . mergemock

# Run mergemock with engine and consensus
$ ./mergemock engine
$ ./mergemock consensus --slot-time=4s

# Run mergemock relay (which also starts the engine)
$ ./mergemock relay
```

## Usage

### `engine`

```console
$ mergemock engine --help

Run a mock Execution Engine.

  --slots-per-epoch           Slots per epoch (default: 0) (type: uint64)
  --datadir                   Directory to store execution chain data (empty for in-memory data) (type: string)
  --genesis                   Genesis execution-config file (default: genesis.json) (type: string)
  --listen-addr               Address to bind RPC HTTP server to (default: 127.0.0.1:8550) (type: string)
  --ws-addr                   Address to serve /ws endpoint on for websocket JSON-RPC (default: 127.0.0.1:8551) (type: string)
  --cors                      List of allowable origins (CORS http header) (default: *) (type: stringSlice)

# log
Change logger configuration

  --log.level                 Log level: trace, debug, info, warn/warning, error, fatal, panic. Capitals are accepted too. (default: info) (type: string)
  --log.color                 Color the log output. Defaults to true if terminal is detected. (default: true) (type: bool)
  --log.format                Format the log output. Supported formats: 'text', 'json' (default: text) (type: string)
  --log.timestamps            Timestamp format in logging. Empty disables timestamps. (default: 2006-01-02T15:04:05Z07:00) (type: string)

# trace
Tracing options

  --trace.enable              enable tracing (default: false) (type: bool)
  --trace.enable-memory       enable memory capture (default: false) (type: bool)
  --trace.disable-stack       disable stack capture (default: false) (type: bool)
  --trace.disable-storage     disable storage capture (default: false) (type: bool)
  --trace.enable-return-data  enable return data capture (default: false) (type: bool)
  --trace.debug               print output during capture end (default: false) (type: bool)
  --trace.limit               maximum length of output, but zero means unlimited (default: 0) (type: int)

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

  --beacon-genesis-time       Beacon genesis time (default: 1636595652) (type: uint64)
  --slot-time                 Time per slot (default: 12s) (type: duration)
  --slots-per-epoch           Slots per epoch (default: 32) (type: uint64)
  --engine                    Address of Engine JSON-RPC endpoint to use (default: http://127.0.0.1:8550) (type: string)
  --datadir                   Directory to store execution chain data (empty for in-memory data) (type: string)
  --ethashdir                 Directory to store ethash data (type: string)
  --genesis                   Genesis execution-config file (default: genesis.json) (type: string)
  --node                      Enode of execution client, required to insert pre-merge blocks. (type: string)
  --ttd                       The terminal total difficulty for the merge (default: 0) (type: uint64)
  --rng                       seed the RNG with an integer number (default: 1234) (type: RNG)
  --reorg-max-depth           Max depth of a chain reorg (default: 64) (type: uint64)

# freq
Modify frequencies of certain behavior

  --freq.gap                  How often an execution block is missing (default: 0.05) (type: float64)
  --freq.proposal             How often the engine gets to propose a block (default: 0.5) (type: float64)
  --freq.ignore               How often the payload produced by the engine does not become canonical (default: 0.1) (type: float64)
  --freq.finality             How often an epoch succeeds to finalize (default: 0.1) (type: float64)
  --freq.reorg                Frequency of chain reorgs (default: 0.05) (type: float64)

# log
Change logger configuration

  --log.level                 Log level: trace, debug, info, warn/warning, error, fatal, panic. Capitals are accepted too. (default: info) (type: string)
  --log.color                 Color the log output. Defaults to true if terminal is detected. (default: true) (type: bool)
  --log.format                Format the log output. Supported formats: 'text', 'json' (default: text) (type: string)
  --log.timestamps            Timestamp format in logging. Empty disables timestamps. (default: 2006-01-02T15:04:05Z07:00) (type: string)

# trace
Tracing options

  --trace.enable              enable tracing (default: false) (type: bool)
  --trace.enable-memory       enable memory capture (default: false) (type: bool)
  --trace.disable-stack       disable stack capture (default: false) (type: bool)
  --trace.disable-storage     disable storage capture (default: false) (type: bool)
  --trace.enable-return-data  enable return data capture (default: false) (type: bool)
  --trace.debug               print output during capture end (default: false) (type: bool)
  --trace.limit               maximum length of output, but zero means unlimited (default: 0) (type: int)
```

## Development

For development, install the following tools:

```bash
go install honnef.co/go/tools/cmd/staticcheck@v0.3.1
go install github.com/ferranbt/fastssz/sszgen@latest
```

## License

MIT, see [`LICENSE`](./LICENSE) file.
