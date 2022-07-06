GIT_VER := $(shell git describe --tags --always --dirty="-dev")

.PHONY: all
all: clean build

.PHONY: v
v:
	@echo "Version: ${GIT_VER}"

.PHONY: build
build:
	go build . mergemock

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	gofmt -d ./
	go vet ./...
	staticcheck ./...

.PHONY: generate-ssz
generate-ssz:
	rm -f types/builder_encoding.go types/signing_encoding.go
	sszgen --path types --include ../go-ethereum/common/hexutil --objs Eth1Data,BeaconBlockHeader,SignedBeaconBlockHeader,ProposerSlashing,Checkpoint,AttestationData,IndexedAttestation,AttesterSlashing,Attestation,Deposit,VoluntaryExit,SyncAggregate,ExecutionPayloadHeader,VersionedExecutionPayloadHeader,BlindedBeaconBlockBody,BlindedBeaconBlock,RegisterValidatorRequestMessage,BuilderBid,SignedBuilderBid,SigningData,forkData,transactions

.PHONY: generate
generate: generate-ssz
	go generate ./...

.PHONY: clean
clean:
	rm -rf mergemock
