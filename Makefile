GIT_VER := $(shell git describe --tags --always --dirty="-dev")

all: clean build

v:
	@echo "Version: ${GIT_VER}"

build:
	go build . mergemock

test:
	go test ./...

lint:
	gofmt -d ./
	go vet ./...
	staticcheck ./...

generate-ssz:
	rm -f types/builder_encoding.go types/signing_encoding.go
	sszgen --path types --include ../go-ethereum/common/hexutil --objs Eth1Data,BeaconBlockHeader,SignedBeaconBlockHeader,ProposerSlashing,Checkpoint,AttestationData,IndexedAttestation,AttesterSlashing,Attestation,Deposit,VoluntaryExit,SyncAggregate,ExecutionPayloadHeader,VersionedExecutionPayloadHeader,BlindedBeaconBlockBody,BlindedBeaconBlock,RegisterValidatorRequestMessage,BuilderBid,SignedBuilderBid,SigningData,forkData

generate: generate-ssz
	go generate ./...
