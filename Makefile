GIT_VER := $(shell git describe --tags --always --dirty="-dev")

all: clean build

v:
	@echo "Version: ${GIT_VER}"

test:
	go test ./...

lint:
	gofmt -d ./
	go vet ./...
	staticcheck ./...

generate-ssz:
	rm -f types/builder_encoding.go
	sszgen --path types --include ../go-ethereum/common/hexutil --objs Eth1Data,BeaconBlockHeader,SignedBeaconBlockHeader,ProposerSlashing,Checkpoint,AttestationData,IndexedAttestation,AttesterSlashing,Attestation,Deposit,VoluntaryExit,SyncAggregate,ExecutionPayloadHeaderV1,BlindedBeaconBlockBodyV1,BlindedBeaconBlockV1,RegisterValidatorRequestMessage,BuilderBidV1,SignedBuilderBidV1

generate: generate-ssz
	go generate ./...
