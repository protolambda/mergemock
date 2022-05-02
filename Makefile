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
