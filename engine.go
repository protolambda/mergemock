package main

import (
	"context"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type EngineCmd struct {
	// TODO options

	// embed logger options
	LogCmd `ask:".log"`

	close chan struct{}
	http  *httpServer
}

func (c *EngineCmd) Default() {
	// TODO
}

func (c *EngineCmd) Help() string {
	return "Run a mock Execution Engine."
}

func (c *EngineCmd) Run(ctx context.Context, args ...string) error {
	log, err := c.LogCmd.Create()
	if err != nil {
		return err
	}

	c.close = make(chan struct{})

	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("engine", &EngineBackend{})
	http.Handle("/", &httpServer{rpc: rpcServer})

	go c.RunNode(log)

	return nil
}

func (c *EngineCmd) RunNode(log *logrus.Logger) {
	log.Info("started")
	http.ListenAndServe(":8090", nil)
}

func (c *EngineCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}

type httpServer struct {
	rpc *rpc.Server
}

func (h *httpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.rpc.ServeHTTP(w, r)
}

type EngineBackend struct{}

func (e *EngineBackend) GetPayload(idx hexutil.Uint64) hexutil.Uint64 {
	return idx
}
