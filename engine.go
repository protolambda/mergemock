package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type EngineCmd struct {
	// TODO options

	// embed logger options
	LogCmd `ask:".log"`

	ListenAddr string `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`

	Timeout struct {
		Read       time.Duration `ask:"--read"`
		ReadHeader time.Duration `ask:"--read-header"`
		Write      time.Duration `ask:"--write"`
		Idle       time.Duration `ask:"--idle"`
	} `ask:".timeout"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	rpcSrv *rpc.Server
	srv    *http.Server
}

func (c *EngineCmd) Default() {
	c.Timeout.Read = 30 * time.Second
	c.Timeout.ReadHeader = 10 * time.Second
	c.Timeout.Write = 30 * time.Second
	c.Timeout.Idle = 5 * time.Minute
}

func (c *EngineCmd) Help() string {
	return "Run a mock Execution Engine."
}

func (c *EngineCmd) Run(ctx context.Context, args ...string) error {
	logr, err := c.LogCmd.Create()
	if err != nil {
		return err
	}
	c.log = logr
	c.ctx = ctx

	c.close = make(chan struct{})

	c.rpcSrv = rpc.NewServer()
	c.rpcSrv.RegisterName("engine", &EngineBackend{log: logr})

	mux := http.NewServeMux()
	mux.Handle("/", c.rpcSrv)

	// log http errors to our logrus logger
	logw := logr.Writer()

	c.srv = &http.Server{
		Addr:              c.ListenAddr,
		Handler:           mux,
		ReadTimeout:       c.Timeout.Read,
		ReadHeaderTimeout: c.Timeout.ReadHeader,
		WriteTimeout:      c.Timeout.Write,
		IdleTimeout:       c.Timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logr.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed state")
		},
		ErrorLog: log.New(logw, "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	go c.RunNode()

	return nil
}

func (c *EngineCmd) RunNode() {
	c.log.Info("started")
	c.srv.ListenAndServe()
}

func (c *EngineCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}

type EngineBackend struct {
	log logrus.Ext1FieldLogger
}

func (e *EngineBackend) GetPayload(idx hexutil.Uint64) hexutil.Uint64 {
	return idx
}

// TODO: more engine methods
