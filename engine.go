package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	gethnode "github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type EngineCmd struct {
	// TODO options

	// embed logger options
	LogCmd `ask:".log" help:"Change logger configuration"`

	ListenAddr    string `ask:"--listen-addr" help:"Address to bind RPC HTTP server to"`
	WebsocketAddr string `ask:"--ws-addr" help:"Address to serve /ws endpoint on for websocket JSON-RPC"`

	Cors []string `ask:"--cors" help:"List of allowable origins (CORS http header)"`

	Timeout struct {
		Read       time.Duration `ask:"--read" help:"Timeout for body reads. None if 0."`
		ReadHeader time.Duration `ask:"--read-header" help:"Timeout for header reads. None if 0."`
		Write      time.Duration `ask:"--write" help:"Timeout for writes. None if 0."`
		Idle       time.Duration `ask:"--idle" help:"Timeout to disconnect idle client connections. None if 0."`
	} `ask:".timeout" help:"Configure timeouts of the HTTP servers"`

	close  chan struct{}
	log    logrus.Ext1FieldLogger
	ctx    context.Context
	rpcSrv *rpc.Server
	srv    *http.Server
	// upgrades to websocket rpc
	wsSrv *http.Server
}

func (c *EngineCmd) Default() {
	c.ListenAddr = "127.0.0.1:8550"
	c.WebsocketAddr = "127.0.0.1:8551"

	c.Cors = []string{"*"}

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

	backend := &EngineBackend{log: logr}

	c.rpcSrv = rpc.NewServer()
	c.rpcSrv.RegisterName("engine", backend)
	wrappedRpc := gethnode.NewHTTPHandlerStack(c.rpcSrv, c.Cors, nil)

	mux := http.NewServeMux()
	mux.Handle("/", wrappedRpc)
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte("wrong port, use the websocket port"))
		logr.WithField("addr", r.RemoteAddr).Warn("user tried to connect to websocket on HTTP port")
	})

	// log http errors to our logrus logger
	logHttp := logr.WithField("type", "http")

	c.srv = &http.Server{
		Addr:              c.ListenAddr,
		Handler:           mux,
		ReadTimeout:       c.Timeout.Read,
		ReadHeaderTimeout: c.Timeout.ReadHeader,
		WriteTimeout:      c.Timeout.Write,
		IdleTimeout:       c.Timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logHttp.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed connection state")
		},
		ErrorLog: log.New(logHttp.Writer(), "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	wsHandler := c.rpcSrv.WebsocketHandler(c.Cors)

	wsMux := http.NewServeMux()
	wsMux.Handle("/", wsHandler)
	wsMux.Handle("/ws", wsHandler)

	logWs := logr.WithField("type", "ws")

	c.wsSrv = &http.Server{
		Addr:              c.WebsocketAddr,
		Handler:           wsHandler,
		ReadTimeout:       c.Timeout.Read,
		ReadHeaderTimeout: c.Timeout.ReadHeader,
		WriteTimeout:      c.Timeout.Write,
		IdleTimeout:       c.Timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logWs.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed connection state")
		},
		ErrorLog: log.New(logWs.Writer(), "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	go c.RunNode()

	return nil
}

func (c *EngineCmd) RunNode() {
	c.log.Info("started")

	go c.srv.ListenAndServe()
	go c.wsSrv.ListenAndServe()

	for {
		select {
		case <-c.close:
			c.rpcSrv.Stop()
			c.srv.Close()
			c.wsSrv.Close()
			return
			// TODO: any other tasks to run in this loop? mock sync changes?
		}
	}
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

func (e *EngineBackend) PreparePayload(ctx context.Context, params *PreparePayloadParams) (PayloadID, error) {

	return 0, nil
}

func (e *EngineBackend) GetPayload(ctx context.Context, id PayloadID) (*ExecutionPayload, error) {
	return nil, nil
}

func (e *EngineBackend) ExecutePayload(ctx context.Context, payload *ExecutionPayload) (*ExecutePayloadResult, error) {
	return nil, nil
}

func (e *EngineBackend) ConsensusValidated(ctx context.Context, params *ConsensusValidatedParams) error {
	return nil
}

func (e *EngineBackend) ForkchoiceUpdated(ctx context.Context, params *ForkchoiceUpdatedParams) error {
	return nil
}

// TODO: more engine methods
