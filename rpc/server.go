package rpc

import (
	"context"
	"fmt"
	glog "log"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/node"
	gethRpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
)

type Server = gethRpc.Server
type API = gethRpc.API

type Error struct {
	Err error
	Id  int
}

func (e *Error) ErrorCode() int { return e.Id }
func (e *Error) Error() string  { return e.Err.Error() }

type Timeout struct {
	Read       time.Duration `ask:"--read" help:"Timeout for body reads. None if 0."`
	ReadHeader time.Duration `ask:"--read-header" help:"Timeout for header reads. None if 0."`
	Write      time.Duration `ask:"--write" help:"Timeout for writes. None if 0."`
	Idle       time.Duration `ask:"--idle" help:"Timeout to disconnect idle client connections. None if 0."`
}

func NewServer(namespace string, backend interface{}, authenticated bool) (*Server, error) {
	srv := gethRpc.NewServer()
	srv.RegisterName(namespace, backend)
	apis := []API{
		{
			Namespace:     namespace,
			Version:       "1.0",
			Service:       backend,
			Public:        true,
			Authenticated: authenticated,
		},
	}
	if err := node.RegisterApis(apis, []string{namespace}, srv, false); err != nil {
		return nil, fmt.Errorf("could not register api: %s", err)
	}
	return srv, nil
}

func NewHTTPServer(ctx context.Context, log logrus.Ext1FieldLogger, rpcSrv *Server, addr string, timeout Timeout, cors []string) *http.Server {
	httpRpcHandler := node.NewHTTPHandlerStack(rpcSrv, cors, nil, nil)
	mux := http.NewServeMux()
	mux.Handle("/", httpRpcHandler)
	logHttp := log.WithField("type", "http")
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       timeout.Read,
		ReadHeaderTimeout: timeout.ReadHeader,
		WriteTimeout:      timeout.Write,
		IdleTimeout:       timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logHttp.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed connection state")
		},
		ErrorLog: glog.New(logHttp.Writer(), "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}
}

func NewWSServer(ctx context.Context, log logrus.Ext1FieldLogger, rpcSrv *Server, addr string, jwt []byte, timeout Timeout, cors []string) *http.Server {
	wsHandler := node.NewWSHandlerStack(rpcSrv.WebsocketHandler(cors), jwt)
	wsMux := http.NewServeMux()
	wsMux.Handle("/", wsHandler)
	wsMux.Handle("/ws", wsHandler)
	logWs := log.WithField("type", "ws")
	return &http.Server{
		Addr:              addr,
		Handler:           wsMux,
		ReadTimeout:       timeout.Read,
		ReadHeaderTimeout: timeout.ReadHeader,
		WriteTimeout:      timeout.Write,
		IdleTimeout:       timeout.Idle,
		ConnState: func(conn net.Conn, state http.ConnState) {
			e := logWs.WithField("addr", conn.RemoteAddr().String())
			e.WithField("state", state.String())
			e.Debug("client changed connection state")
		},
		ErrorLog: glog.New(logWs.Writer(), "", 0),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}
}
