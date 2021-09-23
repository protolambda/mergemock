package main

import (
	"context"
	"fmt"
	"github.com/protolambda/ask"
	"io"
	"os"
	"os/signal"
	"time"
)

type MergeMockCmd struct {
}

func (c *MergeMockCmd) Help() string {
	return "Run MergeMock. Either mock a consensus node or execution engine."
}

func (c *MergeMockCmd) Cmd(route string) (cmd interface{}, err error) {
	switch route {
	case "consensus":
		cmd = &ConsensusCmd{}
	case "engine":
		cmd = &EngineCmd{}
	default:
		return nil, ask.UnrecognizedErr
	}
	return
}

func (c *MergeMockCmd) Routes() []string {
	return []string{"consensus", "engine"}
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())

	var closer io.Closer

	cmd := &MergeMockCmd{}
	descr, err := ask.Load(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to load main command: %v", err.Error())
		os.Exit(1)
	}
	onDeprecated := func(fl ask.PrefixedFlag) error {
		fmt.Fprintf(os.Stderr, "warning: flag %q is deprecated: %s", fl.Path, fl.Deprecated)
		return nil
	}
	if cmd, err := descr.Execute(ctx, &ask.ExecutionOptions{OnDeprecated: onDeprecated}, os.Args[1:]...); err == nil {
		// if the command is long-running and closeable later on, then remember, and have the interrupt close it.
		if cl, ok := cmd.Command.(io.Closer); ok {
			closer = cl
		}
	} else if err == ask.UnrecognizedErr {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	} else if err == ask.HelpErr {
		_, _ = fmt.Fprintln(os.Stderr, cmd.Usage(false))
		os.Exit(0)
	} else {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// TODO: multiple interrupts to force quick exit?
	select {
	case <-interrupt:
		if closer != nil {
			err := closer.Close()
			cancel()
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to close node gracefully. Exiting in 5 seconds. %v", err.Error())
				<-time.After(time.Second * 5)
				os.Exit(1)
			}
			os.Exit(1)
		} else {
			cancel()
			<-time.After(time.Second * 2)
		}
	}
}
