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

type start struct {
	cmd *ask.CommandDescription
	err error
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())

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

	starter := make(chan start, 0)

	// run command in the background, so we can stop it at any time
	go func() {
		cmd, err := descr.Execute(ctx, &ask.ExecutionOptions{OnDeprecated: onDeprecated}, os.Args[1:]...)
		starter <- start{cmd, err}
	}()

	for {
		select {
		case start := <-starter:
			if cmd, err := start.cmd, start.err; err == nil {
				// if the command is long-running and closeable later on, then have the interrupt close it.
				if cl, ok := cmd.Command.(io.Closer); ok {
					select {
					case <-interrupt:
						err := cl.Close()
						cancel()
						if err != nil {
							_, _ = fmt.Fprintf(os.Stderr, "failed to close node gracefully. Exiting in 5 seconds. %v", err.Error())
							<-time.After(time.Second * 5)
							os.Exit(1)
						}
						os.Exit(0)
					}
				} else {
					os.Exit(0)
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
		case <-interrupt: // if interrupted during start, then we try to cancel
			cancel()
			// TODO: multiple interrupts to force quick exit?
		}
	}

}
