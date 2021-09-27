package main

import (
	"context"

	"github.com/sirupsen/logrus"
)

type EngineCmd struct {
	// TODO options

	// embed logger options
	LogCmd `ask:".log"`

	close chan struct{}
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

	// TODO: http server

	go c.RunNode(log)

	return nil
}

func (c *EngineCmd) RunNode(log *logrus.Logger) {

	log.Info("started")

}

func (c *EngineCmd) Close() error {
	if c.close != nil {
		c.close <- struct{}{}
	}
	return nil
}
