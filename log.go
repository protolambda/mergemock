package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

type LogCmd struct {
	LogLvl          string `ask:"--level" help:"Log level: trace, debug, info, warn/warning, error, fatal, panic. Capitals are accepted too."`
	Color           bool   `ask:"--color" help:"Color the log output. Defaults to true if terminal is detected."`
	Format          string `ask:"--format" help:"Format the log output. Supported formats: 'text', 'json'"`
	TimestampFormat string `ask:"--timestamps" help:"Timestamp format in logging. Empty disables timestamps."`
}

func (c *LogCmd) Default() {
	c.LogLvl = "info"
	c.Color = term.IsTerminal(int(os.Stdout.Fd()))
	c.Format = "text"
	c.TimestampFormat = time.RFC3339
}

func (c *LogCmd) Create() (*logrus.Logger, error) {
	var format logrus.Formatter
	switch c.Format {
	case "json":
		format = &logrus.JSONFormatter{
			TimestampFormat:   c.TimestampFormat,
			DisableTimestamp:  c.TimestampFormat == "",
			DisableHTMLEscape: false,
		}
	case "text":
		format = &logrus.TextFormatter{
			ForceColors:      c.Color,
			ForceQuote:       true,
			DisableTimestamp: c.TimestampFormat == "",
			FullTimestamp:    true,
			TimestampFormat:  c.TimestampFormat,
			PadLevelText:     true,
			QuoteEmptyFields: true,
		}
	default:
		return nil, fmt.Errorf("unrecognized log format: %q", c.Format)
	}
	log := logrus.New()
	log.SetFormatter(format)
	lvl, err := logrus.ParseLevel(c.LogLvl)
	if err != nil {
		return nil, err
	}
	log.SetLevel(lvl)
	log.SetOutput(os.Stdout)
	return log, nil
}
