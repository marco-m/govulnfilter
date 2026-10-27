package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marco-m/clim"
)

type initCmd struct{}

func newInitCmd(parent *clim.CLI, name, oneline string) (*initCmd, error) {
	_, err := clim.NewSub(parent, name, oneline)
	return &initCmd{}, err
}

func (cmd *initCmd) Run(cfg cfg) (err error) {
	path, err := filepath.Abs(kFileName)
	if err != nil {
		return fmt.Errorf("init: determining file path: %s", err)
	}
	if fi, err := os.Open(path); err == nil {
		_ = fi.Close()
		return fmt.Errorf("init: configuration file already exists: %s", path)
	}

	fi, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("init: creating file: %s", err)
	}
	defer func() { err = errors.Join(err, fi.Close()) }()

	truncateToStartOfDay := func(t time.Time) time.Time {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	}
	after30days := truncateToStartOfDay(timeNowFn().Add(30 * 24 * time.Hour))
	data := Configuration{
		Description:   "Configuration file for govulnfilter",
		SchemaVersion: kFormatVersion,
		Project:       "Replace with your project name",
		Delays: []Delay{{
			OSV:        "GO-2026-4736",
			Summary:    "Optional, should come from govulncheck output",
			Expiration: after30days,
			Reason:     "Reason for delaying this vulnerability",
		}},
	}
	enc := json.NewEncoder(fi)
	enc.SetIndent("", "    ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("init: writing sample: %s", err)
	}
	fmt.Printf("Created configuration file %s\n", path)
	return nil
}
