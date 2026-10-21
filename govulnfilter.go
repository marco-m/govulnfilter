package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/marco-m/clim"
)

const examples = `
$ govulnfilter init
Create the .govulnfilter.json configuration file.
Then, edit it accordingly.

$ govulnfilter run ./...
Invoke govulncheck to scan the current module. Normally this is all you need.
`

const kFileName = ".govulnfilter.json"

const kFormatVersion = "devel"

type Configuration struct {
	Description   string  `json:"description"`
	SchemaVersion string  `json:"schema_version"`
	Project       string  `json:"project"`
	Delays        []Delay `json:"delays"`
}

type Delay struct {
	OSV        string    `json:"osv"`
	Summary    string    `json:"summary"`
	Expiration time.Time `json:"expiration"`
	Reason     string    `json:"reason"`
}

// Set Version at link time to workaround Go limitations with debug.ReadBuildInfo().
var Version string

// Escape hatch for testing.
var timeNowFn = time.Now

func main() {
	if err := mainErr(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type cfg struct{}

func mainErr(args []string) error {
	var cfg cfg
	cli, err := clim.NewTop("govulnfilter", "ignore temporarily a govulncheck vulnerability")
	if err != nil {
		return err
	}
	cli.SetExamples(examples)

	initCmd, err := newInitCmd(cli, "init", "Create the .govulnfilter.json configuration file")
	if err != nil {
		return err
	}

	_, err = clim.NewSub(cli, "version", "Print the govulnfilter version")
	if err != nil {
		return err
	}

	command, err := cli.Parse(args)
	if err != nil {
		if errors.Is(err, clim.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		return err
	}
	switch command {
	case "govulnfilter init":
		return initCmd.Run(cfg)
	case "govulnfilter version":
		fmt.Fprintln(os.Stderr, version())
		return nil
	default:
		return fmt.Errorf("internal error: unwired command: %s", command)
	}
}

func version() string {
	if Version != "" {
		return Version
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		return buildInfo.Main.Version
	}
	return "(unknown)"
}
