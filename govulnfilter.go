package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"time"
)

const header = `Usage: govulnfilter [<OPTS>] govulncheck <GOVULNCHECK-ARGS>

Options:

`

const footer = `
govulnfilter allows to ignore temporarily a vulnerability reported by govulncheck.

Examples:

    $ govulnfilter -init
    Create the .govulnfilter.json configuration file.
    Then, edit it accordingly.

    $ govulnfilter govulncheck ./...
    Scan the current module. Normally this is all you need.
    The govulnfilter program will add '-format json' to the govulncheck invocation.
`

type Data struct {
	DataVersion string  `json:"data_version"`
	Delays      []Delay `json:"delays"`
}

type Delay struct {
	CVE        string    `json:"cve"`
	Expiration time.Time `json:"expiration"`
	Reason     string    `json:"reason"`
}

// Set Version at link time to workaround Go limitations with debug.ReadBuildInfo().
var Version string

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type cfg struct {
	version bool
}

func run(args []string) error {
	var cfg cfg
	// [flag.FlagSet] is needed to avoid messing with flags added by package testing.
	fs := flag.NewFlagSet("govulnfilter", flag.ExitOnError)
	fs.BoolVar(&cfg.version, "version", false, "Print the govulnfilter version.")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, header)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, footer)
	}

	fs.Parse(args)
	if cfg.version {
		fmt.Fprintln(os.Stderr, version())
		return nil
	}
	if true {
		return fmt.Errorf("ciccio")
	}
	return nil
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
