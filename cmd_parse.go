package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/marco-m/clim"
	"github.com/marco-m/govulnfilter/vuln/govulncheck"
	"github.com/marco-m/govulnfilter/vuln/osv"
)

type parseCmd struct {
	Dump    bool
	Verbose bool
	Args    []string
}

func newParseCmd(parent *clim.CLI, name, oneline string) (*parseCmd, error) {
	var parseCmd parseCmd
	cli, err := clim.NewSub(parent, name, oneline)
	if err != nil {
		return nil, err
	}
	if err := cli.AddFlags(
		&clim.Flag{
			Value: clim.Bool(&parseCmd.Verbose, false),
			Long:  "verbose", Help: "Print also package and module findings, in addition to symbol findings",
		},
		&clim.Flag{
			Value: clim.Bool(&parseCmd.Dump, false),
			Long:  "dump", Help: "Dump to stdout the findings as JSON.",
		},
	); err != nil {
		return nil, err
	}
	if err := cli.AddPosArgs(&parseCmd.Args,
		clim.Pair{Name: "<json-file>", Help: "Path to the JSON output of govulncheck"},
	); err != nil {
		return nil, err
	}
	return &parseCmd, nil
}

func (cmd *parseCmd) Run(cfg cfg) (err error) {
	if clim.CountTrue(cmd.Dump, cmd.Verbose) > 1 {
		return clim.NewParseError("parse: flags -dump -verbose are mutually exclusive")
	}
	if len(cmd.Args) == 0 {
		return clim.NewParseError("parse: missing <json-file>")
	}
	if len(cmd.Args) > 1 {
		return clim.NewParseError("parse: too many arguments: %s", cmd.Args)
	}

	fi, err := os.Open(cmd.Args[0])
	if err != nil {
		return fmt.Errorf("parse: %s", err)
	}
	defer func() { err = errors.Join(err, fi.Close()) }()
	osvEntries, findings, err := Parse(fi)
	if err != nil {
		return fmt.Errorf("parse: %s", err)
	}

	if cmd.Dump {
		if err := json.MarshalWrite(os.Stdout, findings, jsontext.WithIndent("  ")); err != nil {
			return fmt.Errorf("parse: %s", err)
		}
		return nil
	}

	perType, err := Partition(findings)
	if err != nil {
		return fmt.Errorf("parse: %s", err)
	}

	if err := printHeader(cmd.Verbose); err != nil {
		return err
	}
	if err := printSymbols(perType.PerSymbol, osvEntries); err != nil {
		return err
	}
	if cmd.Verbose {
		fmt.Println("=== Package Results ===")
		fmt.Println()
		printCommon(perType.PerPackage, osvEntries)

		fmt.Println("=== Module Results ===")
		fmt.Println()
		printCommon(perType.PerModule, osvEntries)
	}
	printFooter(cmd.Verbose)
	return nil
}

func printSymbols(findings []govulncheck.Finding, osvEntries map[string]osv.Entry) error {
	fmt.Println("=== Symbol Results ===")
	fmt.Println()
	for i, fnd := range findings {
		fmt.Printf("Vulnerability #%d: %s\n", i+1, fnd.OSV)
		fmt.Println(osvToString(osvEntries[fnd.OSV], fnd))
		fmt.Println("    Example traces found:")
		examples, err := MakeExampleTraces(findings)
		if err != nil {
			return err
		}
		for i, example := range examples {
			fmt.Printf("      #%d: %s: %s calls %s",
				i+1, example.Position, example.Caller, example.Vulnerable)
		}
		fmt.Println()
	}
	fmt.Println()
	return nil
}

func printCommon(findings []govulncheck.Finding, osvEntries map[string]osv.Entry) {
	for i, fnd := range findings {
		fmt.Printf("Vulnerability #%d: %s\n", i+1, fnd.OSV)
		fmt.Println(osvToString(osvEntries[fnd.OSV], fnd))
		fmt.Println()
	}
}

func printHeader(verbose bool) error {
	if !verbose {
		return nil
	}
	fmt.Println("HEADER WRITEME")
	fmt.Println()
	return nil
}

func printFooter(verbose bool) {
	fmt.Println("FOOTER WRITEME")
	if !verbose {
		fmt.Println("Use '-show verbose' for more details.")
	}
	fmt.Println()
}

func osvToString(osv osv.Entry, fnd govulncheck.Finding) string {
	var bld strings.Builder
	summaryMax := min(len(osv.Summary), 75)
	fmt.Fprintf(&bld, "    %s\n", osv.Summary[:summaryMax])
	fmt.Fprintf(&bld, "  More info: %s\n", osv.DatabaseSpecific.URL)
	for _, aff := range osv.Affected {
		fmt.Fprintf(&bld, "  Module: %s\n", aff.Module.Path)
		_, fixed := parseRanges(aff.Ranges)
		fmt.Fprintf(&bld, "    Found in: %s@%s\n", aff.Module.Path, parseFoundInFinding(fnd))
		fmt.Fprintf(&bld, "    Fixed in: %s@v%s", aff.Module.Path, fixed)
	}
	return bld.String()
}

// According to [osv.RangeEvent]: Exactly one of Introduced and Fixed must be present.
// I am not sure I understand why so much nesting...
func parseRanges(ranges []osv.Range) (introduced, fixed string) {
	var introducedL, fixedL []string
	for _, rng := range ranges {
		for _, rngEvt := range rng.Events {
			if rngEvt.Introduced != "" {
				introducedL = append(introducedL, rngEvt.Introduced)
			}
			if rngEvt.Fixed != "" {
				fixedL = append(fixedL, rngEvt.Fixed)
			}
		}
	}
	return strings.Join(introducedL, "_"), strings.Join(fixedL, "_")
}

func parseFoundInFinding(fnd govulncheck.Finding) string {
	if len(fnd.Trace) == 0 {
		return "!!!INVALID!!!"
	}
	frame := fnd.Trace[0]
	if frame == nil {
		return "!!!INVALID!!!"
	}
	return frame.Version
}
