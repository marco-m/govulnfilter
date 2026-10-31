package main

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/marco-m/govulnfilter/vuln/govulncheck"
	"github.com/marco-m/govulnfilter/vuln/osv"
)

var (
	ErrFirstMessage      = errors.New("first message in stream mismatch")
	ErrProtocolMismatch  = errors.New("ProtocolVersion mismatch")
	ErrScanLevelMismatch = errors.New("ScanLevel mismatch")
	ErrScanModeMismatch  = errors.New("ScanMode mismatch")
	ErrInvalidJSON       = errors.New("invalid JSON")
)

func Parse(in io.Reader) (map[string]osv.Entry, []govulncheck.Finding, error) {
	osvs, findings, err := parse(in)
	if err != nil {
		if syntaxErr, ok := errors.AsType[*jsontext.SyntacticError](err); ok {
			return nil, nil, fmt.Errorf("parse: %w: %s", ErrInvalidJSON, syntaxErr)
		}
		return nil, nil, fmt.Errorf("parse: %w", err)
	}
	return osvs, findings, nil
}

type FindingsPerType struct {
	PerSymbol  []govulncheck.Finding
	PerPackage []govulncheck.Finding
	PerModule  []govulncheck.Finding
}

// Partition takes the output findings of [Parse] and partitions them in 3 groups:
// symbol findings, package findings and module findings.
// For each symbol finding, it reduces (removes) the corresponding package and
// module findings. This is similar to deduplication.
// Normally you are interested only the symbol findings, which are the only ones
// that represent a vulnerability according to reachability analysis.
func Partition(findings []govulncheck.Finding) (FindingsPerType, error) {
	var perType FindingsPerType
	for _, fnd := range findings {
		fndType, err := findingType(fnd)
		switch fndType {
		case symbolFinding:
			perType.PerSymbol = append(perType.PerSymbol, fnd)
		case packageFinding:
			perType.PerPackage = append(perType.PerPackage, fnd)
		case moduleFinding:
			perType.PerModule = append(perType.PerModule, fnd)
		default:
			return FindingsPerType{}, fmt.Errorf("partition: %s", err)
		}
	}

	// Deduplicate based on symbols:
	for _, sym := range perType.PerSymbol {
		del := func(fnd govulncheck.Finding) bool { return fnd.OSV == sym.OSV }
		perType.PerPackage = slices.DeleteFunc(perType.PerPackage, del)
		perType.PerModule = slices.DeleteFunc(perType.PerModule, del)
	}

	// Deduplicate based on packages:
	for _, pack := range perType.PerPackage {
		del := func(fnd govulncheck.Finding) bool { return fnd.OSV == pack.OSV }
		perType.PerModule = slices.DeleteFunc(perType.PerModule, del)
	}

	return perType, nil
}

type ExampleTrace struct {
	Position   string
	Caller     string
	EntryPoint string
	Vulnerable string
}

// #1: main.go:14:29: vuln.main calls language.Parse
func MakeExampleTraces(perSymbol []govulncheck.Finding) ([]ExampleTrace, error) {
	var examples []ExampleTrace
	for _, fnd := range perSymbol {
		fndType, err := findingType(fnd)
		if err != nil {
			return nil, fmt.Errorf("example traces: %s", err)
		}
		if fndType != symbolFinding {
			return nil, fmt.Errorf("example traces: have: %s; want: %s", fndType, symbolFinding)
		}
		// This is a symbol finding, so it has at least a trace made of 2 frames.
		caller := fnd.Trace[len(fnd.Trace)-1]
		vulnerable := fnd.Trace[0]
		pos := fmt.Sprintf("%s:%d:%d",
			caller.Position.Filename, caller.Position.Line, caller.Position.Column)
		trace := ExampleTrace{
			Position: pos,
			Caller:   packageShortName(caller.Package) + "." + caller.Function,
			// EntryPoint: "not implemented",
			Vulnerable: packageShortName(vulnerable.Package) + "." + vulnerable.Function,
		}
		examples = append(examples, trace)
	}
	return examples, nil
}

func packageShortName(name string) string {
	// golang.org/x/text/language ==> language
	if _, x, ok := strings.CutLast(name, "/"); ok {
		return x
	}
	// foo.bar ==> bar
	x, _, _ := strings.Cut(name, ".")
	return x
}

const (
	symbolFinding  = "symbolFinding"
	packageFinding = "packageFinding"
	moduleFinding  = "moduleFinding"
	invalidFinding = "invalidFinding"
)

func findingType(fnd govulncheck.Finding) (string, error) {
	if len(fnd.Trace) == 0 {
		return invalidFinding, fmt.Errorf("invalid finding, len(trace)==0")
	}
	if len(fnd.Trace) > 1 {
		return symbolFinding, nil
	}
	frame := fnd.Trace[0]
	if frame.Function != "" {
		return symbolFinding, nil
	}
	if frame.Package != "" {
		return packageFinding, nil
	}
	if frame.Module != "" {
		return moduleFinding, nil
	}
	return invalidFinding, fmt.Errorf("invalid finding, func, package, module empty")
}

func parse(in io.Reader) (map[string]osv.Entry, []govulncheck.Finding, error) {
	dec := jsontext.NewDecoder(in)
	var msg govulncheck.Message

	// The first message in a stream must be a [govulncheck.Config].
	err := json.UnmarshalDecode(dec, &msg)
	if err != nil {
		if err == io.EOF {
			err = fmt.Errorf("unexpected end of stream")
		}
		return nil, nil, err
	}
	if msg.Config == nil {
		return nil, nil, fmt.Errorf("%w: have: %s; want: %s",
			ErrFirstMessage, messageType(msg), "Config")
	}
	if have, want := msg.Config.ProtocolVersion, govulncheck.ProtocolVersion; have != want {
		return nil, nil, fmt.Errorf("%w: have: %s; want: %s", ErrProtocolMismatch, have, want)
	}
	if have, want := string(msg.Config.ScanLevel), govulncheck.ScanLevelSymbol; have != want {
		return nil, nil, fmt.Errorf("%w: have: %s; want: %s", ErrScanLevelMismatch, have, want)
	}
	if have, want := string(msg.Config.ScanMode), govulncheck.ScanModeSource; have != want {
		return nil, nil, fmt.Errorf("%w: have: %s; want: %s", ErrScanModeMismatch, have, want)
	}

	osvs := make(map[string]osv.Entry) // to deduplicate the streaming messages
	var findings []govulncheck.Finding
	for {
		var msg govulncheck.Message
		err := json.UnmarshalDecode(dec, &msg)
		if err != nil {
			if err == io.EOF { // End of stream, expected.
				break
			}
			return nil, nil, err
		}
		if msg.OSV != nil {
			osvs[msg.OSV.ID] = *msg.OSV
		}
		if msg.Finding != nil {
			findings = append(findings, *msg.Finding)
		}
	}
	slices.SortFunc(findings,
		func(a, b govulncheck.Finding) int { return cmp.Compare(b.OSV, a.OSV) })
	return osvs, findings, nil
}

func messageType(msg govulncheck.Message) string {
	if msg.Config != nil {
		return "Config"
	}
	if msg.Progress != nil {
		return "Progress"
	}
	if msg.SBOM != nil {
		return "SBOM"
	}
	if msg.OSV != nil {
		return "OSV"
	}
	if msg.Finding != nil {
		return "Finding"
	}
	return "Invalid"
}
