package main

import (
	"io"
	"os"
	"testing"

	"github.com/marco-m/govulnfilter/vuln/govulncheck"
	"github.com/marco-m/rosina/assert"
)

func TestBadStreams(t *testing.T) {
	test := func(t *testing.T, inPath string, wantErr error) {
		t.Helper()
		fi, cleanup := openFile(t, inPath)
		defer cleanup()

		_, _, err := Parse(fi)
		assert.ErrorIs(t, err, wantErr, "Vulnerabilities")
	}

	t.Run("first message must be Config", func(t *testing.T) {
		test(t, "testdata/json/missing-config.json", ErrFirstMessage)
	})
	t.Run("ProtocolVersion must match", func(t *testing.T) {
		test(t, "testdata/json/wrong-protocol.json", ErrProtocolMismatch)
	})
	t.Run("input is not JSON", func(t *testing.T) {
		test(t, "testdata/json/not-json.txt", ErrInvalidJSON)
	})
}

func TestParse(t *testing.T) {
	test := func(t *testing.T, inPath string, wantOsvCount int, wantFindingsCount int) {
		t.Helper()
		fi, cleanup := openFile(t, inPath)
		defer cleanup()

		osvEntries, findings, err := Parse(fi)
		assert.NoError(t, err, "Parse")
		assert.Equal(t, len(osvEntries), wantOsvCount, "len(osvEntries)")
		assert.Equal(t, len(findings), wantFindingsCount, "len(findings)")
		// assert.DeepEqual(t, findings, wantFindings, "Findings")
	}

	t.Run("zero vulnerabilities", func(t *testing.T) {
		test(t, "testdata/json/vulnerabilities-0.json", 186, 0)
	})
	t.Run("one vulnerability", func(t *testing.T) {
		test(t, "testdata/json/vulnerabilities-1.json", 186, 7)
	})
}

func TestPartition(t *testing.T) {
	test := func(t *testing.T, inPath string, wantPerType FindingsPerType) {
		t.Helper()
		fi, cleanup := openFile(t, inPath)
		defer cleanup()

		_, findings, err := Parse(fi)
		assert.NoError(t, err, "Parse")

		fndPerType, err := Partition(findings)
		assert.NoError(t, err, "Partition")

		assert.DeepEqual(t, fndPerType.PerSymbol, wantPerType.PerSymbol, "symbols")
		assert.DeepEqual(t, fndPerType.PerPackage, wantPerType.PerPackage, "packages")
		assert.DeepEqual(t, fndPerType.PerModule, wantPerType.PerModule, "modules")
	}

	t.Run("one vulnerability", func(t *testing.T) {
		test(t, "testdata/json/vulnerabilities-1.json",
			FindingsPerType{
				PerSymbol: []govulncheck.Finding{
					{
						OSV:          "GO-2021-0113",
						FixedVersion: "v0.3.7",
						Trace: []*govulncheck.Frame{
							{
								Module:   "golang.org/x/text",
								Version:  "v0.3.5",
								Package:  "golang.org/x/text/language",
								Function: "Parse",
								Position: &govulncheck.Position{
									Filename: "language/parse.go",
									Offset:   1121, Line: 33, Column: 6},
							},
							{
								Module:   "vuln.tutorial",
								Version:  "",
								Package:  "vuln.tutorial",
								Function: "main",
								Position: &govulncheck.Position{
									Filename: "main.go",
									Offset:   196, Line: 14, Column: 29},
							},
						},
					},
				},
				PerPackage: []govulncheck.Finding{
					{
						OSV:          "GO-2022-1059",
						FixedVersion: "v0.3.8",
						Trace: []*govulncheck.Frame{
							{Module: "golang.org/x/text", Version: "v0.3.5",
								Package: "golang.org/x/text/language",
							},
						},
					},
				},
				PerModule: []govulncheck.Finding{
					{
						OSV:          "GO-2026-6629",
						FixedVersion: "v0.41.0",
						Trace: []*govulncheck.Frame{
							{Module: "golang.org/x/text", Version: "v0.3.5"},
						},
					},
					{
						OSV:          "GO-2026-5970",
						FixedVersion: "v0.39.0",
						Trace: []*govulncheck.Frame{
							{Module: "golang.org/x/text", Version: "v0.3.5"},
						},
					},
				},
			})
	})
}

func TestMakeExampleTraces(t *testing.T) {
	test := func(in []govulncheck.Finding, want []ExampleTrace) {
		t.Helper()
		examples, err := MakeExampleTraces(in)
		assert.NoError(t, err, "MakeExampleTraces")
		assert.DeepEqual(t, examples, want, "examples")
	}

	test([]govulncheck.Finding{
		{
			Trace: []*govulncheck.Frame{
				{
					Package:  "golang.org/x/text/language",
					Function: "Parse",
					Position: &govulncheck.Position{
						Filename: "language/parse.go",
						Offset:   1121, Line: 33, Column: 6},
				},
				{
					Package:  "vuln.tutorial",
					Function: "main",
					Position: &govulncheck.Position{
						Filename: "main.go",
						Offset:   196, Line: 14, Column: 29},
				},
			},
		},
	},
		[]ExampleTrace{
			{
				Position:   "main.go:14:29",
				Caller:     "vuln.main",
				EntryPoint: "", // Not implemented
				Vulnerable: "language.Parse",
			},
		})
}

//
// Helpers
//

func openFile(t *testing.T, inPath string) (rd io.Reader, cleanup func()) {
	t.Helper()
	fi, err := os.Open(inPath)
	assert.NoError(t, err, "openFile")
	return fi, func() { fi.Close() }
}
