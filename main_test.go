package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/marco-m/govulnfilter/fake"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	// Return a fixed timestamp so that we can hardcode timestamps in tests.
	timeNowFn = func() time.Time {
		return time.Date(2026, 10, 21, 15, 16, 17, 0, time.Local)
	}
	testscript.Main(m, map[string]func(){
		"govulnfilter": main,
		"fake": func() {
			if err := fake.Main(os.Args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, "fake:", err)
				os.Exit(1)
			}
		},
	})
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/script",
		RequireExplicitExec: true,
	})
}
