package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/marco-m/clim"
)

// MAYBE extract this from the JSON and print something ???
// govulncheck -version
// Go: go1.27.3
// Scanner: govulncheck@v1.9.0
// DB: https://vuln.go.dev
// DB updated: 2026-10-21 00:27:29 +0000 UTC

type runCmd struct {
	Debug bool
	Args  []string
}

func newRunCmd(parent *clim.CLI, name, oneline string) (*runCmd, error) {
	var runCmd runCmd
	cli, err := clim.NewSub(parent, name, oneline)
	if err != nil {
		return nil, err
	}

	cli.SetExamples(`
$ govulnfilter run govulncheck ./...
Invoke govulncheck to scan the current module.
`)

	if err := cli.AddFlags(&clim.Flag{
		Value: clim.Bool(&runCmd.Debug, false),
		Long:  "debug", Help: "Enable debug mode",
	}); err != nil {
		return nil, err
	}
	if err := cli.AddPosArgs(&runCmd.Args,
		clim.Pair{Name: "<govulncheck>", Help: "Name of (or path to) govulncheck"},
		clim.Pair{Name: "<args>", Help: "Arguments to govulncheck"},
	); err != nil {
		return nil, err
	}
	return &runCmd, nil
}

func (cmd *runCmd) Run(cfg cfg) error {
	if len(cmd.Args) == 0 {
		return clim.NewParseError("run: missing <govulncheck>")
	}
	command := exec.Command(cmd.Args[0], cmd.Args[1:]...)

	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("getting stdout of subprocess: %s", err)
	}
	stderrPipe, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("getting stderr of subprocess: %s", err)
	}

	if err := command.Start(); err != nil {
		return fmt.Errorf("%s", err)
	}

	var scanErrs []error
	stdoutPrefix := ""
	stderrPrefix := ""
	if cmd.Debug {
		stdoutPrefix = "out> "
		stderrPrefix = "err> "
	}

	scanStdout := bufio.NewScanner(stdoutPipe)
	for scanStdout.Scan() {
		fmt.Fprintf(os.Stdout, "%s%s\n", stdoutPrefix, scanStdout.Text())
	}
	if err := scanStdout.Err(); err != nil {
		scanErrs = append(scanErrs, fmt.Errorf("scan subprocess stdout: %s", err))
	}

	scanStderr := bufio.NewScanner(stderrPipe)
	for scanStderr.Scan() {
		fmt.Fprintf(os.Stderr, "%s%s\n", stderrPrefix, scanStderr.Text())
	}
	if err := scanStderr.Err(); err != nil {
		scanErrs = append(scanErrs, fmt.Errorf("scan subprocess stderr: %s", err))
	}

	if err := command.Wait(); err != nil {
		return fmt.Errorf("%s: %w", cmd.Args[0], err)
	}

	if len(scanErrs) > 0 {
		return fmt.Errorf("unexpected I/O error: %s", errors.Join(scanErrs...))
	}
	return nil
}
