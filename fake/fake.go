package fake

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/marco-m/clim"
)

type cfg struct {
	ExitStatus int
	Stdout     string
	Stderr     string
}

// NOTE if no errors, will call os.Exit() !
func Main(args []string) error {
	var cfg cfg
	cli, err := clim.NewTop("fake", "helper to test govulnfilter with testscript")
	if err != nil {
		return err
	}

	if err := cli.AddFlags(
		&clim.Flag{
			Value: clim.Int(&cfg.ExitStatus, 0),
			Long:  "exit", Help: "The exit status"},
		&clim.Flag{
			Value: clim.String(&cfg.Stdout, ""),
			Long:  "stdout", Help: "File to print to stdout"},
		&clim.Flag{
			Value: clim.String(&cfg.Stderr, ""),
			Long:  "stderr", Help: "File to print to stderr"},
	); err != nil {
		return err
	}
	var posArgs []string
	if err := cli.AddPosArgs(&posArgs); err != nil {
		return err
	}

	_, err = cli.Parse(args)
	if err != nil {
		if errors.Is(err, clim.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		return err
	}
	if len(posArgs) > 0 {
		return clim.NewParseError("unexpected arguments: %s", posArgs)
	}

	if err := run(cfg); err != nil {
		return err
	}
	os.Exit(cfg.ExitStatus)
	return nil
}

func run(cfg cfg) error {
	if err := cat(os.Stdout, cfg.Stdout); err != nil {
		return err
	}
	if err := cat(os.Stderr, cfg.Stderr); err != nil {
		return err
	}
	return nil
}

func cat(out io.Writer, path string) error {
	if path == "" {
		return nil
	}
	fi, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fi.Close() // nolint: errcheck
	_, err = io.Copy(out, fi)
	if err != nil {
		return err
	}
	return nil
}
