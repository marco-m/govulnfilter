# govulnfilter -- a filter for govulncheck

`govulnfilter` allows to ignore temporarily a vulnerability reported by [govulncheck].

Usage:

    $ govulnfilter run govulncheck ./...

## Status

**The project currently does not accept Pull Requests.**
**Work in progress, API heavily unstable, not ready for use.**

## AI policy

This project does not accept contributions of any form (code, documentation, issues) written with the aid of AI agents.

## Configuration

Example of a configuration file:

    {
      "description": "Configuration file for govulnfilter",
      "file_version": "1",
      "project": "Replace with your project name",
      "delays": [
        {
          "osv": "GO-2026-4736",
          "summary": "Optional, should come from govulncheck output",
          "expiration": "2026-11-20T00:00:00+01:00",
          "reason": "Reason for delaying this vulnerability"
        }
      ]
    }

## Design decisions

WRITEME

TODO

- handle signals CTRL-C


govulncheck: https://go.dev/blog/vuln
