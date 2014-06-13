package main

import (
	"fmt"
	"os"
	"path"

	"github.com/jessevdk/go-flags"
	"github.com/rolftimmermans/httap/httpfwd"
)

type Flags struct {
	httpfwd.Options
	Help    bool `long:"help"    description:"Display this help and exit"`
	Version bool `long:"version" description:"Display version number and exit"`
}

var opts struct {
	Flags `group:"Options"`
}

var parser *flags.Parser

func writeVersion() {
	cliName := path.Base(os.Args[0])
	cliVersion := "0.1"
	fmt.Fprintf(os.Stderr, "%s version %s (%s)\n", cliName, cliVersion, httpfwd.PcapVersion())
}

func writeHelp() {
	fmt.Fprintln(os.Stderr, "Wiretaps and forwards HTTP traffic\n")
	parser.WriteHelp(os.Stderr)
}

func reportError() {
	if err := recover(); err != nil {
		fmt.Fprintln(os.Stderr, "Fatal:", err)
		os.Exit(1)
	}
}

func init() {
	defer reportError()

	parser = flags.NewParser(&opts, flags.None)
	parser.Usage = "[OPTIONS] [--src HOST:PORT ...] --dst HOST:PORT ..."
	_, err := parser.Parse()

	if len(os.Args) == 1 {
		opts.Help = true
	}

	if err != nil && !opts.Help && !opts.Version {
		panic(err)
	}
}

func main() {
	defer reportError()

	if opts.Version {
		writeVersion()
	} else if opts.Help {
		writeHelp()
	} else {
		httpfwd.NewForwarder(opts.Options).Start()
	}
}
