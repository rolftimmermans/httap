package main

import (
    "fmt"
    "os"
    "path"
    "github.com/ogier/pflag"
    "./httpfwd"
)

var opt struct {
    httpfwd.ForwarderOptions
    Version bool
}

func version() {
    cliName := path.Base(os.Args[0])
    cliVersion := "0.1"

    fmt.Fprintf(os.Stderr, "%s version %s (%s)\n", cliName, cliVersion, httpfwd.PcapVersion())
}

func usage() {
    cliName := path.Base(os.Args[0])

    fmt.Fprintln(os.Stderr, "Wiretaps and forwards HTTP traffic to given destination host")
    fmt.Fprintf (os.Stderr, "Usage: %s [options...] host[:port]\n", cliName)
    fmt.Fprintln(os.Stderr)

    fmt.Fprintln(os.Stderr, "Options:")
    pflag.VisitAll(func(flag *pflag.Flag) {
        format := "--%-13s %s"

        if flag.DefValue == "false" {
            format = format + "%.0s"
        } else {
            format = format + " (default: %s)"
        }

        if len(flag.Shorthand) > 0 {
            format = "  -%s, "  + format
        } else {
            format = "   %s   " + format
        }

        fmt.Fprintf(os.Stderr, format + "\n", flag.Shorthand, flag.Name, flag.Usage, flag.DefValue)
    })
    fmt.Fprintln(os.Stderr)
}

func init() {
    pflag.Usage = usage
    pflag.IntVarP(&opt.Port, "port", "p", 80, "Port to tap HTTP traffic from")
    pflag.BoolVarP(&opt.ReplaceHost, "replace-host", "h", false, "Replace value of host header with destination host")
    pflag.BoolVarP(&opt.Verbose, "verbose", "v", false, "Show extra information including all request headers")
    pflag.BoolVarP(&opt.Version, "version", "", false, "Show version information and exit")
}

func main() {
    pflag.Parse()

    if opt.Version {
        version()
    } else {
        args := pflag.Args()
        if len(args) == 1 {
            httpfwd.NewForwarder(args[0], opt.ForwarderOptions).Start()
        } else {
            pflag.Usage()
        }
    }
}
