package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fetch"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/update"
)

func main() {
	// Cancel the context when one of the below signals are caught.
	ctx, cancel := context.WithCancelCause(context.Background())
	chSig := make(chan os.Signal, 1)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		sig := <-chSig
		cancel(core.SignalError(sig.String()))
	}()

	// Parse the CLI args.
	app, err := cli.Parse(os.Args[1:])
	if err != nil {
		p := core.NewHandle(app.Cfg.Color).Stderr()
		writeCLIErr(p, err)
		os.Exit(1)
	}

	// Parse any config file, and merge with it.
	file, err := config.GetFile(app.ConfigPath)
	if err != nil {
		p := core.NewHandle(app.Cfg.Color).Stderr()
		writeCLIErr(p, err)
		os.Exit(1)
	}
	if file != nil {
		if app.URL != nil {
			hostCfg, ok := file.Hosts[app.URL.Hostname()]
			if ok {
				app.Cfg.Merge(hostCfg)
			}
		}
		app.Cfg.Merge(file.Global)
	}

	printerHandle := core.NewHandle(app.Cfg.Color)
	verbosity := getVerbosity(app)

	// Print help to stdout.
	if app.Help {
		p := printerHandle.Stdout()
		app.PrintHelp(p)
		p.Flush()
		os.Exit(0)
	}

	// Print version to stdout.
	if app.Version {
		fmt.Fprintln(os.Stdout, "fetch", core.Version)
		os.Exit(0)
	}

	// Print build info to stdout.
	if app.BuildInfo {
		p := printerHandle.Stdout()
		info := core.GetBuildInfo()
		if app.Cfg.Format != core.FormatOff {
			format.FormatJSON(info, p)
		} else {
			p.Write(info)
		}
		p.Flush()
		os.Exit(0)
	}

	// Attempt to update the current executable.
	if app.Update {
		p := printerHandle.Stderr()
		timeout := getValue(app.Cfg.Timeout)
		ok := update.Update(ctx, p, timeout, verbosity == core.VSilent)
		if ok {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Otherwise, a URL must be provided.
	if app.URL == nil {
		p := printerHandle.Stderr()
		writeCLIErr(p, errors.New("<URL> must be provided"))
		os.Exit(1)
	}

	// Make the HTTP request using the parsed configuration.
	req := fetch.Request{
		DNSServer:     app.Cfg.DNSServer,
		DryRun:        app.DryRun,
		Edit:          app.Edit,
		Format:        app.Cfg.Format,
		HTTP:          app.Cfg.HTTP,
		IgnoreStatus:  getValue(app.Cfg.IgnoreStatus),
		Insecure:      getValue(app.Cfg.Insecure),
		NoEncode:      getValue(app.Cfg.NoEncode),
		NoPager:       getValue(app.Cfg.NoPager),
		Output:        app.Output,
		PrinterHandle: printerHandle,
		Redirects:     app.Cfg.Redirects,
		TLS:           getValue(app.Cfg.TLS),
		Verbosity:     verbosity,

		Method:      app.Method,
		URL:         app.URL,
		Body:        app.Data,
		Form:        app.Form,
		Multipart:   multipart.NewMultipart(app.Multipart),
		Headers:     app.Cfg.Headers,
		QueryParams: app.Cfg.QueryParams,
		AWSSigv4:    app.AWSSigv4,
		Basic:       app.Basic,
		Bearer:      app.Bearer,
		JSON:        app.JSON,
		XML:         app.XML,
		Proxy:       app.Cfg.Proxy,
		Timeout:     getValue(app.Cfg.Timeout),
	}
	status := fetch.Fetch(ctx, &req)
	os.Exit(status)
}

func getValue[T any](v *T) T {
	if v == nil {
		var t T
		return t
	}
	return *v
}

// getVerbosity returns the Verbosity level based on the app configuration.
func getVerbosity(app *cli.App) core.Verbosity {
	if getValue(app.Cfg.Silent) {
		return core.VSilent
	}
	switch getValue(app.Cfg.Verbosity) {
	case 0:
		return core.VNormal
	case 1:
		return core.VVerbose
	default:
		return core.VExtraVerbose
	}
}

// writeCLIErr writes the provided CLI error to the Printer.
func writeCLIErr(p *core.Printer, err error) {
	p.Set(core.Bold)
	p.Set(core.Red)
	p.WriteString("error")
	p.Reset()

	p.WriteString(": ")
	if pt, ok := err.(core.PrinterTo); ok {
		pt.PrintTo(p)
	} else {
		p.WriteString(err.Error())
	}

	p.WriteString("\n\nFor more information, try '")

	p.Set(core.Bold)
	p.WriteString("--help")
	p.Reset()

	p.WriteString("'.\n")
	p.Flush()
}
