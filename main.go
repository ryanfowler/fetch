package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fetch"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/update"
)

func main() {
	ctx, cancel := context.WithCancelCause(context.Background())
	chSig := make(chan os.Signal, 1)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		sig := <-chSig
		cancel(core.SignalError(sig.String()))
	}()

	app, err := cli.Parse(os.Args[1:])
	if err != nil {
		p := printer.NewHandle(app.Color).Stderr()
		writeCLIErr(p, err)
		os.Exit(1)
	}

	printerHandle := printer.NewHandle(app.Color)
	verbosity := getVerbosity(app)

	if app.Help {
		p := printerHandle.Stdout()
		app.PrintHelp(p)
		p.Flush()
		os.Exit(0)
	}
	if app.Version {
		fmt.Fprintln(os.Stdout, "fetch", core.Version)
		os.Exit(0)
	}
	if app.BuildInfo {
		p := printerHandle.Stdout()
		format.FormatJSON(core.GetBuildInfo(), p)
		p.Flush()
		os.Exit(0)
	}
	if app.Update {
		p := printerHandle.Stderr()
		ok := update.Update(ctx, p, app.Timeout, verbosity == core.VSilent)
		if ok {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if app.URL == nil {
		p := printerHandle.Stderr()
		writeCLIErr(p, errors.New("<URL> must be provided"))
		os.Exit(1)
	}

	req := fetch.Request{
		DNSServer:     app.DNSServer,
		DryRun:        app.DryRun,
		Edit:          app.Edit,
		Format:        app.Format,
		HTTP:          app.HTTP,
		IgnoreStatus:  app.IgnoreStatus,
		Insecure:      app.Insecure,
		NoEncode:      app.NoEncode,
		NoPager:       app.NoPager,
		Output:        app.Output,
		PrinterHandle: printerHandle,
		TLS:           app.TLS,
		Verbosity:     verbosity,

		Method:      app.Method,
		URL:         app.URL,
		Body:        app.Data,
		Form:        app.Form,
		Multipart:   multipart.NewMultipart(app.Multipart),
		Headers:     app.Headers,
		QueryParams: app.QueryParams,
		AWSSigv4:    app.AWSSigv4,
		Basic:       app.Basic,
		Bearer:      app.Bearer,
		JSON:        app.JSON,
		XML:         app.XML,
		Proxy:       app.Proxy,
		Timeout:     app.Timeout,
	}
	status := fetch.Fetch(ctx, &req)
	os.Exit(status)
}

func getVerbosity(app *cli.App) core.Verbosity {
	if app.Silent {
		return core.VSilent
	}
	switch app.Verbose {
	case 0:
		return core.VNormal
	case 1:
		return core.VVerbose
	default:
		return core.VExtraVerbose
	}
}

func writeCLIErr(p *printer.Printer, err error) {
	p.Set(printer.Bold)
	p.Set(printer.Red)
	p.WriteString("error")
	p.Reset()

	p.WriteString(": ")
	if pt, ok := err.(printer.PrinterTo); ok {
		pt.PrintTo(p)
	} else {
		p.WriteString(err.Error())
	}

	p.WriteString("\n\nFor more information, try '")

	p.Set(printer.Bold)
	p.WriteString("--help")
	p.Reset()

	p.WriteString("'.\n")
	p.Flush()
}
