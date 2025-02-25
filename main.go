package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/fetch"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/update"
)

//go:embed VERSION
var version string

func init() {
	version = strings.TrimSpace(version)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app, err := cli.Parse(os.Args[1:])
	if err != nil {
		p := printer.NewHandle(printer.ColorAuto).Stderr()
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
		fmt.Fprintln(os.Stdout, "fetch", version)
		os.Exit(0)
	}
	if app.Update {
		p := printerHandle.Stderr()
		ok := update.Update(ctx, p, app.Timeout, version, verbosity == fetch.VSilent)
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
		DryRun:        app.DryRun,
		Edit:          app.Edit,
		HTTP:          app.HTTP,
		IgnoreStatus:  app.IgnoreStatus,
		Insecure:      app.Insecure,
		NoEncode:      app.NoEncode,
		NoFormat:      app.NoFormat,
		NoPager:       app.NoPager,
		Output:        app.Output,
		PrinterHandle: printerHandle,
		UserAgent:     "fetch/" + version,
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

func getVerbosity(app *cli.App) fetch.Verbosity {
	if app.Silent {
		return fetch.VSilent
	}
	switch app.Verbose {
	case 0:
		return fetch.VNormal
	case 1:
		return fetch.VVerbose
	default:
		return fetch.VExtraVerbose
	}
}

func writeCLIErr(p *printer.Printer, err error) {
	p.Set(printer.Bold)
	p.Set(printer.Red)
	p.WriteString("error")
	p.Reset()

	p.WriteString(": ")
	p.WriteString(err.Error())
	p.WriteString("\n\nFor more information, try '")

	p.Set(printer.Bold)
	p.Set("\\--help")
	p.Reset()

	p.WriteString("'.\n")
	p.Flush()
}
