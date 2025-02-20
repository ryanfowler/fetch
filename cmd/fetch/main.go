package main

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/fetch"
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/update"
	"github.com/ryanfowler/fetch/internal/vars"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app, err := cli.Parse()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	printerHandle := printer.NewHandle(app.Color)

	if app.Help {
		p := printerHandle.Stdout()
		cli.Help(app.CLI(), p)
		p.Flush(os.Stdout)
		os.Exit(0)
	}
	if app.Version {
		fmt.Fprintln(os.Stdout, "fetch", vars.Version)
		os.Exit(0)
	}
	if app.Update {
		p := printerHandle.Stderr()
		if ok := update.Update(ctx, p, app.Timeout); ok {
			os.Exit(0)
		}
		os.Exit(1)
	}

	req := fetch.Request{
		DryRun:        app.DryRun,
		HTTP:          app.HTTP,
		Insecure:      app.Insecure,
		NoEncode:      app.NoEncode,
		NoFormat:      app.NoFormat,
		Output:        app.Output,
		PrinterHandle: printerHandle,
		Verbosity:     getVerbosity(app),

		Method:      app.Method,
		URL:         app.URL,
		Body:        app.Data,
		Form:        app.Form,
		Multipart:   getMultipartReader(app.Multipart),
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

func getMultipartReader(kvs []vars.KeyVal) io.Reader {
	if len(kvs) == 0 {
		return nil
	}

	reader, writer := io.Pipe()
	go func() {
		defer writer.Close()

		mpw := multipart.NewWriter(writer)
		defer mpw.Close()

		for _, kv := range kvs {
			if !strings.HasPrefix(kv.Val, "@") {
				err := mpw.WriteField(kv.Key, kv.Val)
				if err != nil {
					writer.CloseWithError(err)
					return
				}
				continue
			}

			// Form part is a file.
			w, err := mpw.CreateFormFile(kv.Key, kv.Val[1:])
			if err != nil {
				writer.CloseWithError(err)
				return
			}

			f, err := os.Open(kv.Val[1:])
			if err != nil {
				writer.CloseWithError(err)
				return
			}

			_, err = io.Copy(w, f)
			f.Close()
			if err != nil {
				writer.CloseWithError(err)
				return
			}
		}
	}()

	return reader
}
