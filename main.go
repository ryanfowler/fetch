package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/complete"
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

	// Handle completion requests.
	if app.Complete != "" {
		err := handleCompletion(app.Complete, app.ExtraArgs)
		if err != nil {
			p := core.NewHandle(app.Cfg.Color).Stderr()
			core.WriteErrorMsg(p, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Parse any config file, and merge with it.
	handle := core.NewHandle(app.Cfg.Color)
	err = parseConfigFile(app, handle.Stderr())
	if err != nil {
		p := handle.Stderr()
		core.WriteErrorMsg(p, err)
		os.Exit(1)
	}

	// Start async update, if necessary.
	if !app.Update && app.Cfg.AutoUpdate != nil && *app.Cfg.AutoUpdate >= 0 {
		checkForUpdate(ctx, handle.Stderr(), *app.Cfg.AutoUpdate)
	}

	// Print help to stdout.
	if app.Help {
		p := handle.Stdout()
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
		p := handle.Stdout()
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
	verbosity := getVerbosity(app)
	if app.Update {
		p := handle.Stderr()
		timeout := getValue(app.Cfg.Timeout)
		status := update.Update(ctx, p, timeout, verbosity == core.VSilent)
		os.Exit(status)
	}

	// Otherwise, a URL must be provided.
	if app.URL == nil {
		p := handle.Stderr()
		writeCLIErr(p, errors.New("<URL> must be provided"))
		os.Exit(1)
	}

	// Make the HTTP request using the parsed configuration.
	req := fetch.Request{
		AWSSigv4:      app.AWSSigv4,
		Basic:         app.Basic,
		Bearer:        app.Bearer,
		Data:          app.Data,
		DNSServer:     app.Cfg.DNSServer,
		DryRun:        app.DryRun,
		Edit:          app.Edit,
		Form:          app.Form,
		Format:        app.Cfg.Format,
		Headers:       app.Cfg.Headers,
		HTTP:          app.Cfg.HTTP,
		IgnoreStatus:  getValue(app.Cfg.IgnoreStatus),
		Image:         app.Cfg.Image,
		Insecure:      getValue(app.Cfg.Insecure),
		JSON:          app.JSON,
		Method:        app.Method,
		Multipart:     multipart.NewMultipart(app.Multipart),
		NoEncode:      getValue(app.Cfg.NoEncode),
		NoPager:       getValue(app.Cfg.NoPager),
		Output:        app.Output,
		OutputDir:     app.OutputDir,
		PrinterHandle: handle,
		Proxy:         app.Cfg.Proxy,
		QueryParams:   app.Cfg.QueryParams,
		Range:         app.Range,
		Redirects:     app.Cfg.Redirects,
		Timeout:       getValue(app.Cfg.Timeout),
		TLS:           getValue(app.Cfg.TLS),
		URL:           app.URL,
		Verbosity:     verbosity,
		XML:           app.XML,
	}
	status := fetch.Fetch(ctx, &req)
	os.Exit(status)
}

func handleCompletion(name string, args []string) error {
	shell := complete.GetShell(name)
	if shell == nil {
		return errShellNotSupported(name)
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stdout, shell.Register())
		return nil
	}

	os.Stdout.WriteString(complete.Complete(shell, args))
	return nil
}

// parse and merge any config file with the CLI app configuration.
func parseConfigFile(app *cli.App, p *core.Printer) error {
	file, err := config.GetFile(app.ConfigPath)
	if err != nil {
		return err
	}
	if file == nil {
		return nil
	}

	if app.URL != nil {
		hostCfg, ok := file.Hosts[app.URL.Hostname()]
		if ok {
			app.Cfg.Merge(hostCfg)
		}
	}

	app.Cfg.Merge(file.Global)

	if getVerbosity(app) >= core.LDebug {
		p.Set(core.Bold)
		p.WriteString("config")
		p.Reset()

		p.WriteString(": '")
		p.Set(core.Dim)
		p.WriteString(file.Path)
		p.Reset()
		p.WriteString("'\n\n")
		p.Flush()
	}

	return nil
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
	case 2:
		return core.VExtraVerbose
	default:
		return core.LDebug
	}
}

func checkForUpdate(ctx context.Context, p *core.Printer, dur time.Duration) {
	// Check the metadata file to see if we should start an async update.
	ok, err := update.ShouldAttemptUpdate(ctx, p, dur)
	if err != nil {
		msg := fmt.Sprintf("unable to check if update is needed: %s", err.Error())
		core.WriteWarningMsg(p, msg)
		return
	}
	if !ok {
		return
	}

	// Asynchronously start an update process.
	// Should we output a log here?
	path, err := os.Executable()
	if err != nil {
		return
	}
	_ = exec.Command(path, "--update", "--timeout=300").Start()
}

// writeCLIErr writes the provided CLI error to the Printer.
func writeCLIErr(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)

	p.WriteString("\nFor more information, try '")

	p.Set(core.Bold)
	p.WriteString("--help")
	p.Reset()

	p.WriteString("'.\n")
	p.Flush()
}

type errShellNotSupported string

func (err errShellNotSupported) Error() string {
	return fmt.Sprintf("completions not supported for shell '%s'", string(err))
}

func (err errShellNotSupported) PrintTo(p *core.Printer) {
	p.WriteString("completions not supported for shell '")
	p.Set(core.Bold)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("'")
}
