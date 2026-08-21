package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/complete"
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/dnsinspect"
	"github.com/ryanfowler/fetch/internal/fetch"
	"github.com/ryanfowler/fetch/internal/format"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/pager"
	"github.com/ryanfowler/fetch/internal/tlsinspect"
	"github.com/ryanfowler/fetch/internal/update"
)

// verboseHelp is the detailed, Markdown-formatted reference shown by
// `fetch -v --help`. Embedding it keeps metadata commands offline and makes
// the output match the documentation shipped with the binary.
//
//go:embed docs/cli-reference.md
var verboseHelp []byte

func main() {
	// Cancel the context when one of the below signals are caught.
	ctx, cancel := context.WithCancelCause(context.Background())
	chSig := make(chan os.Signal, 1)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		sig := <-chSig
		signal.Stop(chSig)
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

	// Metadata-only commands should never be blocked by config errors or start
	// background update work. Valid config is still merged so presentation
	// settings like color and buildinfo formatting continue to apply.
	if app.Help || app.Version || app.BuildInfo {
		_, _ = parseConfigFile(app)
		status := handleMetadataCommand(ctx, app, core.NewHandle(app.Cfg.Color), os.Args[1:])
		os.Exit(statusForContext(ctx, status))
	}

	// Parse any config file with the CLI color setting for parse errors, then
	// recreate the handle after config values are merged.
	tmpHandle := core.NewHandle(app.Cfg.Color)
	configPath, err := parseConfigFile(app)
	if err != nil {
		p := tmpHandle.Stderr()
		core.WriteErrorMsg(p, err)
		os.Exit(1)
	}
	handle := core.NewHandle(app.Cfg.Color)
	if err := app.Cfg.Validate(); err != nil {
		p := handle.Stderr()
		core.WriteErrorMsg(p, err)
		os.Exit(1)
	}
	printConfigDebug(app, handle.Stderr(), configPath)

	// Start async update, if necessary.
	if !app.Update && !core.NoSelfUpdate && app.Cfg.AutoUpdate != nil && *app.Cfg.AutoUpdate >= 0 {
		checkForUpdate(ctx, handle.Stderr(), *app.Cfg.AutoUpdate, getValue(app.Cfg.Silent), update.NetworkConfig{
			CACerts:          app.Cfg.CACerts,
			ConnectTimeout:   getValue(app.Cfg.ConnectTimeout),
			ResolverEndpoint: app.Cfg.DNSEndpoint,
			DNSServer:        app.Cfg.DNSServer,
			Proxy:            app.Cfg.Proxy,
		})
	}

	// Attempt to update the current executable.
	verbosity := getVerbosity(app)
	if app.Update {
		if core.NoSelfUpdate {
			p := handle.Stderr()
			core.WriteErrorMsg(p, errSelfUpdateDisabled(core.PackageManager))
			os.Exit(1)
		}
		p := handle.Stderr()
		timeout := getValue(app.Cfg.Timeout)
		status := update.UpdateWithConfig(ctx, p, timeout, verbosity == core.VSilent, app.DryRun, update.NetworkConfig{
			CACerts:          app.Cfg.CACerts,
			ConnectTimeout:   getValue(app.Cfg.ConnectTimeout),
			ResolverEndpoint: app.Cfg.DNSEndpoint,
			DNSServer:        app.Cfg.DNSServer,
			Proxy:            app.Cfg.Proxy,
		})
		os.Exit(statusForContext(ctx, status))
	}

	// gRPC discovery can run offline when a local schema is provided.
	if app.URL == nil && app.HasGRPCDiscovery() && !app.HasProtoSchema() {
		p := handle.Stderr()
		writeCLIErr(p, errors.New("<URL> must be provided unless --proto-file or --proto-desc is set"))
		os.Exit(1)
	}

	// Otherwise, a URL must be provided.
	if app.URL == nil && !app.HasGRPCDiscovery() {
		p := handle.Stderr()
		writeCLIErr(p, errors.New("<URL> must be provided"))
		os.Exit(1)
	}

	// Handle --inspect-dns: resolve the URL hostname only, no HTTP request.
	if app.InspectDNS {
		os.Exit(statusForContext(ctx, inspectDNS(ctx, app, handle)))
	}

	// Handle --inspect-tls: perform TLS handshake only, no HTTP request.
	if app.InspectTLS {
		os.Exit(statusForContext(ctx, inspectTLS(ctx, app, handle)))
	}

	// Respond with an error if the selected proxy is used with HTTP/2 or
	// higher. This includes environment proxies, but respects NO_PROXY.
	if app.Cfg.HTTP >= core.HTTP2 {
		proxy, proxyErr := client.ProxyForURL(app.Cfg.Proxy, app.URL)
		if proxyErr != nil {
			p := handle.Stderr()
			writeCLIErr(p, proxyErr)
			os.Exit(1)
		}
		if proxy != nil {
			p := handle.Stderr()
			writeCLIErr(p, errors.New("a proxy can only be used with HTTP/1.1"))
			os.Exit(1)
		}
	}

	// Respond with an error if a unix socket is specified with HTTP/3.
	if app.UnixSocket != "" && app.Cfg.HTTP == core.HTTP3 {
		p := handle.Stderr()
		writeCLIErr(p, errors.New("cannot use a unix socket with HTTP/3.0"))
		os.Exit(1)
	}

	// Respond with an error if WebSocket is used with HTTP/3.
	if app.WS && app.Cfg.HTTP > core.HTTP1 {
		p := handle.Stderr()
		writeCLIErr(p, fmt.Errorf("cannot use WebSocket with %s", app.Cfg.HTTP.String()))
		os.Exit(1)
	}

	// Parse any client certificate configuration for mTLS.
	var clientCert *tls.Certificate
	clientCert, err = app.Cfg.ClientCert()
	if err != nil {
		p := handle.Stderr()
		writeCLIErr(p, err)
		os.Exit(1)
	}

	// Make the HTTP request using the parsed configuration.
	req := fetch.Request{
		AWSSigv4:         app.AWSSigv4,
		Basic:            app.Basic,
		Bearer:           app.Bearer,
		CACerts:          app.Cfg.CACerts,
		ClientCert:       clientCert,
		Clobber:          app.Clobber,
		ConnectTimeout:   getValue(app.Cfg.ConnectTimeout),
		Compression:      app.Cfg.Compress,
		Article:          app.Article,
		ContentType:      app.ContentType,
		Copy:             getValue(app.Cfg.Copy),
		Data:             app.Data,
		Digest:           app.Digest,
		Discard:          app.Discard,
		ResolverEndpoint: app.Cfg.DNSEndpoint,
		DNSServer:        app.Cfg.DNSServer,
		DryRun:           app.DryRun,
		ECH:              app.Cfg.ECH,
		Edit:             app.Edit,
		Form:             app.Form,
		Format:           app.Cfg.Format,
		GRPC:             app.GRPC,
		GRPCDescribe:     app.GRPCDescribe,
		GRPCList:         app.GRPCList,
		HAR:              app.HAR,
		Headers:          app.Cfg.Headers,
		HTTP:             app.Cfg.HTTP,
		IgnoreStatus:     getValue(app.Cfg.IgnoreStatus),
		Image:            app.Cfg.Image,
		Insecure:         getValue(app.Cfg.Insecure),
		Method:           app.Method,
		Multipart:        multipart.NewMultipart(app.Multipart),
		NoEncode:         getValue(app.Cfg.NoEncode),
		NoPager:          app.Cfg.Pager == core.PagerUnknown && getValue(app.Cfg.NoPager),
		Pager:            app.Cfg.Pager,
		Output:           app.Output,
		PrinterHandle:    handle,
		ProtoDesc:        app.ProtoDesc,
		ProtoFiles:       app.ProtoFiles,
		ProtoImports:     app.ProtoImports,
		Proxy:            app.Cfg.Proxy,
		QueryParams:      app.Cfg.QueryParams,
		Range:            app.Range,
		Redirects:        app.Cfg.Redirects,
		RemoteHeaderName: app.RemoteHeaderName,
		RemoteName:       app.RemoteName,
		Retry:            getValue(app.Cfg.Retry),
		RetryDelay:       getValue(app.Cfg.RetryDelay),
		Session:          getValue(app.Cfg.Session),
		Timeout:          getValue(app.Cfg.Timeout),
		Timing:           getValue(app.Cfg.Timing),
		TLSMax:           getValue(app.Cfg.TLSMax),
		TLSMin:           getValue(app.Cfg.TLSMin),
		UnixSocket:       app.UnixSocket,
		URL:              app.URL,
		Verbosity:        verbosity,
		WS:               app.WS,
		WSInteractive:    app.WSInteractive,
		SchemelessURL:    app.SchemelessURL,
	}
	if app.HasGRPCDiscovery() {
		status := fetch.DiscoverGRPC(ctx, &req)
		os.Exit(statusForContext(ctx, status))
	}
	status := fetch.Fetch(ctx, &req)
	os.Exit(statusForContext(ctx, status))
}

func handleMetadataCommand(ctx context.Context, app *cli.App, handle *core.Handle, args []string) int {
	// Help is intentionally split into a concise command synopsis and a
	// detailed Markdown reference. Only an explicitly supplied -v/--verbose
	// changes help mode; a config default must not make scripts unexpectedly
	// receive a large document.
	if app.Help {
		if helpVerboseRequested(args, app) {
			return printVerboseHelp(ctx, app)
		}
		printConciseHelp(app, handle.Stdout())
		return flushMetadata(handle)
	}

	if app.Version {
		p := handle.Stdout()
		p.WriteString("fetch ")
		p.WriteString(core.Version)
		p.WriteString("\n")
		return flushMetadata(handle)
	}

	if app.BuildInfo {
		p := handle.Stdout()
		info := core.GetBuildInfo(getValue(app.Cfg.Verbosity) > 0)
		if app.Cfg.Format != core.FormatOff {
			if err := format.FormatJSON(info, p); err != nil {
				return handleMetadataOutputError(handle, err)
			}
		} else {
			if _, err := p.Write(info); err != nil {
				return handleMetadataOutputError(handle, err)
			}
		}
		return flushMetadata(handle)
	}
	return 0
}

func printConciseHelp(app *cli.App, p *core.Printer) {
	p.WriteString("fetch is a modern HTTP(S) client for the command line\n\n")
	p.Set(core.Bold)
	p.Set(core.Underline)
	p.WriteString("Usage")
	p.Reset()
	p.WriteString(": fetch [OPTIONS] [URL]\n\n")
	p.WriteString("Common options:\n")
	p.WriteString("  --help, -h       Show this concise help\n")
	p.WriteString("  --verbose, -v    Increase output detail\n")
	p.WriteString("  --version, -V    Print the version\n")
	p.WriteString("  --buildinfo      Print build information\n")
	p.WriteString("  --config PATH    Read a configuration file\n")
	p.WriteString("  --complete SHELL Print shell completion\n")
	p.WriteString("\nRequest and output options:\n")
	p.WriteString("  --method METHOD  Set the HTTP method\n")
	p.WriteString("  --header NAME:VALUE  Add a request header\n")
	p.WriteString("  --data VALUE     Send a request body\n")
	p.WriteString("  --format MODE    Select response formatting\n")
	p.WriteString("  --article        Extract readable page content\n")
	p.WriteString("  --output PATH    Write the response to a file\n")
	p.WriteString("  --pager MODE     Select pager behavior\n")
	p.WriteString("  --compress MODE  Select response compression\n")
	p.WriteString("\nNetworking and diagnostics:\n")
	p.WriteString("  --http VERSION   Select HTTP/1.1, HTTP/2, or HTTP/3\n")
	p.WriteString("  --proxy PROXY    Use a proxy\n")
	p.WriteString("  --timeout SECONDS  Set the request timeout\n")
	p.WriteString("  --inspect-dns    Inspect DNS resolution\n")
	p.WriteString("  --inspect-tls   Inspect the TLS handshake\n")
	p.WriteString("  --grpc           Use gRPC mode\n")
	if runtime.GOOS != "windows" {
		p.WriteString("  --unix PATH      Use a Unix socket\n")
	}
	p.WriteString("\nUse `fetch -v --help` for the full Markdown reference.\n")
}

func printVerboseHelp(ctx context.Context, app *cli.App) int {
	useColor := app.Cfg.Color == core.ColorOn ||
		(app.Cfg.Color != core.ColorOff && core.IsStdoutTerm)
	p := core.TestPrinter(useColor)
	if err := format.FormatMarkdown(verboseHelp, p); err != nil {
		return handleMetadataOutputError(core.NewHandle(app.Cfg.Color), err)
	}
	data := append([]byte(nil), p.Bytes()...)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	mode := app.Cfg.Pager
	if app.Cfg.Pager == core.PagerUnknown && getValue(app.Cfg.NoPager) {
		mode = core.PagerOff
	}
	if err := pager.WriteTextContext(ctx, data, mode, core.IsStdoutTerm); err != nil {
		if code, ok := core.SignalExitCode(context.Cause(ctx)); ok {
			return code
		}
		return handleMetadataOutputError(core.NewHandle(app.Cfg.Color), err)
	}
	return 0
}

func flushMetadata(handle *core.Handle) int {
	if err := handle.Stdout().Flush(); err != nil {
		if core.IsBrokenPipe(err) {
			return 0
		}
		return handleMetadataOutputError(handle, err)
	}
	return 0
}

func handleMetadataOutputError(handle *core.Handle, err error) int {
	if core.IsBrokenPipe(err) {
		return 0
	}
	core.WriteErrorMsg(handle.Stderr(), err)
	return 1
}

func helpVerboseRequested(args []string, app *cli.App) bool {
	var help, verbose bool
	options := app.CLI().Options()
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "--") {
			name, _, hasValue := strings.Cut(arg[2:], "=")
			flag, known := options.Lookup(name)
			if name == "help" {
				help = true
			} else if name == "verbose" {
				verbose = true
			}
			if known && flag.Args != "" && !hasValue {
				if !flag.OptionalArg {
					skipNext = true
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			shorts := arg[1:]
			for i := 0; i < len(shorts); i++ {
				name := shorts[i : i+1]
				flag, known := options.Lookup(name)
				if name == "h" {
					help = true
				} else if name == "v" {
					verbose = true
				}
				if known && flag.Args != "" {
					// The remainder of a short cluster is the value. If
					// there is no remainder, the next argument is the value.
					if i+1 == len(shorts) && !flag.OptionalArg {
						skipNext = true
					}
					break
				}
			}
		}
	}
	return help && verbose
}

func statusForContext(ctx context.Context, status int) int {
	if code, ok := core.SignalExitCode(context.Cause(ctx)); ok {
		return code
	}
	return status
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
func parseConfigFile(app *cli.App) (string, error) {
	file, err := config.GetFile(app.ConfigPath)
	if err != nil {
		return "", err
	}
	if file == nil {
		return "", nil
	}

	if app.URL != nil {
		hostname := app.URL.Hostname()
		if hostCfg := file.HostConfig(hostname); hostCfg != nil {
			app.RecordConfigKeys(app.Cfg.Merge(hostCfg), cli.SourceHostConfig)
		}
	}

	app.RecordConfigKeys(app.Cfg.Merge(file.Global), cli.SourceGlobalConfig)

	return file.Path, nil
}

func printConfigDebug(app *cli.App, p *core.Printer, path string) {
	if path == "" {
		return
	}
	if getVerbosity(app) >= core.VDebug {
		p.WriteInfoPrefix()
		p.Set(core.Bold)
		p.Set(core.Yellow)
		p.WriteString("Config")
		p.Reset()

		p.WriteString(": '")
		p.Set(core.Dim)
		p.WriteString(path)
		p.Reset()
		p.WriteString("'\n")
		p.WriteInfoPrefix()
		p.WriteString("\n")
		p.Flush()
	}
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
		return core.VDebug
	}
}

func checkForUpdate(ctx context.Context, p *core.Printer, dur time.Duration, silent bool, network update.NetworkConfig) {
	// A custom CA is represented as parsed certificates rather than reusable
	// paths. Do not silently start a background updater that would lose that
	// trust policy; explicit --update still carries the certificates directly.
	if len(network.CACerts) > 0 || (network.Proxy != nil && network.Proxy.User != nil) {
		// Parsed certificates and proxy credentials are intentionally not
		// copied into a detached child through argv or the environment.
		return
	}
	// Check the metadata file to see if we should start an async update.
	ok, err := update.ShouldAttemptUpdate(ctx, p, dur)
	if err != nil {
		msg := fmt.Sprintf("unable to check if update is needed: %s", err.Error())
		core.WriteWarningMsgIf(p, msg, silent)
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
	args := []string{"--update", "--timeout=300", "--silent"}
	if network.ResolverEndpoint != nil {
		if endpointURL := network.ResolverEndpoint.URL(); endpointURL != nil {
			args = append(args, "--dns-server", endpointURL.String())
		}
	}
	if network.Proxy != nil {
		args = append(args, "--proxy", network.Proxy.String())
	}
	if network.ConnectTimeout > 0 {
		args = append(args, "--connect-timeout", strconv.FormatFloat(network.ConnectTimeout.Seconds(), 'f', -1, 64))
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Start()
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

type inspectionMode string

const (
	inspectionDNS inspectionMode = "--inspect-dns"
	inspectionTLS inspectionMode = "--inspect-tls"
)

func ignoredInspectionFlags(app *cli.App, mode inspectionMode) []string {
	optionMode := cli.ModeTLSInspection
	if mode == inspectionDNS {
		optionMode = cli.ModeDNSInspection
	}
	return app.CLI().Options().Ignored(optionMode, app.OptionWasExplicit)
}

func warnIgnoredInspectionFlags(p *core.Printer, mode inspectionMode, ignored []string, silentMode ...bool) {
	if len(ignored) == 0 {
		return
	}
	silent := len(silentMode) > 0 && silentMode[0]
	core.WriteWarningMsgIf(p, string(mode)+" ignores: "+strings.Join(ignored, ", "), silent)
}

// inspectDNS performs DNS resolution only and renders the resolved records.
func inspectDNS(ctx context.Context, app *cli.App, handle *core.Handle) int {
	p := handle.Stderr()

	warnIgnoredInspectionFlags(p, inspectionDNS, ignoredInspectionFlags(app, inspectionDNS), getValue(app.Cfg.Silent))

	return dnsinspect.Inspect(ctx, p, &dnsinspect.Config{
		Endpoint:  app.Cfg.DNSEndpoint,
		DNSServer: app.Cfg.DNSServer,
		Proxy:     app.Cfg.Proxy,
		CACerts:   app.Cfg.CACerts,
		Insecure:  getValue(app.Cfg.Insecure),
		TLSMin:    getValue(app.Cfg.TLSMin),
		TLSMax:    getValue(app.Cfg.TLSMax),
		Timeout:   getValue(app.Cfg.Timeout),
		URL:       app.URL,
		Silent:    getValue(app.Cfg.Silent),
	})
}

type errSelfUpdateDisabled string

func (err errSelfUpdateDisabled) Error() string {
	return "self-update is disabled for this installation; please update using " + string(err)
}

func (err errSelfUpdateDisabled) PrintTo(p *core.Printer) {
	p.WriteString("self-update is disabled for this installation; please update using ")
	p.Set(core.Bold)
	p.WriteString(string(err))
	p.Reset()

	if err == "Homebrew" {
		p.WriteString("\n\n  ")
		p.Set(core.Dim)
		p.WriteString("brew upgrade ryanfowler/tap/fetch")
		p.Reset()
	}
}

// inspectTLS performs a TLS-only handshake and renders the certificate chain.
func inspectTLS(ctx context.Context, app *cli.App, handle *core.Handle) int {
	p := handle.Stderr()

	// Default scheme: non-loopback defaults to HTTPS, loopback is rejected.
	if app.URL.Scheme == "" {
		hostname := app.URL.Hostname()
		if client.IsLoopback(hostname) {
			writeCLIErr(p, errors.New("--inspect-tls requires an HTTPS URL"))
			return 1
		}
		app.URL.Scheme = "https"
	}
	switch app.URL.Scheme {
	case "https", "wss":
		// OK: these schemes use TLS.
	default:
		writeCLIErr(p, errors.New("--inspect-tls requires an HTTPS URL"))
		return 1
	}

	warnIgnoredInspectionFlags(p, inspectionTLS, ignoredInspectionFlags(app, inspectionTLS), getValue(app.Cfg.Silent))

	// Parse client certificate for mTLS.
	clientCert, err := app.Cfg.ClientCert()
	if err != nil {
		writeCLIErr(p, err)
		return 1
	}

	return tlsinspect.Inspect(ctx, p, &tlsinspect.Config{
		CACerts:          app.Cfg.CACerts,
		ClientCert:       clientCert,
		ResolverEndpoint: app.Cfg.DNSEndpoint,
		DNSServer:        app.Cfg.DNSServer,
		HTTP:             app.Cfg.HTTP,
		Insecure:         getValue(app.Cfg.Insecure),
		TLSMax:           getValue(app.Cfg.TLSMax),
		TLSMin:           getValue(app.Cfg.TLSMin),
		Timeout:          getValue(app.Cfg.Timeout),
		URL:              app.URL,
	})
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
