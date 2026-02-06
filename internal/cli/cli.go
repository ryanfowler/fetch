package cli

import (
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

var unixOS = []string{"linux", "darwin", "freebsd", "openbsd", "netbsd", "aix", "dragonfly", "solaris"}

type CLI struct {
	Description    string
	ArgFn          func(s string) error
	Args           []Arguments
	Flags          []Flag
	ExclusiveFlags [][]string
	RequiredFlags  []core.KeyVal[[]string]
}

type Arguments struct {
	Name        string
	Description string
}

type Flag struct {
	Short       string
	Long        string
	Aliases     []string
	Args        string
	Description string
	Default     string
	Values      []core.KeyVal[string]
	HideValues  bool
	IsHidden    bool
	IsSet       func() bool
	OS          []string
	Fn          func(value string) error
}

func parse(cli *CLI, args []string) error {
	short := make(map[string]Flag)
	long := make(map[string]Flag)
	for _, flag := range cli.Flags {
		if !isFlagVisibleOnOS(flag.OS) {
			continue
		}

		if flag.Short != "" {
			assertFlagNotExists(short, flag.Short)
			short[flag.Short] = flag
		}
		if flag.Long != "" {
			assertFlagNotExists(long, flag.Long)
			long[flag.Long] = flag
		}

		for _, alias := range flag.Aliases {
			if len(alias) == 1 {
				assertFlagNotExists(short, alias)
				short[alias] = flag
			} else {
				assertFlagNotExists(long, alias)
				long[alias] = flag
			}
		}
	}

	exclusives := make(map[string][][]string)
	for _, fs := range cli.ExclusiveFlags {
		for _, f := range fs {
			exclusives[f] = append(exclusives[f], fs)
		}
	}

	var err error
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]

		// Parse argument.
		if len(arg) <= 1 || arg[0] != '-' {
			err = cli.ArgFn(arg)
			if err != nil {
				return err
			}
			continue
		}

		// Parse short flag(s).
		if arg[1] != '-' {
			args, err = parseShortFlag(arg, args, short)
			if err != nil {
				return err
			}
			continue
		}

		// Parse long flag.
		if len(arg) > 2 {
			args, err = parseLongFlag(arg, args, long)
			if err != nil {
				return err
			}
			continue
		}

		// "--" means consider everything else arguments.
		err = cli.ArgFn("--")
		if err != nil {
			return err
		}
		for _, arg := range args {
			err = cli.ArgFn(arg)
			if err != nil {
				return err
			}
		}
		break
	}

	// Check exclusive flags.
	for _, exc := range cli.ExclusiveFlags {
		err = validateExclusives(exc, long)
		if err != nil {
			return err
		}
	}

	// Check required flags.
	for _, req := range cli.RequiredFlags {
		err = validateRequired(req, long)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseShortFlag(arg string, args []string, short map[string]Flag) ([]string, error) {
	arg = arg[1:]

	for arg != "" {
		c := arg[:1]
		flag, exists := short[c]
		if !exists {
			return nil, unknownFlagError("-" + c)
		}

		var value string
		if len(arg) >= 2 && arg[1] == '=' {
			// -f=val
			value = arg[2:]
			arg = ""
			if flag.Args == "" {
				return nil, flagNoArgsError("-" + c)
			}
		} else if flag.Args != "" {
			if len(arg) > 1 {
				// -fval
				value = arg[1:]
			} else if len(args) > 0 {
				// -f val
				value = args[0]
				args = args[1:]
			} else {
				return nil, argRequiredError("-" + c)
			}
			arg = ""
		} else {
			arg = arg[1:]
		}

		if err := flag.Fn(value); err != nil {
			return nil, err
		}
	}

	return args, nil
}

func parseLongFlag(arg string, args []string, long map[string]Flag) ([]string, error) {
	name, value, ok := strings.Cut(arg[2:], "=")

	flag, exists := long[name]
	if !exists {
		return nil, unknownFlagError("--" + name)
	}

	if (ok || value != "") && flag.Args == "" {
		return nil, flagNoArgsError("--" + name)
	}

	if flag.Args != "" && value == "" {
		if len(args) == 0 {
			return nil, argRequiredError("--" + name)
		}

		value = args[0]
		args = args[1:]
	}

	if err := flag.Fn(value); err != nil {
		return nil, err
	}

	return args, nil
}

func validateExclusives(exc []string, long map[string]Flag) error {
	var lastSet string
	for _, name := range exc {
		flag := long[name]
		if !flag.IsSet() {
			continue
		}

		if lastSet == "" {
			lastSet = name
			continue
		}

		return newExclusiveFlagsError(lastSet, name)
	}
	return nil
}

func validateRequired(req core.KeyVal[[]string], long map[string]Flag) error {
	flag := long[req.Key]
	if !flag.IsSet() {
		return nil
	}

	// Check if ANY of the required flags is set (OR logic).
	for _, required := range req.Val {
		requiredFlag := long[required]
		if requiredFlag.IsSet() {
			return nil
		}
	}

	// None of the required flags are set.
	return newRequiredFlagError(req.Key, req.Val)
}

func isFlagVisibleOnOS(flagOS []string) bool {
	return len(flagOS) == 0 || slices.Contains(flagOS, runtime.GOOS)
}

func Parse(args []string) (*App, error) {
	var app App

	cli := app.CLI()
	err := parse(cli, args)
	if err != nil {
		return &app, err
	}

	if err := app.validateWSExclusives(); err != nil {
		return &app, err
	}

	return &app, nil
}

// validateWSExclusives checks that ws:// / wss:// scheme is not combined
// with incompatible flags.
func (a *App) validateWSExclusives() error {
	if !a.WS {
		return nil
	}

	type flagCheck struct {
		name  string
		isSet bool
	}
	conflicts := []flagCheck{
		{"grpc", a.GRPC},
		{"form", len(a.Form) > 0},
		{"multipart", len(a.Multipart) > 0},
		{"xml", a.xmlSet},
		{"edit", a.Edit},
	}

	// The URL scheme was rewritten from ws->http / wss->https during
	// parsing, so reverse the mapping for the error message.
	scheme := "ws"
	if a.URL != nil && a.URL.Scheme == "https" {
		scheme = "wss"
	}

	for _, c := range conflicts {
		if c.isSet {
			return schemeExclusiveError{scheme: scheme, flag: c.name}
		}
	}
	return nil
}

func printHelp(cli *CLI, p *core.Printer) {
	p.WriteString(cli.Description)
	p.WriteString("\n\n")

	p.Set(core.Bold)
	p.Set(core.Underline)
	p.WriteString("Usage")
	p.Reset()
	p.WriteString(": ")

	p.Set(core.Bold)
	p.WriteString("fetch")
	p.Reset()

	if len(cli.Flags) > 0 {
		p.WriteString(" [OPTIONS]")
	}

	for _, arg := range cli.Args {
		p.WriteString(" [")
		p.WriteString(arg.Name)
		p.WriteString("]")
	}
	p.WriteString("\n")

	if len(cli.Args) > 0 {
		p.WriteString("\n")

		p.Set(core.Bold)
		p.Set(core.Underline)
		p.WriteString("Arguments")
		p.Reset()
		p.WriteString(":\n")

		for _, arg := range cli.Args {
			p.WriteString("  [")
			p.WriteString(arg.Name)
			p.WriteString("]  ")
			p.WriteString(arg.Description)
			p.WriteString("\n")
		}
	}

	if len(cli.Flags) > 0 {
		p.WriteString("\n")

		p.Set(core.Bold)
		p.Set(core.Underline)
		p.WriteString("Options")
		p.Reset()
		p.WriteString(":\n")

		maxLen := maxFlagLength(cli.Flags)
		for _, flag := range cli.Flags {
			if flag.IsHidden {
				continue
			}
			if !isFlagVisibleOnOS(flag.OS) {
				continue
			}

			p.Set(core.Bold)
			p.WriteString("  ")

			if flag.Short == "" {
				p.WriteString("    ")
			} else {
				p.WriteString("-")
				p.WriteString(flag.Short)
				p.WriteString(", ")
			}

			p.WriteString("--")
			p.WriteString(flag.Long)
			p.Reset()

			if flag.Args != "" {
				p.WriteString(" <")
				p.WriteString(flag.Args)
				p.WriteString(">")
			}

			p.WriteString("  ")
			for range maxLen - flagLength(flag) {
				p.WriteString(" ")
			}

			p.WriteString(flag.Description)

			if !flag.HideValues && len(flag.Values) > 0 {
				p.WriteString(" [")
				for i, kv := range flag.Values {
					if i > 0 {
						p.WriteString(", ")
					}
					p.WriteString(kv.Key)
				}
				p.WriteString("]")
			}

			if flag.Default != "" {
				p.WriteString(" [default: ")
				p.WriteString(flag.Default)
				p.WriteString("]")
			}

			p.WriteString("\n")
		}
	}
}

func maxFlagLength(fs []Flag) int {
	var out int
	for _, f := range fs {
		if f.IsHidden {
			continue
		}
		len := flagLength(f)
		if len > out {
			out = len
		}
	}
	return out
}

func flagLength(f Flag) int {
	out := len(f.Long)
	if f.Args != "" {
		out += 3 + len(f.Args)
	}
	return out
}

func assertFlagNotExists(m map[string]Flag, value string) {
	if _, ok := m[value]; ok {
		panic(fmt.Sprintf("flag '%s' defined multiple times", value))
	}
}
