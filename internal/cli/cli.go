package cli

import (
	"fmt"
	"strings"

	"github.com/ryanfowler/fetch/internal/printer"
)

type CLI struct {
	Description    string
	ArgFn          func(s string) error
	Args           []Arguments
	Flags          []Flag
	ExclusiveFlags [][]string
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
	Values      []string
	IsSecret    bool
	IsSet       func() bool
	Fn          func(value string) error
}

func parse(cli *CLI, args []string) error {
	short := make(map[string]Flag)
	long := make(map[string]Flag)
	for _, flag := range cli.Flags {
		if flag.Short != "" {
			short[flag.Short] = flag
		}
		if flag.Long != "" {
			long[flag.Long] = flag
		}
		for _, alias := range flag.Aliases {
			if len(alias) == 1 {
				short[alias] = flag
			} else {
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
			value = arg[2:]
			arg = arg[len(arg)-1:]
		}

		if flag.Args == "" && value != "" {
			return nil, fmt.Errorf("option '-%s' does not take any arguments", c)
		}

		if flag.Args != "" && value == "" {
			if len(arg) > 1 {
				value = arg[1:]
				arg = arg[len(arg)-1:]
			} else if len(args) == 0 {
				return nil, fmt.Errorf("argument required for flag '-%s'", c)
			} else {
				value = args[0]
				args = args[1:]
			}
		}

		if err := flag.Fn(value); err != nil {
			return nil, err
		}

		arg = arg[1:]
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
		return nil, fmt.Errorf("flag '--%s' does not take any arguments", name)
	}

	if flag.Args != "" && value == "" {
		if len(args) == 0 {
			return nil, fmt.Errorf("argument required for flag '--%s'", name)
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

		return fmt.Errorf("flags '--%s' and '--%s' cannot be used together", lastSet, name)
	}
	return nil
}

func unknownFlagError(name string) error {
	return fmt.Errorf("unknown flag: '%s'", name)
}

func Parse(args []string) (*App, error) {
	app := NewApp()

	cli := app.CLI()
	err := parse(cli, args)
	if err != nil {
		return app, err
	}

	return app, nil
}

func printHelp(cli *CLI, p *printer.Printer) {
	p.WriteString(cli.Description)
	p.WriteString("\n\n")

	p.Set(printer.Bold)
	p.Set(printer.Underline)
	p.WriteString("Usage")
	p.Reset()
	p.WriteString(": ")

	p.Set(printer.Bold)
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

		p.Set(printer.Bold)
		p.Set(printer.Underline)
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

		p.Set(printer.Bold)
		p.Set(printer.Underline)
		p.WriteString("Options")
		p.Reset()
		p.WriteString(":\n")

		maxLen := maxFlagLength(cli.Flags)
		for _, flag := range cli.Flags {
			if flag.IsSecret {
				continue
			}

			p.Set(printer.Bold)
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

			if len(flag.Values) > 0 {
				p.WriteString(" [")
				p.WriteString(strings.Join(flag.Values, ", "))
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
		if f.IsSecret {
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
