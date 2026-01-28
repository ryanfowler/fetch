package complete

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/core"
)

// Complete returns the completions output for the provided shell and arguments.
func Complete(shell Shell, args []string) string {
	if len(args) <= 1 {
		return shell.Complete(nil)
	}
	args = args[1:]

	flags := getFlags()
	short, long := getFlagMaps(flags)

	for len(args) > 0 {
		arg := args[0]
		args = args[1:]

		if !strings.HasPrefix(arg, "-") {
			// Not a flag, skip completions.
			continue
		}

		// If last argument, attempt completion for it.
		if len(args) == 0 {
			if arg == "-" || arg == "--" {
				return shell.Complete(allFlags(flags))
			}

			// Complete long flag.
			after, ok := strings.CutPrefix(arg, "--")
			if ok {
				return shell.Complete(completeLongFlag(flags, long, after))
			}

			// Complete short flag.
			return shell.Complete(completeShortFlag(flags, short, arg[1:]))
		}

		// Parse long flag.
		after, ok := strings.CutPrefix(arg, "--")
		if ok {
			name, _, hasVal := strings.Cut(after, "=")
			flag, ok := long[name]
			if !ok {
				continue
			}
			if flag.Args == "" {
				// Skip the arg if no arguments are expected.
				continue
			}
			if hasVal {
				// arg=param, we can continue.
				continue
			}

			// Check if the argument to this flag needs completion.
			if len(args) == 1 {
				value := args[0]
				return shell.Complete(completeValue(flag, "", value))
			}

			// Otherwise, we need to skip the next argument.
			args = args[1:]
			continue
		}

		// Parse short flag.
		values := arg[1:]
		for i := range values {
			name := values[i : i+1]
			flag, ok := short[name]
			if !ok {
				// Unknown flag, skip the argument.
				break
			}
			if flag.Args == "" {
				// Flag doesn't take an argument, continue.
				continue
			}
			if i != len(values)-1 {
				// Flag takes an argument, and value is inline.
				// E.g. -mGET or -m=GET
				break
			}

			// Check if the argument to this flag needs completion.
			if len(args) == 1 {
				value := args[0]
				return shell.Complete(completeValue(flag, "", value))
			}

			// Otherwise, we need to skip the next argument.
			args = args[1:]
			break
		}
	}

	return shell.Complete(nil)
}

func getFlags() []cli.Flag {
	var app cli.App
	flags := app.CLI().Flags

	out := make([]cli.Flag, 0, len(flags))
	for _, flag := range flags {
		if flag.IsHidden {
			continue
		}
		out = append(out, flag)
	}
	return out
}

func getFlagMaps(flags []cli.Flag) (map[string]cli.Flag, map[string]cli.Flag) {
	short := make(map[string]cli.Flag)
	long := make(map[string]cli.Flag)
	for _, flag := range flags {
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
	return short, long
}

func completeLongFlag(flags []cli.Flag, long map[string]cli.Flag, value string) []core.KeyVal[string] {
	if key, val, ok := strings.Cut(value, "="); ok {
		flag, ok := long[key]
		if !ok {
			return nil
		}
		prefix := "--" + key + "="
		return completeValue(flag, prefix, val)
	}

	var out []core.KeyVal[string]
	for _, flag := range flags {
		if strings.HasPrefix(flag.Long, value) {
			out = append(out, core.KeyVal[string]{
				Key: "--" + flag.Long,
				Val: flag.Description,
			})
		}
	}
	return out
}

func completeShortFlag(flags []cli.Flag, short map[string]cli.Flag, value string) []core.KeyVal[string] {
	values := make(map[string]struct{})
	for i := range value {
		name := value[i : i+1]
		flag, ok := short[name]
		if !ok {
			return nil
		}
		if flag.Args != "" {
			prefix := "-" + value[:i+1]
			val := value[i+1:]
			if len(val) > 0 && val[0] == '=' {
				prefix += "="
				val = val[1:]
			}
			return completeValue(flag, prefix, val)
		}
		values[value[i:i+1]] = struct{}{}
	}

	var out []core.KeyVal[string]
	for _, flag := range flags {
		if flag.Short == "" {
			continue
		}
		if _, ok := values[flag.Short]; ok {
			continue
		}
		out = append(out, core.KeyVal[string]{
			Key: "-" + value + flag.Short,
			Val: flag.Description,
		})
	}
	return out
}

func completeValue(flag cli.Flag, prefix, value string) []core.KeyVal[string] {
	if flag.Args == "" {
		// This flag doesn't take any arguments.
		return nil
	}

	if len(flag.Values) > 0 {
		// There are specific values for this flag.
		var kvs []core.KeyVal[string]
		for _, fv := range flag.Values {
			if strings.HasPrefix(fv.Key, value) {
				kvs = append(kvs, core.KeyVal[string]{
					Key: prefix + fv.Key,
					Val: fv.Val,
				})
			}
		}
		return kvs
	}

	switch flag.Long {
	case "ca-cert", "cert", "config", "key", "output", "proto-desc", "proto-file", "proto-import", "unix":
		return completePath(prefix, value)
	case "data", "json", "xml":
		path, ok := strings.CutPrefix(value, "@")
		if ok {
			return completePath(prefix+"@", path)
		}
	case "multipart":
		key, val, ok := strings.Cut(value, "=")
		if ok && strings.HasPrefix(val, "@") {
			return completePath(prefix+key+"=@", val[1:])
		}
	}

	return nil
}

func completePath(prefix, orig string) []core.KeyVal[string] {
	path := os.ExpandEnv(orig)

	if orig == "~" {
		// Special case when path is '~'.
		return []core.KeyVal[string]{{Key: prefix + "~/", Val: "File"}}
	}

	if len(path) >= 2 && path[0] == '~' && path[1] == os.PathSeparator {
		// Expand '~' to the user's home directory.
		home, err := os.UserHomeDir()
		if err == nil {
			path = home + path[1:]
		}
	}

	// Read all files in the base directory.
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	// Parse the path's base to know what to filter on.
	var base string
	if path != "" && !strings.HasSuffix(path, string(os.PathSeparator)) {
		base = filepath.Base(path)
	}

	var out []core.KeyVal[string]
	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden files when listing all files in a directory.
		if base == "" && strings.HasPrefix(name, ".") {
			continue
		}

		// Skip any files that don't start with the base file path.
		if !strings.HasPrefix(name, base) {
			continue
		}

		// Format the completion using the original file path.
		file := filepath.Join(filepath.Dir(orig), name)
		if entry.IsDir() {
			file = file + string(os.PathSeparator)
		}
		out = append(out, core.KeyVal[string]{
			Key: prefix + file,
			Val: "File",
		})
	}
	return out
}

func allFlags(flags []cli.Flag) []core.KeyVal[string] {
	kvs := make([]core.KeyVal[string], 0, len(flags))
	for _, flag := range flags {
		if flag.IsHidden {
			continue
		}
		kvs = append(kvs, core.KeyVal[string]{
			Key: "--" + flag.Long,
			Val: flag.Description,
		})
	}
	return kvs
}
