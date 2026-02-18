package cli

import "github.com/ryanfowler/fetch/internal/core"

// boolFlag creates a Flag that sets a bool to true when present.
func boolFlag(target *bool, long, short, desc string) Flag {
	return Flag{
		Long:        long,
		Short:       short,
		Description: desc,
		IsSet: func() bool {
			return *target
		},
		Fn: func(string) error {
			*target = true
			return nil
		},
	}
}

// ptrBoolFlag creates a Flag that sets a *bool pointer to &true when present.
func ptrBoolFlag(target **bool, long, short, desc string) Flag {
	return Flag{
		Long:        long,
		Short:       short,
		Description: desc,
		IsSet: func() bool {
			return *target != nil
		},
		Fn: func(string) error {
			*target = new(true)
			return nil
		},
	}
}

// stringFlag creates a Flag that stores a string value.
func stringFlag(target *string, long, short, args, desc string) Flag {
	return Flag{
		Long:        long,
		Short:       short,
		Args:        args,
		Description: desc,
		IsSet: func() bool {
			return *target != ""
		},
		Fn: func(value string) error {
			*target = value
			return nil
		},
	}
}

// cfgFlag creates a Flag that delegates to an isSet check and a parse function.
func cfgFlag(long, short, args, desc string, isSet func() bool, parse func(string) error) Flag {
	return Flag{
		Long:        long,
		Short:       short,
		Args:        args,
		Description: desc,
		IsSet:       isSet,
		Fn:          parse,
	}
}

// WithAliases adds aliases to the Flag.
func (f Flag) WithAliases(aliases ...string) Flag {
	f.Aliases = aliases
	return f
}

// WithValues sets the accepted values for the Flag.
func (f Flag) WithValues(values []core.KeyVal[string]) Flag {
	f.Values = values
	return f
}

// WithHideValues hides the accepted values from help output.
func (f Flag) WithHideValues() Flag {
	f.HideValues = true
	return f
}

// WithDefault sets the default value shown in help.
func (f Flag) WithDefault(def string) Flag {
	f.Default = def
	return f
}

// WithHidden marks the flag as hidden from help output.
func (f Flag) WithHidden(hidden bool) Flag {
	f.IsHidden = hidden
	return f
}

// WithOS restricts the flag to specific operating systems.
func (f Flag) WithOS(os []string) Flag {
	f.OS = os
	return f
}
