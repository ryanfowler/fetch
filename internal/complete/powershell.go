package complete

import (
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// PowerShell implements native completion registration for PowerShell. The
// completion protocol remains the same as the other shells: fetch receives the
// command words and returns one candidate per line, with an optional tab and
// description.
type PowerShell struct{}

func (p PowerShell) Name() string { return "powershell" }

func (p PowerShell) Register() string {
	return `Register-ArgumentCompleter -Native -CommandName fetch -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $elements = @($commandAst.CommandElements |
    Where-Object { $_.Extent.EndOffset -le $cursorPosition } |
    ForEach-Object { $_.Extent.Text })
  if ($elements.Count -eq 0) { $elements = @('fetch') }
  # Keep only tokens before the cursor. A token containing the cursor is the
  # current word and is supplied separately below; a trailing space leaves the
  # previous token in this list and supplies an empty current word.
  if ($elements.Count -gt 1 -and $wordToComplete -ne '' -and
      $elements[$elements.Count - 1] -eq $wordToComplete) {
    if ($elements.Count -eq 2) { $elements = @($elements[0]) }
    else { $elements = $elements[0..($elements.Count - 2)] }
  }
  $args = @('--complete=powershell', '--') + $elements + $wordToComplete
  & fetch @args | ForEach-Object {
    $parts = $_ -split ([char]9), 2
    $description = if ($parts.Count -eq 2) { $parts[1] } else { $parts[0] }
    [System.Management.Automation.CompletionResult]::new($parts[0], $parts[0], 'ParameterValue', $description)
  }
}`
}

func (p PowerShell) Complete(vals []core.KeyVal[string]) string {
	var sb strings.Builder
	for _, kv := range vals {
		// PowerShell cannot read a candidate with a control character
		// from one line, so skip it.
		if strings.ContainsFunc(kv.Key, isControl) {
			continue
		}
		// PowerShell inserts a candidate into the command line as it is.
		sb.WriteString(powerShellQuote(kv.Key))
		if kv.Val != "" {
			sb.WriteByte('\t')
			sb.WriteString(kv.Val)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// powerShellSingleQuotes holds the characters that PowerShell reads as a
// single quote: the ASCII quote and four Unicode quotes.
const powerShellSingleQuotes = "'\u2018\u2019\u201a\u201b"

// powerShellQuote returns s as a single-quoted PowerShell string when it
// contains a character that PowerShell would interpret, such as "$", "@",
// a space, or a quote. Each single quote character in s is doubled, which
// is how PowerShell escapes it inside a single-quoted string.
func powerShellQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"$`;&|<>(){}@#,"+powerShellSingleQuotes) {
		return s
	}
	var sb strings.Builder
	sb.WriteByte('\'')
	for _, r := range s {
		if strings.ContainsRune(powerShellSingleQuotes, r) {
			sb.WriteRune(r)
		}
		sb.WriteRune(r)
	}
	sb.WriteByte('\'')
	return sb.String()
}
