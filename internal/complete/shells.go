package complete

import (
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Shell represents a supported shell for completions.
type Shell interface {
	Name() string
	Register() string
	Complete([]core.KeyVal) string
}

// GetShell returns the shell matching the provided name. If no shell matches,
// nil is returned.
func GetShell(name string) Shell {
	switch name {
	case "fish":
		return Fish{}
	case "zsh":
		return Zsh{}
	default:
		return nil
	}
}

type Fish struct{}

func (f Fish) Name() string {
	return "fish"
}

func (f Fish) Register() string {
	return `complete --keep-order --exclusive --command fetch --arguments "(fetch --complete=fish -- (commandline --current-process --tokens-expanded --cut-at-cursor) (commandline --cut-at-cursor --current-token))"`
}

func (f Fish) Complete(vals []core.KeyVal) string {
	var sb strings.Builder
	for _, kv := range vals {
		sb.WriteString(kv.Key)
		if kv.Val != "" {
			sb.WriteByte('\t')
			sb.WriteString(kv.Val)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

type Zsh struct{}

func (z Zsh) Name() string {
	return "zsh"
}

func (z Zsh) Register() string {
	return `# Completion function for the 'fetch' command
_fetch_complete() {
  # Array of tokens before the current word
  local -a prev_tokens
  local current_token
  prev_tokens=("${words[@]:0:$CURRENT-1}")
  current_token=${words[$CURRENT]}

  # Call fetch and split its output into an array of lines
  local -a completions=("${(@f)$(fetch --complete=zsh -- "${prev_tokens[@]}" "${current_token}")}")

  if [[ -n $completions ]]; then
    compadd -f -a completions
  fi
}

# Register the completion function for the 'fetch' command
compdef _fetch_complete fetch`
}

func (z Zsh) Complete(vals []core.KeyVal) string {
	var sb strings.Builder
	for i, kv := range vals {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(kv.Key)
	}
	return sb.String()
}
