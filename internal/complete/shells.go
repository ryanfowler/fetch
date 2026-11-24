package complete

import (
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Shell represents a supported shell for completions.
type Shell interface {
	Name() string
	Register() string
	Complete([]core.KeyVal[string]) string
}

// GetShell returns the shell matching the provided name. If no shell matches,
// nil is returned.
func GetShell(name string) Shell {
	switch name {
	case "bash":
		return Bash{}
	case "fish":
		return Fish{}
	case "zsh":
		return Zsh{}
	case "powershell":
		return PowerShell{}
	default:
		return nil
	}
}

type Bash struct{}

func (b Bash) Name() string {
	return "bash"
}

func (b Bash) Register() string {
	return `_fetch_complete() {
  local cur prev_tokens
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev_tokens=("${COMP_WORDS[@]:0:COMP_CWORD}")
  local line
  COMPREPLY=()
  # Read one candidate per line. An unquoted $(...) array would split and
  # glob-expand the candidates.
  while IFS= read -r line; do
    COMPREPLY+=("$line")
  done < <(fetch --complete=bash -- "${prev_tokens[@]}" "$cur")
}
complete -o nosort -o nospace -F _fetch_complete fetch`
}

func (b Bash) Complete(vals []core.KeyVal[string]) string {
	var sb strings.Builder
	for _, kv := range vals {
		word, ok := bashCandidate(kv.Key)
		if !ok {
			continue
		}
		sb.WriteString(word)
		if !strings.HasSuffix(kv.Key, "/") && !strings.HasSuffix(kv.Key, "=") {
			sb.WriteByte(' ')
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

type Fish struct{}

func (f Fish) Name() string {
	return "fish"
}

func (f Fish) Register() string {
	return `complete --keep-order --exclusive --command fetch --arguments "(fetch --complete=fish -- (commandline --current-process --tokens-expanded --cut-at-cursor) (commandline --cut-at-cursor --current-token))"`
}

func (f Fish) Complete(vals []core.KeyVal[string]) string {
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

func (z Zsh) Complete(vals []core.KeyVal[string]) string {
	var sb strings.Builder
	for i, kv := range vals {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(kv.Key)
	}
	return sb.String()
}

// bashCandidate returns key as bash must insert it into the command line.
// Bash inserts a candidate as it is, so the file name part of key must be
// escaped: a file named "$(cmd)" would otherwise run cmd. The text before
// the last "/" comes from the word that the user typed, so it stays as it
// is and "~" or "$HOME" in it still expands. A trailing "/" on a directory
// candidate does not start the file name part. bashCandidate returns false
// when key contains a newline or another control character, because bash
// cannot read such a candidate from one line.
func bashCandidate(key string) (string, bool) {
	if strings.ContainsFunc(key, isControl) {
		return "", false
	}
	trimmed, slash := strings.CutSuffix(key, "/")
	start := strings.LastIndexByte(trimmed, '/') + 1
	var sb strings.Builder
	sb.WriteString(trimmed[:start])
	name := trimmed[start:]
	for i, r := range name {
		switch {
		case strings.ContainsRune(" \t\\'\"$`!&;|<>()[]{}*?^", r):
			sb.WriteByte('\\')
		case (r == '~' || r == '#') && i == 0 && start == 0 && name != "~":
			// A word that starts with "~" or "#" is a tilde expansion or
			// a comment. A bare "~" is the home directory candidate.
			sb.WriteByte('\\')
		}
		sb.WriteRune(r)
	}
	if slash {
		sb.WriteByte('/')
	}
	return sb.String(), true
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}
