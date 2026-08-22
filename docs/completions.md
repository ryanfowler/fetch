# Shell completion

Completion candidates come from the same Go option registry used by CLI help
and validation. Hidden internal options are not offered.

`fetch --complete SHELL` prints a registration script when called without
additional words, or candidate lines when called by an installed completion
function. Supported shells are Bash, Zsh, Fish, and PowerShell.

## Bash

```sh
echo 'eval "$(fetch --complete bash)"' >> ~/.bashrc
```

## Zsh

```sh
mkdir -p ~/.zshrc.d
fetch --complete zsh > ~/.zshrc.d/_fetch
```

Add `~/.zshrc.d` to `fpath` if needed.

## Fish

```sh
mkdir -p ~/.config/fish/completions
fetch --complete fish > ~/.config/fish/completions/fetch.fish
```

## PowerShell

Add the generated registration script to the PowerShell profile:

```powershell
New-Item -ItemType Directory -Force (Split-Path $PROFILE) | Out-Null
fetch --complete powershell >> $PROFILE
```

The completion function asks the installed Go binary for candidates. It does
not execute a shell command assembled from user input. Enum values include HTTP
versions, compression, pager, ECH, image, skill agents, WebSocket modes, and
other values registered by the CLI.
