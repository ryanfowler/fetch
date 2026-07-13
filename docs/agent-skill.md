# Agent Skill

`fetch` includes an Agent Skill that teaches supported coding agents how to use
the CLI. The skill is embedded in the binary, so viewing, installing, and
uninstalling it require no network access.

## View the Skill

Print the embedded `SKILL.md` without installing it:

```sh
fetch --skill
```

## Install

Install to the interoperable Agents location:

```sh
fetch --install-skill
```

Choose a specific agent, or install all supported targets:

```sh
fetch --install-skill codex
fetch --install-skill claude
fetch --install-skill gemini
fetch --install-skill pi
fetch --install-skill all
```

The default scope is `user`. Use `--scope project` to install inside the current
project:

```sh
fetch --install-skill pi --scope project
```

| Target             | User scope                 | Project scope          |
| ------------------ | -------------------------- | ---------------------- |
| `agents` (default) | `~/.agents/skills/fetch`   | `.agents/skills/fetch` |
| `codex`            | `~/.codex/skills/fetch`    | `.codex/skills/fetch`  |
| `claude`           | `~/.claude/skills/fetch`   | `.claude/skills/fetch` |
| `gemini`           | `~/.gemini/skills/fetch`   | `.gemini/skills/fetch` |
| `pi`               | `~/.pi/agent/skills/fetch` | `.pi/skills/fetch`     |

`all` means the five locations in the table; it does not probe for or write to
other agent directories.

## Preview Changes

Use `--dry-run` to show every destination without writing:

```sh
fetch --install-skill all --scope project --dry-run
fetch --uninstall-skill all --dry-run
```

When attached to a terminal, install and uninstall commands show their
destinations and ask for confirmation before making changes.

## Update or Replace an Installation

Each installed copy includes `.fetch-skill.json`, which records the skill and
`fetch` versions plus file hashes. This allows `fetch` to detect local
modifications before replacing or deleting an installation.

By default, modified installations are left untouched. Review the destination,
then use `--force` if replacement is intentional:

```sh
fetch --install-skill pi --force
```

## Uninstall

Remove the generic installation, a specific agent installation, or every
supported installation:

```sh
fetch --uninstall-skill
fetch --uninstall-skill pi
fetch --uninstall-skill all --scope project
```

Uninstall uses the same modification checks as installation. Use `--force` only
when you intend to remove a locally changed copy.

## Safety and Scope

The skill workflow:

- operates only on the selected user or project destinations;
- does not download files;
- does not edit agent configuration files;
- detects modified installations before replacement or removal; and
- uses locked, atomic filesystem operations.

## See Also

- [CLI Reference](cli-reference.md#agent-skill-options)
- [Getting Started](getting-started.md)
