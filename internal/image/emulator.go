package image

import "os"

type emulator int

const (
	eUnknown emulator = iota
	eAlacritty
	eApple
	eGhostty
	eHyper
	eIterm2
	eKitty
	eKonsole
	eMintty
	eTmux
	eVSCode
	eWezTerm
	eWindows
	eZellij
)

func (e emulator) Protocol() Protocol {
	switch e {
	case eAlacritty, eApple, eTmux, eUnknown, eVSCode, eWindows, eZellij:
		return ProtoBlock
	case eHyper, eIterm2, eMintty, eWezTerm:
		return ProtoInline
	case eGhostty, eKitty, eKonsole:
		return ProtoKitty
	default:
		return ProtoBlock
	}
}

func detectEmulator() emulator {
	if os.Getenv("ZELLIJ") != "" {
		return eZellij
	}

	if em, ok := detectProgramVar(); ok {
		return em
	}

	if em, ok := detectTermVar(); ok {
		return em
	}

	if em, ok := detectCustomVar(); ok {
		return em
	}

	return eUnknown
}

func detectProgramVar() (emulator, bool) {
	switch os.Getenv("TERM_PROGRAM") {
	case "Apple_Terminal":
		return eApple, true
	case "ghostty":
		return eGhostty, true
	case "Hyper":
		return eHyper, true
	case "iTerm.app":
		return eIterm2, true
	case "mintty":
		return eMintty, true
	case "tmux":
		return eTmux, true
	case "vscode":
		return eVSCode, true
	case "WezTerm":
		return eWezTerm, true
	default:
		return eUnknown, false
	}
}

func detectTermVar() (emulator, bool) {
	switch os.Getenv("TERM") {
	case "alacritty":
		return eAlacritty, true
	case "xterm-ghostty":
		return eGhostty, true
	case "xterm-kitty":
		return eKitty, true
	default:
		return eUnknown, false
	}
}

func detectCustomVar() (emulator, bool) {
	switch {
	case os.Getenv("GHOSTTY_BIN_DIR") != "":
		return eGhostty, true
	case os.Getenv("ITERM_SESSION_ID") != "":
		return eIterm2, true
	case os.Getenv("KITTY_PID") != "":
		return eKitty, true
	case os.Getenv("KONSOLE_VERSION") != "":
		return eKonsole, true
	case os.Getenv("VSCODE_INJECTION") != "":
		return eVSCode, true
	case os.Getenv("WEZTERM_EXECUTABLE") != "":
		return eWezTerm, true
	case os.Getenv("WT_SESSION") != "":
		return eWindows, true
	default:
		return eUnknown, false
	}
}
