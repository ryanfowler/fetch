//go:build linux

package ws

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// openTestPTY returns the controller and the terminal side of a new pty.
func openTestPTY(t *testing.T) (controller, tty *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { controller.Close() })
	if err := unix.IoctlSetPointerInt(int(controller.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(controller.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("get pty number: %v", err)
	}
	tty, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pty: %v", err)
	}
	return controller, tty
}

func ptyTermios(t *testing.T, controller *os.File) unix.Termios {
	t.Helper()
	termios, err := unix.IoctlGetTermios(int(controller.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("get termios: %v", err)
	}
	return *termios
}

func TestTerminalRestoreAndCloseRestoresBeforeClose(t *testing.T) {
	controller, tty := openTestPTY(t)
	before := ptyTermios(t, controller)
	term := &terminal{fd: int(tty.Fd())}
	if err := term.enterRaw(); err != nil {
		t.Fatal(err)
	}
	if ptyTermios(t, controller) == before {
		t.Fatal("enterRaw did not change the terminal state")
	}

	term.restoreAndClose(tty)

	if after := ptyTermios(t, controller); after != before {
		t.Fatalf("terminal state after restoreAndClose = %+v, want %+v", after, before)
	}
	// A second restore, such as an explicit fallback restore before the
	// deferred call, must be a safe no-op.
	term.restore()
}
