//go:build (darwin || linux) && cgo

package integration

/*
#cgo linux LDFLAGS: -lutil
#if defined(__APPLE__)
#include <util.h>
#else
#include <pty.h>
#endif
#include <errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
static int fetch_errno(void) { return errno; }
static int set_winsize(int fd, unsigned short rows, unsigned short cols, unsigned short xpixel, unsigned short ypixel) {
	struct winsize ws;
	ws.ws_row = rows;
	ws.ws_col = cols;
	ws.ws_xpixel = xpixel;
	ws.ws_ypixel = ypixel;
	return ioctl(fd, TIOCSWINSZ, &ws);
}
*/
import "C"

import (
	"os"
	"syscall"
	"testing"
)

func OpenPTY(t *testing.T, rows, cols uint16) (*os.File, *os.File) {
	t.Helper()
	return OpenPTYWithPixels(t, rows, cols, 0, 0)
}

func OpenPTYWithPixels(t *testing.T, rows, cols, widthPx, heightPx uint16) (*os.File, *os.File) {
	t.Helper()

	var master C.int
	var slave C.int
	ws := C.struct_winsize{
		ws_row:    C.ushort(rows),
		ws_col:    C.ushort(cols),
		ws_xpixel: C.ushort(widthPx),
		ws_ypixel: C.ushort(heightPx),
	}
	if rc := C.openpty(&master, &slave, nil, nil, &ws); rc != 0 {
		t.Fatalf("openpty failed: %v", syscall.Errno(C.fetch_errno()))
	}
	if rc := C.set_winsize(slave, C.ushort(rows), C.ushort(cols), C.ushort(widthPx), C.ushort(heightPx)); rc != 0 {
		t.Fatalf("setting pty window size failed: %v", syscall.Errno(C.fetch_errno()))
	}

	return os.NewFile(uintptr(master), "fetch-pty-master"), os.NewFile(uintptr(slave), "fetch-pty-slave")
}
