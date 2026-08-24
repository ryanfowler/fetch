//go:build windows

package proto

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func assertProtocChildTerminated(t *testing.T, pid int) {
	t.Helper()
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Fatalf("OpenProcess(%d) error = %v", pid, err)
	}
	defer windows.CloseHandle(process)

	result, err := windows.WaitForSingleObject(process, uint32(time.Second/time.Millisecond))
	if err != nil {
		t.Fatalf("WaitForSingleObject(%d) error = %v", pid, err)
	}
	switch result {
	case windows.WAIT_OBJECT_0:
		return
	case uint32(windows.WAIT_TIMEOUT):
		t.Fatalf("contained protoc child process %d is still running", pid)
	default:
		t.Fatalf("WaitForSingleObject(%d) returned unexpected result %d", pid, result)
	}
}
