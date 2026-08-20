//go:build linux

package integration_test

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMetadataHelpInPTY(t *testing.T) {
	fetchPath := goBuild(t, t.TempDir())

	tests := []struct {
		name string
		args []string
		want []string
		not  []string
	}{
		{name: "concise", args: []string{"--help"}, want: []string{"Usage", "--unix"}, not: []string{"# CLI Reference"}},
		{name: "verbose markdown", args: []string{"-v", "--help", "--pager", "off", "--color", "on"}, want: []string{"CLI Reference", "\x1b["}},
		{name: "automatic pager", args: []string{"-v", "--help", "--pager", "auto"}, want: []string{"CLI Reference"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := runInPTY(t, fetchPath, test.args...)
			if err != nil {
				t.Fatalf("fetch in PTY failed: %v\n%s", err, output)
			}
			for _, value := range test.want {
				if !strings.Contains(output, value) {
					t.Fatalf("PTY output lacks %q:\n%s", value, output)
				}
			}
			for _, value := range test.not {
				if strings.Contains(output, value) {
					t.Fatalf("PTY output unexpectedly contains %q", value)
				}
			}
		})
	}
}

func runInPTY(t *testing.T, path string, args ...string) (string, error) {
	t.Helper()
	master, slave := openPTY(t)
	defer master.Close()

	cmd := exec.Command(path, args...)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = cleanPagerEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		return "", err
	}
	slave.Close()

	outputDone := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(master)
		outputDone <- string(data)
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	select {
	case err := <-waitDone:
		select {
		case output := <-outputDone:
			return output, err
		case <-time.After(2 * time.Second):
			return "", err
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		return "", <-waitDone
	}
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open ptmx: %v", err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Fatalf("unlock ptmx: %v", err)
	}
	ptyNumber, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Fatalf("get pty number: %v", err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(ptyNumber), os.O_RDWR, 0)
	if err != nil {
		master.Close()
		t.Fatalf("open pty slave: %v", err)
	}
	return master, slave
}

func cleanPagerEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "PAGER=") || strings.HasPrefix(value, "NO_PAGER=") || strings.HasPrefix(value, "LESS=") {
			continue
		}
		env = append(env, value)
	}
	env = append(env, "PAGER=cat")
	return env
}
