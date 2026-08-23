//go:build windows

package update

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var probeJobs sync.Map // map[*exec.Cmd]windows.Handle
var probeResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

func configureProbeProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create validation job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("configure validation job: %w", err)
	}
	probeJobs.Store(cmd, job)
	return nil
}

func attachProbeProcess(cmd *exec.Cmd) error {
	value, ok := probeJobs.Load(cmd)
	if !ok {
		return fmt.Errorf("probe job is unavailable")
	}
	job := value.(windows.Handle)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open validation process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("attach probe process: %w", err)
	}
	if status, _, callErr := probeResumeProcess.Call(uintptr(process)); status != 0 {
		if callErr != nil {
			return fmt.Errorf("resume probe process: %w", callErr)
		}
		return fmt.Errorf("resume probe process: NTSTATUS 0x%x", status)
	}
	return nil
}

func terminateProbeProcess(cmd *exec.Cmd) {
	if value, ok := probeJobs.Load(cmd); ok {
		_ = windows.TerminateJobObject(value.(windows.Handle), 1)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func releaseProbeProcess(cmd *exec.Cmd) {
	if value, ok := probeJobs.LoadAndDelete(cmd); ok {
		_ = windows.CloseHandle(value.(windows.Handle))
	}
}
