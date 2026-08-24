//go:build windows

package pager

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var pagerJobs sync.Map // map[*exec.Cmd]windows.Handle
var pagerResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

func configureProcess(cmd *exec.Cmd, interactive bool) error {
	// Keep the pager suspended until it is assigned to the job. This closes the
	// race in which a wrapper can create a descendant before job assignment.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create pager job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("configure pager job: %w", err)
	}
	pagerJobs.Store(cmd, job)
	return nil
}

func attachProcess(cmd *exec.Cmd) error {
	value, ok := pagerJobs.Load(cmd)
	if !ok {
		return fmt.Errorf("pager job is unavailable")
	}
	if cmd.Process == nil {
		return fmt.Errorf("pager process is unavailable")
	}
	job := value.(windows.Handle)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open pager process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("attach pager process to job: %w", err)
	}
	if status, _, callErr := pagerResumeProcess.Call(uintptr(process)); status != 0 {
		if callErr != nil {
			return fmt.Errorf("resume pager process: %w", callErr)
		}
		return fmt.Errorf("resume pager process: NTSTATUS 0x%x", status)
	}
	return nil
}

func terminateProcessTree(cmd *exec.Cmd) {
	if value, ok := pagerJobs.Load(cmd); ok {
		_ = windows.TerminateJobObject(value.(windows.Handle), 1)
	}
	if cmd.Process != nil {
		// This covers the short interval where job assignment failed and the
		// process is still suspended outside the job.
		_ = cmd.Process.Kill()
	}
}

func releaseProcess(cmd *exec.Cmd) {
	if value, ok := pagerJobs.LoadAndDelete(cmd); ok {
		_ = windows.CloseHandle(value.(windows.Handle))
	}
}

func pagerExitWasSIGPIPE(error) bool { return false }
