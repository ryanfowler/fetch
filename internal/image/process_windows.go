//go:build windows

package image

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var imageJobs sync.Map // map[*exec.Cmd]windows.Handle
var ntResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

func configureProcess(cmd *exec.Cmd) error {
	// Keep the process suspended until it is assigned to the job. This closes
	// the race in which an adapter could create a child before job assignment.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	// A job with KILL_ON_JOB_CLOSE contains descendants when an adapter is
	// canceled. This is the Windows equivalent of the Unix process group.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create image adapter job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("configure image adapter job: %w", err)
	}
	imageJobs.Store(cmd, job)
	return nil
}

func attachProcess(cmd *exec.Cmd) error {
	value, ok := imageJobs.Load(cmd)
	if !ok {
		return fmt.Errorf("image adapter job is unavailable")
	}
	job := value.(windows.Handle)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open image adapter process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("attach image adapter to job: %w", err)
	}
	if status, _, callErr := ntResumeProcess.Call(uintptr(process)); status != 0 {
		if callErr != nil {
			return fmt.Errorf("resume image adapter: %w", callErr)
		}
		return fmt.Errorf("resume image adapter: NTSTATUS 0x%x", status)
	}
	return nil
}

func releaseProcess(cmd *exec.Cmd) {
	if value, ok := imageJobs.LoadAndDelete(cmd); ok {
		_ = windows.CloseHandle(value.(windows.Handle))
	}
}

func terminateProcessTree(cmd *exec.Cmd) {
	if value, ok := imageJobs.Load(cmd); ok {
		_ = windows.TerminateJobObject(value.(windows.Handle), 1)
	}
	// This also covers the short interval where job assignment failed and the
	// process is still suspended outside the job.
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
