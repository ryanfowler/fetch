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

var validationJobs sync.Map // map[*exec.Cmd]windows.Handle
var validationResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

func configureValidationProcess(cmd *exec.Cmd) error {
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
	validationJobs.Store(cmd, job)
	return nil
}

func attachValidationProcess(cmd *exec.Cmd) error {
	value, ok := validationJobs.Load(cmd)
	if !ok {
		return fmt.Errorf("validation job is unavailable")
	}
	job := value.(windows.Handle)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open validation process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("attach validation process: %w", err)
	}
	if status, _, callErr := validationResumeProcess.Call(uintptr(process)); status != 0 {
		if callErr != nil {
			return fmt.Errorf("resume validation process: %w", callErr)
		}
		return fmt.Errorf("resume validation process: NTSTATUS 0x%x", status)
	}
	return nil
}

func terminateValidationProcess(cmd *exec.Cmd) {
	if value, ok := validationJobs.Load(cmd); ok {
		_ = windows.TerminateJobObject(value.(windows.Handle), 1)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func releaseValidationProcess(cmd *exec.Cmd) {
	if value, ok := validationJobs.LoadAndDelete(cmd); ok {
		_ = windows.CloseHandle(value.(windows.Handle))
	}
}
