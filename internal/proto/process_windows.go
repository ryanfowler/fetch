//go:build windows

package proto

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var protocJobs sync.Map // map[*exec.Cmd]windows.Handle
var protocResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

func configureProtocProcess(cmd *exec.Cmd) error {
	// Keep the process suspended until it is assigned to the job, preventing a
	// descendant from escaping during the short post-Start interval.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create protoc job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("configure protoc job: %w", err)
	}
	protocJobs.Store(cmd, job)
	return nil
}

func attachProtocProcess(cmd *exec.Cmd) error {
	value, ok := protocJobs.Load(cmd)
	if !ok {
		return fmt.Errorf("protoc job is unavailable")
	}
	job := value.(windows.Handle)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open protoc process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("attach protoc process to job: %w", err)
	}
	if status, _, callErr := protocResumeProcess.Call(uintptr(process)); status != 0 {
		if callErr != nil {
			return fmt.Errorf("resume protoc process: %w", callErr)
		}
		return fmt.Errorf("resume protoc process: NTSTATUS 0x%x", status)
	}
	return nil
}

func releaseProtocProcess(cmd *exec.Cmd) {
	if value, ok := protocJobs.LoadAndDelete(cmd); ok {
		_ = windows.CloseHandle(value.(windows.Handle))
	}
}

func terminateProtocProcess(cmd *exec.Cmd) {
	if value, ok := protocJobs.Load(cmd); ok {
		_ = windows.TerminateJobObject(value.(windows.Handle), 1)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
