package proto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

const (
	protocWaitDelay              = 100 * time.Millisecond
	protocDescriptorPollInterval = 10 * time.Millisecond
	protocOutputFailureCapacity  = 3
)

// CompileProtos compiles .proto files via protoc and returns the loaded schema.
// protoFiles is a list of .proto file paths.
// importPaths is a list of directories to search for imports (-I flags to protoc).
func CompileProtos(protoFiles, importPaths []string) (*Schema, error) {
	return CompileProtosWithContext(context.Background(), protoFiles, importPaths)
}

// CompileProtosWithContext compiles .proto files via protoc using the supplied
// cancellation context and a local operation deadline.
func CompileProtosWithContext(parent context.Context, protoFiles, importPaths []string) (*Schema, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, core.DefaultProtocTimeout)
	defer cancel()

	// Check that protoc is available.
	protocPath, err := exec.LookPath("protoc")
	if err != nil {
		return nil, &ProtocNotFoundError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, newProtocContextError(err)
	}

	// Create temp file for descriptor output.
	tmpFile, err := os.CreateTemp("", "fetch-proto-*.pb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}
	defer os.Remove(tmpPath)

	// Build protoc command.
	args := []string{
		"--descriptor_set_out=" + tmpPath,
		"--include_imports",
	}

	// Add import paths.
	// If no import paths specified, add the directory of each proto file.
	seenDirs := make(map[string]bool)
	if len(importPaths) == 0 {
		for _, f := range protoFiles {
			dir := filepath.Dir(f)
			absDir, err := filepath.Abs(dir)
			if err != nil {
				absDir = dir
			}
			if !seenDirs[absDir] {
				seenDirs[absDir] = true
				args = append(args, "-I="+absDir)
			}
		}
	} else {
		for _, imp := range importPaths {
			args = append(args, "-I="+imp)
		}
	}

	// Add proto files.
	args = append(args, protoFiles...)

	stdout := core.NewBoundedBuffer(core.MaxProtocOutputBytes, "protoc output")
	stderr := core.NewBoundedBuffer(core.MaxProtocOutputBytes, "protoc error output")
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create protoc stdout pipe: %w", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return nil, fmt.Errorf("failed to create protoc stderr pipe: %w", err)
	}

	cmd := exec.CommandContext(ctx, protocPath, args...)
	cmd.Stdin = nil
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	cmd.WaitDelay = protocWaitDelay
	// CommandContext normally terminates only the direct process. The
	// platform-specific helper also terminates descendants that could retain a
	// pipe or continue running after protoc is canceled.
	cmd.Cancel = func() error {
		terminateProtocProcess(cmd)
		return nil
	}
	if err := configureProtocProcess(cmd); err != nil {
		closeProtocPipes(stdoutReader, stdoutWriter, stderrReader, stderrWriter)
		return nil, fmt.Errorf("configure protoc command: %w", err)
	}
	if err := cmd.Start(); err != nil {
		releaseProtocProcess(cmd)
		closeProtocPipes(stdoutReader, stdoutWriter, stderrReader, stderrWriter)
		return nil, &ProtocError{Message: err.Error(), Err: err}
	}
	// os/exec does not copy output when *os.File values are supplied. Close
	// the parent write ends so only protoc and its contained descendants can
	// keep the readers open.
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()

	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})
	outputFailure := make(chan protocOutputFailure, protocOutputFailureCapacity)
	descriptorMonitorStop := make(chan struct{})
	descriptorMonitorDone := make(chan struct{})
	go monitorProtocDescriptorOutput(tmpPath, descriptorMonitorStop, descriptorMonitorDone, outputFailure)
	go drainProtocOutput(stdoutReader, stdout, "stdout", stdoutDone, outputFailure)
	go drainProtocOutput(stderrReader, stderr, "stderr", stderrDone, outputFailure)

	if err := attachProtocProcess(cmd); err != nil {
		terminateProtocProcess(cmd)
		_ = cmd.Wait()
		stopProtocDescriptorMonitor(descriptorMonitorStop, descriptorMonitorDone)
		closeProtocOutput(stdoutReader, stderrReader, stdoutDone, stderrDone)
		releaseProtocProcess(cmd)
		return nil, fmt.Errorf("attach protoc command: %w", err)
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var runErr error
	select {
	case runErr = <-waitCh:
	case failure := <-outputFailure:
		terminateProtocProcess(cmd)
		runErr = <-waitCh
		stopProtocDescriptorMonitor(descriptorMonitorStop, descriptorMonitorDone)
		return nil, finishProtocCommand(cmd, runErr, ctx, stdoutReader, stderrReader, stdoutDone, stderrDone, outputFailure, failure, stdout, stderr)
	case <-ctx.Done():
		terminateProtocProcess(cmd)
		runErr = <-waitCh
	}

	stopProtocDescriptorMonitor(descriptorMonitorStop, descriptorMonitorDone)
	terminateProtocProcess(cmd)
	closeProtocOutput(stdoutReader, stderrReader, stdoutDone, stderrDone)
	releaseProtocProcess(cmd)

	failure := collectProtocOutputFailure(outputFailure)
	if failure.err != nil {
		return nil, finishProtocError(ctx, runErr, failure, stdout, stderr)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, finishProtocError(ctx, runErr, protocOutputFailure{}, stdout, stderr)
	}
	if runErr != nil {
		errMsg := strings.TrimSpace(string(stderr.Bytes()))
		if errMsg == "" {
			errMsg = runErr.Error()
		}
		return nil, &ProtocError{Message: errMsg, Err: runErr}
	}

	// LoadDescriptorSetFile performs the same bounded read for generated
	// output, including a size check before protobuf parsing.
	return LoadDescriptorSetFileWithContext(ctx, tmpPath)
}

func monitorProtocDescriptorOutput(path string, stop <-chan struct{}, done chan<- struct{}, failures chan<- protocOutputFailure) {
	defer close(done)
	ticker := time.NewTicker(protocDescriptorPollInterval)
	defer ticker.Stop()

	for {
		if info, err := os.Stat(path); err == nil && info.Size() > core.MaxProtobufDescriptorSetBytes {
			failures <- protocOutputFailure{
				stream: "descriptor",
				err: core.LimitError{
					Subsystem: "protobuf descriptor set",
					Limit:     core.MaxProtobufDescriptorSetBytes,
				},
			}
			return
		}

		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func stopProtocDescriptorMonitor(stop chan struct{}, done <-chan struct{}) {
	close(stop)
	<-done
}

type protocOutputFailure struct {
	stream string
	err    error
}

func drainProtocOutput(r io.Reader, dst *core.BoundedBuffer, stream string, done chan<- struct{}, failures chan<- protocOutputFailure) {
	defer close(done)
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				failures <- protocOutputFailure{stream: stream, err: writeErr}
				return
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			failures <- protocOutputFailure{stream: stream, err: err}
			return
		}
	}
}

func closeProtocPipes(stdoutReader, stdoutWriter, stderrReader, stderrWriter *os.File) {
	_ = stdoutReader.Close()
	_ = stdoutWriter.Close()
	_ = stderrReader.Close()
	_ = stderrWriter.Close()
}

func closeProtocOutput(stdoutReader, stderrReader *os.File, stdoutDone, stderrDone <-chan struct{}) {
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	<-stdoutDone
	<-stderrDone
}

func collectProtocOutputFailure(failures <-chan protocOutputFailure) protocOutputFailure {
	var first protocOutputFailure
	for {
		select {
		case failure := <-failures:
			if first.err == nil {
				first = failure
			}
		default:
			return first
		}
	}
}

func finishProtocCommand(cmd *exec.Cmd, runErr error, ctx context.Context, stdoutReader, stderrReader *os.File, stdoutDone, stderrDone <-chan struct{}, failures <-chan protocOutputFailure, failure protocOutputFailure, stdout, stderr *core.BoundedBuffer) error {
	closeProtocOutput(stdoutReader, stderrReader, stdoutDone, stderrDone)
	releaseProtocProcess(cmd)
	if failure.err == nil {
		failure = collectProtocOutputFailure(failures)
	}
	return finishProtocError(ctx, runErr, failure, stdout, stderr)
}

func finishProtocError(ctx context.Context, runErr error, failure protocOutputFailure, stdout, stderr *core.BoundedBuffer) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return &ProtocError{Message: "protoc timed out", Err: context.Cause(ctx)}
		}
		return &ProtocError{Message: "protoc canceled: " + ctxErr.Error(), Err: context.Cause(ctx)}
	}
	if failure.err != nil {
		if errors.Is(failure.err, core.ErrLimitExceeded) {
			if failure.stream == "descriptor" {
				return &ProtocError{
					Message: fmt.Sprintf("generated descriptor set exceeded %d bytes", core.MaxProtobufDescriptorSetBytes),
					Err:     failure.err,
				}
			}
			return &ProtocError{
				Message: fmt.Sprintf("protoc %s output exceeded %d bytes", failure.stream, core.MaxProtocOutputBytes),
				Err:     failure.err,
			}
		}
		return &ProtocError{Message: fmt.Sprintf("protoc %s output: %v", failure.stream, failure.err), Err: failure.err}
	}
	if runErr != nil {
		errMsg := strings.TrimSpace(string(stderr.Bytes()))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(stdout.Bytes()))
		}
		if errMsg == "" {
			errMsg = runErr.Error()
		}
		return &ProtocError{Message: errMsg, Err: runErr}
	}
	return nil
}

func newProtocContextError(err error) *ProtocError {
	if errors.Is(err, context.DeadlineExceeded) {
		return &ProtocError{Message: "protoc timed out", Err: err}
	}
	return &ProtocError{Message: "protoc canceled: " + err.Error(), Err: err}
}

// ProtocNotFoundError indicates protoc is not installed or not in PATH.
type ProtocNotFoundError struct{}

func (e *ProtocNotFoundError) Error() string {
	return "protoc not found in PATH. Install protoc from https://github.com/protocolbuffers/protobuf/releases"
}

// ProtocError indicates protoc execution failed.
type ProtocError struct {
	Message string
	Err     error
}

func (e *ProtocError) Error() string {
	return fmt.Sprintf("protoc failed: %s", e.Message)
}

func (e *ProtocError) Unwrap() error { return e.Err }
