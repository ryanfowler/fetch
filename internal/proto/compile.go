package proto

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CompileProtos compiles .proto files via protoc and returns the loaded schema.
// protoFiles is a list of .proto file paths.
// importPaths is a list of directories to search for imports (-I flags to protoc).
func CompileProtos(protoFiles, importPaths []string) (*Schema, error) {
	// Check that protoc is available.
	protocPath, err := exec.LookPath("protoc")
	if err != nil {
		return nil, &ProtocNotFoundError{}
	}

	// Create temp file for descriptor output.
	tmpFile, err := os.CreateTemp("", "fetch-proto-*.pb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
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

	// Execute protoc.
	var stderr bytes.Buffer
	cmd := exec.Command(protocPath, args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, &ProtocError{Message: errMsg}
	}

	// Load the generated descriptor set.
	return LoadDescriptorSetFile(tmpPath)
}

// ProtocNotFoundError indicates protoc is not installed or not in PATH.
type ProtocNotFoundError struct{}

func (e *ProtocNotFoundError) Error() string {
	return "protoc not found in PATH. Install protoc from https://github.com/protocolbuffers/protobuf/releases"
}

// ProtocError indicates protoc execution failed.
type ProtocError struct {
	Message string
}

func (e *ProtocError) Error() string {
	return fmt.Sprintf("protoc failed: %s", e.Message)
}
