package proto

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCompileProtosSuccess(t *testing.T) {
	// Skip if protoc is not available.
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not found in PATH, skipping compile tests")
	}

	// Create a test proto file.
	tmpDir := t.TempDir()
	protoFile := filepath.Join(tmpDir, "test.proto")
	protoContent := `
syntax = "proto3";
package testcompile;

message TestRequest {
  int64 id = 1;
  string name = 2;
}

message TestResponse {
  bool success = 1;
  string message = 2;
}

service TestService {
  rpc GetTest(TestRequest) returns (TestResponse);
}
`
	if err := os.WriteFile(protoFile, []byte(protoContent), 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	// Compile the proto.
	schema, err := CompileProtos([]string{protoFile}, nil)
	if err != nil {
		t.Fatalf("CompileProtos() error = %v", err)
	}

	// Verify messages were loaded.
	md, err := schema.FindMessage("testcompile.TestRequest")
	if err != nil {
		t.Errorf("FindMessage(TestRequest) error = %v", err)
	}
	if md == nil {
		t.Error("FindMessage(TestRequest) returned nil")
	}

	md, err = schema.FindMessage("testcompile.TestResponse")
	if err != nil {
		t.Errorf("FindMessage(TestResponse) error = %v", err)
	}
	if md == nil {
		t.Error("FindMessage(TestResponse) returned nil")
	}

	// Verify service was loaded.
	sd, err := schema.FindService("testcompile.TestService")
	if err != nil {
		t.Errorf("FindService() error = %v", err)
	}
	if sd == nil {
		t.Error("FindService() returned nil")
	}

	// Verify method was loaded.
	method, err := schema.FindMethod("testcompile.TestService/GetTest")
	if err != nil {
		t.Errorf("FindMethod() error = %v", err)
	}
	if method == nil {
		t.Error("FindMethod() returned nil")
	}
}

func TestCompileProtosWithImports(t *testing.T) {
	// Skip if protoc is not available.
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not found in PATH, skipping compile tests")
	}

	// Create a directory structure with imports.
	tmpDir := t.TempDir()
	commonDir := filepath.Join(tmpDir, "common")
	serviceDir := filepath.Join(tmpDir, "service")

	if err := os.MkdirAll(commonDir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(common) error = %v", err)
	}
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(service) error = %v", err)
	}

	// Create common proto.
	commonProto := filepath.Join(commonDir, "common.proto")
	commonContent := `
syntax = "proto3";
package common;

message Timestamp {
  int64 seconds = 1;
  int32 nanos = 2;
}
`
	if err := os.WriteFile(commonProto, []byte(commonContent), 0644); err != nil {
		t.Fatalf("os.WriteFile(common) error = %v", err)
	}

	// Create service proto that imports common.
	serviceProto := filepath.Join(serviceDir, "service.proto")
	serviceContent := `
syntax = "proto3";
package myservice;

import "common/common.proto";

message Event {
  string id = 1;
  common.Timestamp timestamp = 2;
}
`
	if err := os.WriteFile(serviceProto, []byte(serviceContent), 0644); err != nil {
		t.Fatalf("os.WriteFile(service) error = %v", err)
	}

	// Compile with import path.
	schema, err := CompileProtos([]string{serviceProto}, []string{tmpDir})
	if err != nil {
		t.Fatalf("CompileProtos() error = %v", err)
	}

	// Verify message was loaded.
	md, err := schema.FindMessage("myservice.Event")
	if err != nil {
		t.Errorf("FindMessage(Event) error = %v", err)
	}
	if md == nil {
		t.Error("FindMessage(Event) returned nil")
	}

	// Verify imported message is also available.
	md, err = schema.FindMessage("common.Timestamp")
	if err != nil {
		t.Errorf("FindMessage(Timestamp) error = %v", err)
	}
	if md == nil {
		t.Error("FindMessage(Timestamp) returned nil")
	}
}

func TestCompileProtosFileNotFound(t *testing.T) {
	// Skip if protoc is not available.
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not found in PATH, skipping compile tests")
	}

	_, err := CompileProtos([]string{"/nonexistent/path/to/file.proto"}, nil)
	if err == nil {
		t.Error("CompileProtos() expected error for nonexistent file")
	}
}

func TestCompileProtosInvalidSyntax(t *testing.T) {
	// Skip if protoc is not available.
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not found in PATH, skipping compile tests")
	}

	tmpDir := t.TempDir()
	protoFile := filepath.Join(tmpDir, "invalid.proto")

	// Write invalid proto syntax.
	invalidContent := `
this is not valid proto syntax!!!
message {
  broken = 1;
}
`
	if err := os.WriteFile(protoFile, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	_, err := CompileProtos([]string{protoFile}, nil)
	if err == nil {
		t.Error("CompileProtos() expected error for invalid proto syntax")
	}

	// Should be a ProtocError.
	protocErr, ok := err.(*ProtocError)
	if !ok {
		t.Errorf("expected ProtocError, got %T", err)
	}
	if protocErr != nil && protocErr.Message == "" {
		t.Error("ProtocError.Message should not be empty")
	}
}

func TestCompileProtosMultipleFiles(t *testing.T) {
	// Skip if protoc is not available.
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not found in PATH, skipping compile tests")
	}

	tmpDir := t.TempDir()

	// Create first proto file.
	proto1 := filepath.Join(tmpDir, "first.proto")
	proto1Content := `
syntax = "proto3";
package first;

message FirstMessage {
  string value = 1;
}
`
	if err := os.WriteFile(proto1, []byte(proto1Content), 0644); err != nil {
		t.Fatalf("os.WriteFile(first) error = %v", err)
	}

	// Create second proto file.
	proto2 := filepath.Join(tmpDir, "second.proto")
	proto2Content := `
syntax = "proto3";
package second;

message SecondMessage {
  int32 count = 1;
}
`
	if err := os.WriteFile(proto2, []byte(proto2Content), 0644); err != nil {
		t.Fatalf("os.WriteFile(second) error = %v", err)
	}

	// Compile both.
	schema, err := CompileProtos([]string{proto1, proto2}, nil)
	if err != nil {
		t.Fatalf("CompileProtos() error = %v", err)
	}

	// Verify both messages are available.
	md1, err := schema.FindMessage("first.FirstMessage")
	if err != nil {
		t.Errorf("FindMessage(FirstMessage) error = %v", err)
	}
	if md1 == nil {
		t.Error("FindMessage(FirstMessage) returned nil")
	}

	md2, err := schema.FindMessage("second.SecondMessage")
	if err != nil {
		t.Errorf("FindMessage(SecondMessage) error = %v", err)
	}
	if md2 == nil {
		t.Error("FindMessage(SecondMessage) returned nil")
	}
}

func TestProtocNotFoundError(t *testing.T) {
	err := &ProtocNotFoundError{}
	msg := err.Error()
	if msg == "" {
		t.Error("ProtocNotFoundError.Error() returned empty string")
	}
	if len(msg) < 10 {
		t.Error("ProtocNotFoundError.Error() message too short")
	}
}

func TestProtocError(t *testing.T) {
	err := &ProtocError{Message: "test error message"}
	msg := err.Error()
	if msg == "" {
		t.Error("ProtocError.Error() returned empty string")
	}
	if msg != "protoc failed: test error message" {
		t.Errorf("ProtocError.Error() = %v, want 'protoc failed: test error message'", msg)
	}
}
