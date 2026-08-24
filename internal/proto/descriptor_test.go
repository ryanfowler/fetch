package proto

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestLoadDescriptorSetFile(t *testing.T) {
	// Create a temporary descriptor set file.
	fds := createTestDescriptorSet()
	data, err := proto.Marshal(fds)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.pb")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	// Test loading.
	schema, err := LoadDescriptorSetFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadDescriptorSetFile() error = %v", err)
	}

	// Verify schema was loaded correctly.
	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Errorf("FindMessage() error = %v", err)
	}
	if md == nil {
		t.Error("FindMessage() returned nil")
	}
}

func TestLoadDescriptorSetFileNotFound(t *testing.T) {
	_, err := LoadDescriptorSetFile("/nonexistent/path/to/file.pb")
	if err == nil {
		t.Error("LoadDescriptorSetFile() expected error for nonexistent file")
	}
}

func TestLoadDescriptorSetFileRejectsNonRegularInput(t *testing.T) {
	path := t.TempDir()
	started := time.Now()

	_, err := LoadDescriptorSetFile(path)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("LoadDescriptorSetFile() error = %v, want non-regular input error", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("LoadDescriptorSetFile() took too long for non-regular input: %s", elapsed)
	}
}

func TestLoadDescriptorSetFileWithContextHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "descriptor.pb")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := LoadDescriptorSetFileWithContext(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadDescriptorSetFileWithContext() error = %v, want context.Canceled", err)
	}
}

func TestReadDescriptorSetFileHonorsCancellationDuringRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer writer.Close()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, readErr := readDescriptorSetFile(ctx, reader)
		result <- readErr
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("readDescriptorSetFile() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("readDescriptorSetFile() did not stop after cancellation")
	}
}

func TestLoadDescriptorSetFileInvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.pb")

	// Write invalid protobuf data.
	if err := os.WriteFile(tmpFile, []byte("not a valid protobuf"), 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	_, err := LoadDescriptorSetFile(tmpFile)
	if err == nil {
		t.Error("LoadDescriptorSetFile() expected error for invalid protobuf")
	}
}

func TestLoadDescriptorSetFileRejectsOversizedInput(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "oversized.pb")
	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	if err := file.Truncate(core.MaxProtobufDescriptorSetBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("File.Truncate() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("File.Close() error = %v", err)
	}

	_, err = LoadDescriptorSetFile(tmpFile)
	if err == nil || !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("LoadDescriptorSetFile() error = %v, want descriptor size limit", err)
	}
}

func TestLoadDescriptorSetBytes(t *testing.T) {
	fds := createTestDescriptorSet()
	data, err := proto.Marshal(fds)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	schema, err := loadDescriptorSetBytes(data)
	if err != nil {
		t.Fatalf("LoadDescriptorSetBytes() error = %v", err)
	}

	// Verify schema was loaded correctly.
	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Errorf("FindMessage() error = %v", err)
	}
	if md == nil {
		t.Error("FindMessage() returned nil")
	}
}

func TestLoadDescriptorSetBytesEmpty(t *testing.T) {
	// Empty bytes should produce empty schema.
	fds := &descriptorpb.FileDescriptorSet{}
	data, err := proto.Marshal(fds)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	schema, err := loadDescriptorSetBytes(data)
	if err != nil {
		t.Fatalf("LoadDescriptorSetBytes() error = %v", err)
	}

	if len(schema.ListMessages()) != 0 {
		t.Errorf("expected 0 messages, got %d", len(schema.ListMessages()))
	}
	if len(schema.ListServices()) != 0 {
		t.Errorf("expected 0 services, got %d", len(schema.ListServices()))
	}
}

func TestLoadDescriptorSetBytesInvalid(t *testing.T) {
	_, err := loadDescriptorSetBytes([]byte("not valid protobuf"))
	if err == nil {
		t.Error("LoadDescriptorSetBytes() expected error for invalid protobuf")
	}
}
