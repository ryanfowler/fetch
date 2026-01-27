package proto

import (
	"os"
	"path/filepath"
	"testing"

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
