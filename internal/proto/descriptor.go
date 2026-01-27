package proto

import (
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// LoadDescriptorSetFile loads a schema from a pre-compiled FileDescriptorSet file (.pb).
func LoadDescriptorSetFile(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read descriptor set file: %w", err)
	}

	return loadDescriptorSetBytes(data)
}

// loadDescriptorSetBytes loads a schema from FileDescriptorSet bytes.
func loadDescriptorSetBytes(data []byte) (*Schema, error) {
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, fds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal FileDescriptorSet: %w", err)
	}

	return LoadFromDescriptorSet(fds)
}
