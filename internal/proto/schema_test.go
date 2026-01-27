package proto

import (
	"testing"

	"google.golang.org/protobuf/types/descriptorpb"
)

func TestNewSchema(t *testing.T) {
	s := NewSchema()
	if s == nil {
		t.Fatal("NewSchema() returned nil")
	}
	if s.files == nil {
		t.Error("NewSchema().files is nil")
	}
	if s.messages == nil {
		t.Error("NewSchema().messages is nil")
	}
	if s.services == nil {
		t.Error("NewSchema().services is nil")
	}
}

func TestLoadFromDescriptorSet(t *testing.T) {
	// Create a minimal FileDescriptorSet with a message and service.
	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    strPtr("test.proto"),
				Package: strPtr("testpkg"),
				MessageType: []*descriptorpb.DescriptorProto{
					{
						Name: strPtr("TestMessage"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:   strPtr("id"),
								Number: int32Ptr(1),
								Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_INT64),
							},
							{
								Name:   strPtr("name"),
								Number: int32Ptr(2),
								Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_STRING),
							},
						},
					},
					{
						Name: strPtr("NestedOuter"),
						NestedType: []*descriptorpb.DescriptorProto{
							{
								Name: strPtr("NestedInner"),
								Field: []*descriptorpb.FieldDescriptorProto{
									{
										Name:   strPtr("value"),
										Number: int32Ptr(1),
										Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_STRING),
									},
								},
							},
						},
					},
				},
				Service: []*descriptorpb.ServiceDescriptorProto{
					{
						Name: strPtr("TestService"),
						Method: []*descriptorpb.MethodDescriptorProto{
							{
								Name:       strPtr("GetTest"),
								InputType:  strPtr(".testpkg.TestMessage"),
								OutputType: strPtr(".testpkg.TestMessage"),
							},
							{
								Name:       strPtr("CreateTest"),
								InputType:  strPtr(".testpkg.TestMessage"),
								OutputType: strPtr(".testpkg.TestMessage"),
							},
						},
					},
				},
			},
		},
	}

	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	// Verify messages were indexed.
	messages := schema.ListMessages()
	if len(messages) < 2 {
		t.Errorf("expected at least 2 messages, got %d", len(messages))
	}

	// Verify services were indexed.
	services := schema.ListServices()
	if len(services) != 1 {
		t.Errorf("expected 1 service, got %d", len(services))
	}
}

func TestFindMessage(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	tests := []struct {
		name    string
		msgName string
		wantErr bool
	}{
		{
			name:    "find by full name",
			msgName: "testpkg.TestMessage",
			wantErr: false,
		},
		{
			name:    "find with leading dot",
			msgName: ".testpkg.TestMessage",
			wantErr: false,
		},
		{
			name:    "find nested message",
			msgName: "testpkg.NestedOuter.NestedInner",
			wantErr: false,
		},
		{
			name:    "not found",
			msgName: "testpkg.NonExistent",
			wantErr: true,
		},
		{
			name:    "wrong package",
			msgName: "wrongpkg.TestMessage",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md, err := schema.FindMessage(tt.msgName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && md == nil {
				t.Error("FindMessage() returned nil without error")
			}
		})
	}
}

func TestFindService(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	tests := []struct {
		name    string
		svcName string
		wantErr bool
	}{
		{
			name:    "find by full name",
			svcName: "testpkg.TestService",
			wantErr: false,
		},
		{
			name:    "find with leading dot",
			svcName: ".testpkg.TestService",
			wantErr: false,
		},
		{
			name:    "not found",
			svcName: "testpkg.NonExistent",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := schema.FindService(tt.svcName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && sd == nil {
				t.Error("FindService() returned nil without error")
			}
		})
	}
}

func TestFindMethod(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	tests := []struct {
		name       string
		methodName string
		wantErr    bool
	}{
		{
			name:       "slash separator",
			methodName: "testpkg.TestService/GetTest",
			wantErr:    false,
		},
		{
			name:       "dot separator",
			methodName: "testpkg.TestService.GetTest",
			wantErr:    false,
		},
		{
			name:       "second method",
			methodName: "testpkg.TestService/CreateTest",
			wantErr:    false,
		},
		{
			name:       "service not found",
			methodName: "testpkg.NonExistent/GetTest",
			wantErr:    true,
		},
		{
			name:       "method not found",
			methodName: "testpkg.TestService/NonExistent",
			wantErr:    true,
		},
		{
			name:       "invalid format - no separator",
			methodName: "InvalidMethodName",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md, err := schema.FindMethod(tt.methodName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindMethod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && md == nil {
				t.Error("FindMethod() returned nil without error")
			}
		})
	}
}

func TestListMessages(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	messages := schema.ListMessages()
	// Should have TestMessage, NestedOuter, and NestedOuter.NestedInner
	if len(messages) < 3 {
		t.Errorf("expected at least 3 messages, got %d: %v", len(messages), messages)
	}

	// Check that expected messages are present.
	found := make(map[string]bool)
	for _, m := range messages {
		found[m] = true
	}
	if !found["testpkg.TestMessage"] {
		t.Error("TestMessage not in list")
	}
	if !found["testpkg.NestedOuter"] {
		t.Error("NestedOuter not in list")
	}
	if !found["testpkg.NestedOuter.NestedInner"] {
		t.Error("NestedOuter.NestedInner not in list")
	}
}

func TestListServices(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	services := schema.ListServices()
	if len(services) != 1 {
		t.Errorf("expected 1 service, got %d: %v", len(services), services)
	}
	if len(services) > 0 && services[0] != "testpkg.TestService" {
		t.Errorf("expected testpkg.TestService, got %s", services[0])
	}
}

func TestLoadFromDescriptorSetError(t *testing.T) {
	// Empty FileDescriptorSet should still work.
	fds := &descriptorpb.FileDescriptorSet{}
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Errorf("LoadFromDescriptorSet() with empty FDS error = %v", err)
	}
	if schema == nil {
		t.Error("expected non-nil schema for empty FDS")
	}
}

// Helper functions to create test data.

func createTestDescriptorSet() *descriptorpb.FileDescriptorSet {
	return &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    strPtr("test.proto"),
				Package: strPtr("testpkg"),
				MessageType: []*descriptorpb.DescriptorProto{
					{
						Name: strPtr("TestMessage"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:   strPtr("id"),
								Number: int32Ptr(1),
								Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_INT64),
							},
							{
								Name:   strPtr("name"),
								Number: int32Ptr(2),
								Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_STRING),
							},
						},
					},
					{
						Name: strPtr("NestedOuter"),
						NestedType: []*descriptorpb.DescriptorProto{
							{
								Name: strPtr("NestedInner"),
								Field: []*descriptorpb.FieldDescriptorProto{
									{
										Name:   strPtr("value"),
										Number: int32Ptr(1),
										Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_STRING),
									},
								},
							},
						},
					},
				},
				Service: []*descriptorpb.ServiceDescriptorProto{
					{
						Name: strPtr("TestService"),
						Method: []*descriptorpb.MethodDescriptorProto{
							{
								Name:       strPtr("GetTest"),
								InputType:  strPtr(".testpkg.TestMessage"),
								OutputType: strPtr(".testpkg.TestMessage"),
							},
							{
								Name:       strPtr("CreateTest"),
								InputType:  strPtr(".testpkg.TestMessage"),
								OutputType: strPtr(".testpkg.TestMessage"),
							},
						},
					},
				},
			},
		},
	}
}

func strPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}

func typePtr(t descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto_Type {
	return &t
}
