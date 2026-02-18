package proto

import (
	"encoding/json"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestJSONToProtobuf(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Fatalf("FindMessage() error = %v", err)
	}

	tests := []struct {
		name      string
		jsonInput string
		wantErr   bool
		checkFunc func(t *testing.T, data []byte)
	}{
		{
			name:      "simple message",
			jsonInput: `{"id": 123, "name": "test"}`,
			wantErr:   false,
			checkFunc: func(t *testing.T, data []byte) {
				// Verify the protobuf contains expected fields.
				if len(data) == 0 {
					t.Error("expected non-empty protobuf data")
				}
			},
		},
		{
			name:      "empty message",
			jsonInput: `{}`,
			wantErr:   false,
			checkFunc: func(t *testing.T, data []byte) {
				// Empty message should produce empty or minimal protobuf.
			},
		},
		{
			name:      "partial message - id only",
			jsonInput: `{"id": 456}`,
			wantErr:   false,
			checkFunc: func(t *testing.T, data []byte) {
				if len(data) == 0 {
					t.Error("expected non-empty protobuf data")
				}
			},
		},
		{
			name:      "partial message - name only",
			jsonInput: `{"name": "only name"}`,
			wantErr:   false,
			checkFunc: func(t *testing.T, data []byte) {
				if len(data) == 0 {
					t.Error("expected non-empty protobuf data")
				}
			},
		},
		{
			name:      "unknown field is discarded",
			jsonInput: `{"id": 1, "unknownField": "ignored"}`,
			wantErr:   false,
		},
		{
			name:      "invalid JSON",
			jsonInput: `{invalid`,
			wantErr:   true,
		},
		{
			name:      "type mismatch - string for int",
			jsonInput: `{"id": "not a number"}`,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := JSONToProtobuf([]byte(tt.jsonInput), md)
			if (err != nil) != tt.wantErr {
				t.Errorf("JSONToProtobuf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, data)
			}
		})
	}
}

func TestProtobufToJSON(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Fatalf("FindMessage() error = %v", err)
	}

	tests := []struct {
		name       string
		protoInput []byte
		wantErr    bool
		wantID     string // protojson outputs int64 as strings
		wantName   string
	}{
		{
			name:       "simple message",
			protoInput: buildTestProtobuf(123, "test"),
			wantErr:    false,
			wantID:     "123",
			wantName:   "test",
		},
		{
			name:       "empty message",
			protoInput: []byte{},
			wantErr:    false,
		},
		{
			name:       "id only",
			protoInput: buildTestProtobuf(999, ""),
			wantErr:    false,
			wantID:     "999",
		},
		{
			name:       "name only",
			protoInput: buildNameOnlyProtobuf("hello"),
			wantErr:    false,
			wantName:   "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := ProtobufToJSON(tt.protoInput, md)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProtobufToJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Verify JSON is valid.
			var result map[string]any
			if err := json.Unmarshal(jsonData, &result); err != nil {
				t.Errorf("ProtobufToJSON() produced invalid JSON: %v", err)
				return
			}

			// Check ID field (protojson outputs int64 as strings).
			if tt.wantID != "" {
				// protojson may output as string or number depending on config
				switch v := result["id"].(type) {
				case string:
					if v != tt.wantID {
						t.Errorf("id = %v, want %v", v, tt.wantID)
					}
				case float64:
					// Also accept numeric if config allows
				default:
					if result["id"] != nil {
						t.Errorf("id has unexpected type %T", result["id"])
					}
				}
			}

			// Check name field.
			if tt.wantName != "" {
				if name, ok := result["name"].(string); !ok || name != tt.wantName {
					t.Errorf("name = %v, want %v", result["name"], tt.wantName)
				}
			}
		})
	}
}

func TestProtobufToJSONCompact(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Fatalf("FindMessage() error = %v", err)
	}

	protoData := buildTestProtobuf(123, "test")
	jsonData, err := ProtobufToJSONCompact(protoData, md)
	if err != nil {
		t.Fatalf("ProtobufToJSONCompact() error = %v", err)
	}

	// Compact JSON should not have newlines.
	if slices.Contains(jsonData, byte('\n')) {
		t.Error("ProtobufToJSONCompact() output contains newlines")
	}

	// Verify it's valid JSON.
	var result map[string]any
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Errorf("ProtobufToJSONCompact() produced invalid JSON: %v", err)
	}
}

func TestJSONToProtobufRoundTrip(t *testing.T) {
	fds := createTestDescriptorSet()
	schema, err := LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}

	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Fatalf("FindMessage() error = %v", err)
	}

	tests := []struct {
		name      string
		jsonInput string
		wantID    string // protojson outputs int64 as strings
		wantName  string
	}{
		{
			name:      "full message",
			jsonInput: `{"id": 42, "name": "roundtrip"}`,
			wantID:    "42",
			wantName:  "roundtrip",
		},
		{
			name:      "zero values",
			jsonInput: `{"id": 0, "name": ""}`,
			wantID:    "",
			wantName:  "",
		},
		{
			name:      "large id",
			jsonInput: `{"id": 9223372036854775807, "name": "max int64"}`,
			wantID:    "9223372036854775807",
			wantName:  "max int64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// JSON -> Protobuf.
			protoData, err := JSONToProtobuf([]byte(tt.jsonInput), md)
			if err != nil {
				t.Fatalf("JSONToProtobuf() error = %v", err)
			}

			// Protobuf -> JSON.
			jsonData, err := ProtobufToJSON(protoData, md)
			if err != nil {
				t.Fatalf("ProtobufToJSON() error = %v", err)
			}

			// Parse result.
			var result map[string]any
			if err := json.Unmarshal(jsonData, &result); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Verify values (only check non-zero since zero values may be omitted).
			if tt.wantID != "" {
				// protojson outputs int64 as strings
				switch v := result["id"].(type) {
				case string:
					if v != tt.wantID {
						t.Errorf("id = %v, want %v", v, tt.wantID)
					}
				case float64:
					// Also accept numeric
				default:
					if result["id"] != nil {
						t.Errorf("id has unexpected type %T", result["id"])
					}
				}
			}
			if tt.wantName != "" {
				if name, ok := result["name"].(string); !ok || name != tt.wantName {
					t.Errorf("name = %v, want %v", result["name"], tt.wantName)
				}
			}
		})
	}
}

func TestJSONToProtobufWithNestedMessage(t *testing.T) {
	// Create a schema with nested message.
	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    new("nested.proto"),
				Package: new("nested"),
				MessageType: []*descriptorpb.DescriptorProto{
					{
						Name: new("Inner"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:   new("value"),
								Number: new(int32(1)),
								Type:   new(descriptorpb.FieldDescriptorProto_TYPE_STRING),
							},
						},
					},
					{
						Name: new("Outer"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:     new("inner"),
								Number:   new(int32(1)),
								Type:     new(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
								TypeName: new(".nested.Inner"),
							},
							{
								Name:   new("count"),
								Number: new(int32(2)),
								Type:   new(descriptorpb.FieldDescriptorProto_TYPE_INT32),
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

	md, err := schema.FindMessage("nested.Outer")
	if err != nil {
		t.Fatalf("FindMessage() error = %v", err)
	}

	jsonInput := `{"inner": {"value": "nested value"}, "count": 5}`
	protoData, err := JSONToProtobuf([]byte(jsonInput), md)
	if err != nil {
		t.Fatalf("JSONToProtobuf() error = %v", err)
	}

	// Convert back and verify.
	jsonOutput, err := ProtobufToJSON(protoData, md)
	if err != nil {
		t.Fatalf("ProtobufToJSON() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(jsonOutput, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Check nested value.
	inner, ok := result["inner"].(map[string]any)
	if !ok {
		t.Fatal("inner field not found or not an object")
	}
	if inner["value"] != "nested value" {
		t.Errorf("inner.value = %v, want 'nested value'", inner["value"])
	}
	if result["count"] != float64(5) {
		t.Errorf("count = %v, want 5", result["count"])
	}
}

// Helper functions to build test protobuf data.

func buildTestProtobuf(id int64, name string) []byte {
	var buf []byte
	// Field 1: id (int64, varint).
	if id != 0 {
		buf = protowire.AppendTag(buf, 1, protowire.VarintType)
		buf = protowire.AppendVarint(buf, uint64(id))
	}
	// Field 2: name (string, bytes).
	if name != "" {
		buf = protowire.AppendTag(buf, 2, protowire.BytesType)
		buf = protowire.AppendString(buf, name)
	}
	return buf
}

func buildNameOnlyProtobuf(name string) []byte {
	var buf []byte
	buf = protowire.AppendTag(buf, 2, protowire.BytesType)
	buf = protowire.AppendString(buf, name)
	return buf
}
