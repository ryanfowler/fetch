package fetch

import (
	"bytes"
	"io"
	"strings"
	"testing"

	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	"github.com/ryanfowler/fetch/internal/proto"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestStreamGRPCRequest(t *testing.T) {
	desc := testMessageDescriptor(t)

	t.Run("single message", func(t *testing.T) {
		input := `{"name":"hello"}`
		rc := streamGRPCRequest(io.NopCloser(strings.NewReader(input)), desc)
		defer rc.Close()

		frames := readAllFrames(t, rc)
		if len(frames) != 1 {
			t.Fatalf("expected 1 frame, got %d", len(frames))
		}
	})

	t.Run("multiple messages", func(t *testing.T) {
		input := `{"name":"one"}{"name":"two"}{"name":"three"}`
		rc := streamGRPCRequest(io.NopCloser(strings.NewReader(input)), desc)
		defer rc.Close()

		frames := readAllFrames(t, rc)
		if len(frames) != 3 {
			t.Fatalf("expected 3 frames, got %d", len(frames))
		}
	})

	t.Run("ndjson style", func(t *testing.T) {
		input := "{\"name\":\"one\"}\n{\"name\":\"two\"}\n{\"name\":\"three\"}\n"
		rc := streamGRPCRequest(io.NopCloser(strings.NewReader(input)), desc)
		defer rc.Close()

		frames := readAllFrames(t, rc)
		if len(frames) != 3 {
			t.Fatalf("expected 3 frames, got %d", len(frames))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		rc := streamGRPCRequest(io.NopCloser(strings.NewReader("")), desc)
		defer rc.Close()

		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 0 {
			t.Fatalf("expected empty output, got %d bytes", len(data))
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		rc := streamGRPCRequest(io.NopCloser(strings.NewReader("{invalid")), desc)
		defer rc.Close()

		_, err := io.ReadAll(rc)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "failed to decode JSON message") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("whitespace between objects", func(t *testing.T) {
		input := "  {\"name\":\"one\"}  \n\n  {\"name\":\"two\"}  "
		rc := streamGRPCRequest(io.NopCloser(strings.NewReader(input)), desc)
		defer rc.Close()

		frames := readAllFrames(t, rc)
		if len(frames) != 2 {
			t.Fatalf("expected 2 frames, got %d", len(frames))
		}
	})
}

func TestConvertJSONToProtobufClosesBody(t *testing.T) {
	desc := testMessageDescriptor(t)
	body := &trackingReadCloser{Reader: strings.NewReader(`{"name":"hello"}`)}

	if _, err := convertJSONToProtobuf(body, desc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !body.closed {
		t.Fatal("expected convertJSONToProtobuf to close body")
	}
}

func TestFrameGRPCRequestClosesBody(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader("hello")}

	if _, err := frameGRPCRequest(body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !body.closed {
		t.Fatal("expected frameGRPCRequest to close body")
	}
}

func TestStreamGRPCRequestClosesBody(t *testing.T) {
	desc := testMessageDescriptor(t)
	body := &trackingReadCloser{Reader: strings.NewReader(`{"name":"hello"}`)}
	rc := streamGRPCRequest(body, desc)
	defer rc.Close()

	_ = readAllFrames(t, rc)
	if !body.closed {
		t.Fatal("expected streamGRPCRequest to close body")
	}
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

// testMessageDescriptor builds a simple protobuf message descriptor for testing.
func testMessageDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()

	strType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	int64Type := descriptorpb.FieldDescriptorProto_TYPE_INT64
	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    new("test.proto"),
				Package: new("testpkg"),
				Syntax:  new("proto3"),
				MessageType: []*descriptorpb.DescriptorProto{
					{
						Name: new("TestMessage"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:   new("id"),
								Number: new(int32(1)),
								Type:   &int64Type,
							},
							{
								Name:   new("name"),
								Number: new(int32(2)),
								Type:   &strType,
							},
						},
					},
				},
			},
		},
	}

	schema, err := proto.LoadFromDescriptorSet(fds)
	if err != nil {
		t.Fatalf("failed to load descriptor set: %v", err)
	}
	md, err := schema.FindMessage("testpkg.TestMessage")
	if err != nil {
		t.Fatalf("failed to find message: %v", err)
	}
	return md
}

// readAllFrames reads all gRPC frames from a reader.
func readAllFrames(t *testing.T, r io.Reader) [][]byte {
	t.Helper()

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read all data: %v", err)
	}

	var frames [][]byte
	reader := bytes.NewReader(data)
	for {
		frame, _, err := fetchgrpc.ReadFrame(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read frame: %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}
