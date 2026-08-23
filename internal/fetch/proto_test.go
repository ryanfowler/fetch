package fetch

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
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

func TestFrameGRPCBodyClosesSource(t *testing.T) {
	source := body.NewReader(strings.NewReader("hello"), int64(len("hello")), "")
	framed, err := frameGRPCBody(source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stream, err := framed.Open()
	if err != nil {
		t.Fatalf("unexpected open error: %v", err)
	}
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if err := framed.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestFrameGRPCBodyKnownLengthIsLazyAndReplayable(t *testing.T) {
	var opened int
	source := body.NewFactory(func() (io.ReadCloser, error) {
		opened++
		return io.NopCloser(strings.NewReader("hello")), nil
	}, 5, "", true)

	framed, err := frameGRPCBody(source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opened != 0 {
		t.Fatalf("source opened during framing: %d opens", opened)
	}

	first, err := framed.Open()
	if err != nil {
		t.Fatalf("unexpected first open error: %v", err)
	}
	firstData, err := io.ReadAll(first)
	if err != nil {
		t.Fatalf("unexpected first read error: %v", err)
	}
	first.Close()
	if !bytes.Equal(firstData, fetchgrpc.Frame([]byte("hello"), false)) {
		t.Fatalf("first frame = %x", firstData)
	}

	replay, err := framed.Replay()
	if err != nil {
		t.Fatalf("unexpected replay error: %v", err)
	}
	replayData, err := io.ReadAll(replay)
	if err != nil {
		t.Fatalf("unexpected replay read error: %v", err)
	}
	replay.Close()
	if !bytes.Equal(replayData, firstData) {
		t.Fatalf("replay frame differs from first frame")
	}
	if opened != 2 {
		t.Fatalf("source opens = %d, want one per stream", opened)
	}
	framed.Close()
}

func TestFrameGRPCBodyRejectsKnownOversizeBeforeOpen(t *testing.T) {
	var opened int
	source := body.NewFactory(func() (io.ReadCloser, error) {
		opened++
		return io.NopCloser(strings.NewReader("must not open")), nil
	}, fetchgrpc.MaxMessageSize+1, "", true)

	_, err := frameGRPCBody(source)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("frame error = %v, want a limit error", err)
	}
	if opened != 0 {
		t.Fatalf("oversized source opened %d times", opened)
	}
}

func TestFrameGRPCBodySpoolsUnknownLengthWithBound(t *testing.T) {
	input := &patternReader{remaining: fetchgrpc.MaxMessageSize + 1}
	source := body.NewReader(input, -1, "")

	_, err := frameGRPCBody(source)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("frame error = %v, want a limit error", err)
	}
	if input.read != fetchgrpc.MaxMessageSize+1 {
		t.Fatalf("spool read %d bytes, want exactly MaxMessageSize+1", input.read)
	}
	if !input.closed {
		t.Fatal("unknown-length source was not closed after spooling")
	}
}

func TestFrameGRPCBodySupportsRetryReplayAfterSpooling(t *testing.T) {
	source := body.NewReader(strings.NewReader("payload"), -1, "")
	framed, err := frameGRPCBody(source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer framed.Close()

	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	body.Attach(req, framed)
	replayer, err := newReplayableBody(req)
	if err != nil {
		t.Fatalf("unexpected replayer error: %v", err)
	}
	defer replayer.close()

	first, err := replayer.reset()
	if err != nil {
		t.Fatalf("unexpected first reset error: %v", err)
	}
	firstData, err := io.ReadAll(first)
	first.Close()
	if err != nil {
		t.Fatalf("unexpected first replay read error: %v", err)
	}
	second, err := replayer.reset()
	if err != nil {
		t.Fatalf("unexpected second reset error: %v", err)
	}
	secondData, err := io.ReadAll(second)
	second.Close()
	if err != nil {
		t.Fatalf("unexpected second replay read error: %v", err)
	}
	if !bytes.Equal(firstData, secondData) || !bytes.Equal(firstData, fetchgrpc.Frame([]byte("payload"), false)) {
		t.Fatalf("replay data did not preserve the framed payload")
	}
}

func TestFrameGRPCBodySupportsDigestReplayAfterSpooling(t *testing.T) {
	var received [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read authenticated body: %v", err)
		}
		received = append(received, data)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	framed, err := frameGRPCBody(body.NewReader(strings.NewReader("payload"), -1, ""))
	if err != nil {
		t.Fatalf("unexpected framing error: %v", err)
	}
	defer framed.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	body.Attach(req, framed)
	replayer, err := newReplayableBody(req)
	if err != nil {
		t.Fatalf("unexpected replayer error: %v", err)
	}
	defer replayer.close()
	requestBody, err := replayer.reset()
	if err != nil {
		t.Fatalf("unexpected request body error: %v", err)
	}
	req.Body = requestBody

	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	resp, err := doOnce(&Request{Digest: &core.KeyVal[string]{Key: "user", Val: "pass"}}, c, req, replayer)
	if err != nil {
		t.Fatalf("digest request failed: %v", err)
	}
	defer resp.Body.Close()

	want := fetchgrpc.Frame([]byte("payload"), false)
	if len(received) != 1 || !bytes.Equal(received[0], want) {
		t.Fatalf("authenticated bodies = %d/%x, want one framed payload %x", len(received), received, want)
	}
}

type patternReader struct {
	remaining int64
	read      int64
	closed    bool
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.remaining -= int64(len(p))
	r.read += int64(len(p))
	return len(p), nil
}

func (r *patternReader) Close() error {
	r.closed = true
	return nil
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

func TestSetStreamingGRPCBodyWrapsGetBody(t *testing.T) {
	desc := testMessageDescriptor(t)
	req := &http.Request{
		Body: io.NopCloser(strings.NewReader(`{"name":"first"}`)),
		GetBody: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(`{"name":"replay"}`)), nil
		},
		ContentLength: int64(len(`{"name":"first"}`)),
	}

	setStreamingGRPCBody(req, desc)
	if req.ContentLength != -1 {
		t.Fatalf("expected unknown content length, got %d", req.ContentLength)
	}

	frames := readAllFrames(t, req.Body)
	if len(frames) != 1 {
		t.Fatalf("expected current body to contain 1 framed message, got %d", len(frames))
	}

	replay, err := req.GetBody()
	if err != nil {
		t.Fatalf("unexpected GetBody error: %v", err)
	}
	defer replay.Close()
	frames = readAllFrames(t, replay)
	if len(frames) != 1 {
		t.Fatalf("expected replay body to contain 1 framed message, got %d", len(frames))
	}
}

func TestSetStreamingGRPCBodyClearsMissingGetBody(t *testing.T) {
	desc := testMessageDescriptor(t)
	req := &http.Request{
		Body:          io.NopCloser(strings.NewReader(`{"name":"first"}`)),
		ContentLength: int64(len(`{"name":"first"}`)),
	}

	setStreamingGRPCBody(req, desc)
	if req.GetBody != nil {
		t.Fatal("expected GetBody to remain nil")
	}
	if req.ContentLength != -1 {
		t.Fatalf("expected unknown content length, got %d", req.ContentLength)
	}
	frames := readAllFrames(t, req.Body)
	if len(frames) != 1 {
		t.Fatalf("expected current body to contain 1 framed message, got %d", len(frames))
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
