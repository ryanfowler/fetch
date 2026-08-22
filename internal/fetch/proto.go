package fetch

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/core"
	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	"github.com/ryanfowler/fetch/internal/proto"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// checkGRPCStatus checks gRPC status from trailers (or headers for
// trailers-only responses) and prints an error to stderr if the status
// is non-OK. Returns the updated exit code.
func checkGRPCStatus(r *Request, resp *http.Response, exitCode int) int {
	status := grpcStatusFromResponse(resp)
	if status == nil {
		return exitCode
	}

	p := r.PrinterHandle.Stderr()
	core.WriteErrorMsg(p, status)

	if exitCode == 0 {
		return 1
	}
	return exitCode
}

// loadProtoSchema loads schema from files or descriptor set.
func loadProtoSchema(r *Request) (*proto.Schema, error) {
	if len(r.ProtoFiles) > 0 {
		return proto.CompileProtos(r.ProtoFiles, r.ProtoImports)
	}
	if r.ProtoDesc != "" {
		return proto.LoadDescriptorSetFile(r.ProtoDesc)
	}
	return nil, nil
}

// parseGRPCPath extracts service and method names from URL path.
// Expected format: /package.Service/Method
func parseGRPCPath(urlPath string) (serviceName, methodName string, err error) {
	path := strings.TrimPrefix(urlPath, "/")

	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid gRPC path: expected '/Service/Method' format")
	}

	serviceName = path[:idx]
	methodName = path[idx+1:]

	if serviceName == "" || methodName == "" {
		return "", "", fmt.Errorf("invalid gRPC path: service and method cannot be empty")
	}

	return serviceName, methodName, nil
}

// setupGRPC configures request for gRPC protocol.
// Returns request/response descriptors, whether the method is client-streaming, and any error.
func setupGRPC(r *Request, schema *proto.Schema) (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, bool, error) {
	var requestDesc, responseDesc protoreflect.MessageDescriptor
	var isClientStreaming bool
	if schema != nil && r.URL != nil {
		serviceName, methodName, err := parseGRPCPath(r.URL.Path)
		if err != nil {
			return nil, nil, false, err
		}

		fullMethod := serviceName + "/" + methodName
		method, err := schema.FindMethod(fullMethod)
		if err != nil {
			return nil, nil, false, err
		}
		requestDesc = method.Input()
		responseDesc = method.Output()
		isClientStreaming = method.IsStreamingClient()
	}

	return requestDesc, responseDesc, isClientStreaming, nil
}

// convertJSONToProtobuf converts JSON body to protobuf.
func convertJSONToProtobuf(data io.ReadCloser, desc protoreflect.MessageDescriptor) ([]byte, error) {
	defer data.Close()

	// JSON-to-protobuf conversion is one of the explicitly materializing
	// protocol paths. Keep it bounded rather than turning generated input into
	// an unbounded in-memory upload.
	jsonData, err := core.ReadAllLimited(data, core.MaxCompositeMaterialization, "gRPC request body")
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Convert JSON to protobuf.
	protoData, err := proto.JSONToProtobuf(jsonData, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JSON to protobuf: %w", err)
	}

	return protoData, nil
}

// dryRunGRPCBody adds the five-byte gRPC frame header lazily. Replayable
// sources remain streamable and files are not materialized just to display a
// preview. One-shot sources are retained as one-shot and are not opened by
// dry-run's preview path.
func dryRunGRPCBody(source *body.Body) (*body.Body, error) {
	if source == nil || source.ContentLength() == 0 {
		framed, err := fetchgrpc.FrameChecked(nil, false)
		if err != nil {
			return nil, err
		}
		return body.NewBytes(framed, fetchgrpc.ContentType), nil
	}
	length := source.ContentLength()
	// A lengthless stream cannot carry a frame header without first reading
	// the whole stream. Leave it untouched; dry-run will report that its
	// one-shot/streaming preview is unavailable instead of consuming it.
	if length < 0 {
		return source, nil
	}
	if length > fetchgrpc.MaxMessageSize {
		return nil, core.LimitError{Subsystem: "gRPC request body", Limit: fetchgrpc.MaxMessageSize}
	}
	framedLength := length + 5
	open := func() (io.ReadCloser, error) {
		stream, err := source.Open()
		if err != nil {
			return nil, err
		}
		var header [5]byte
		binary.BigEndian.PutUint32(header[1:], uint32(length))
		return newReaderWithCloser(io.MultiReader(bytes.NewReader(header[:]), stream), stream), nil
	}
	return body.NewFactory(open, framedLength, fetchgrpc.ContentType, source.Replayable()), nil
}

// frameGRPCRequest wraps data in gRPC framing.
// Handles nil/empty body by sending an empty framed message.
func frameGRPCRequest(data io.ReadCloser) ([]byte, error) {
	var rawData []byte
	if data != nil && data != http.NoBody {
		defer data.Close()

		var err error
		rawData, err = core.ReadAllLimited(data, core.MaxCompositeMaterialization, "gRPC request body")
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// Frame with gRPC format (works for empty data too).
	framedData, err := fetchgrpc.FrameChecked(rawData, false)
	if err != nil {
		return nil, err
	}
	return framedData, nil
}

// streamGRPCRequest reads JSON objects from data, converts each to protobuf,
// frames each as a gRPC message, and streams them through an io.Pipe.
// Returns an io.ReadCloser to use as the request body.
func streamGRPCRequest(data io.ReadCloser, desc protoreflect.MessageDescriptor) io.ReadCloser {
	pr, pw := io.Pipe()
	input := &closeOnceReadCloser{ReadCloser: data}
	go func() {
		defer pw.Close()
		defer input.Close()

		for {
			decoder := json.NewDecoder(&boundedJSONReader{r: input, max: core.MaxCompositeMaterialization})
			var raw json.RawMessage
			err := decoder.Decode(&raw)
			if err == io.EOF {
				return
			}
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to decode JSON message: %w", err))
				return
			}
			if int64(len(raw)) > core.MaxCompositeMaterialization {
				pw.CloseWithError(core.LimitError{Subsystem: "gRPC request body", Limit: core.MaxCompositeMaterialization})
				return
			}
			protoData, err := proto.JSONToProtobuf(raw, desc)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to convert JSON to protobuf: %w", err))
				return
			}
			frame, err := fetchgrpc.FrameChecked(protoData, false)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if _, err := pw.Write(frame); err != nil {
				return // pipe closed by reader
			}
		}
	}()
	return &grpcPipeReader{PipeReader: pr, input: input}
}

type closeOnceReadCloser struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (r *closeOnceReadCloser) Close() error {
	r.once.Do(func() { r.err = r.ReadCloser.Close() })
	return r.err
}

type grpcPipeReader struct {
	*io.PipeReader
	input *closeOnceReadCloser
}

func (r *grpcPipeReader) Close() error {
	return errors.Join(r.PipeReader.Close(), r.input.Close())
}

type boundedJSONReader struct {
	r     io.Reader
	max   int64
	bytes int64
}

func (r *boundedJSONReader) Read(p []byte) (int, error) {
	if r.bytes >= r.max+1 {
		return 0, core.LimitError{Subsystem: "gRPC request body", Limit: r.max}
	}
	if len(p) > 1 {
		p = p[:1]
	}
	n, err := r.r.Read(p)
	r.bytes += int64(n)
	return n, err
}

func setStreamingGRPCBody(req *http.Request, desc protoreflect.MessageDescriptor) {
	first := req.Body
	getBody := req.GetBody
	var openMu sync.Mutex
	usedFirst := false
	open := func() (io.ReadCloser, error) {
		openMu.Lock()
		if !usedFirst {
			usedFirst = true
			openMu.Unlock()
			return streamGRPCRequest(first, desc), nil
		}
		openMu.Unlock()
		if getBody == nil {
			return nil, body.ErrNotReplayable
		}
		raw, err := getBody()
		if err != nil {
			return nil, err
		}
		return streamGRPCRequest(raw, desc), nil
	}
	source := body.NewFactory(open, -1, req.Header.Get("Content-Type"), getBody != nil)
	body.Attach(req, source)
}
