package fetch

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
// Returns request/response descriptors, whether the method is client- or
// server-streaming, and any error. The streaming information is kept separate
// from the descriptors because a schema-less binary call can still be sent
// when reflection is unavailable, but a bounded HAR capture cannot safely
// assume that such a call is unary.
func setupGRPC(r *Request, schema *proto.Schema) (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, bool, bool, error) {
	var requestDesc, responseDesc protoreflect.MessageDescriptor
	var isClientStreaming, isServerStreaming bool
	if schema != nil && r.URL != nil {
		serviceName, methodName, err := parseGRPCPath(r.URL.Path)
		if err != nil {
			return nil, nil, false, false, err
		}

		fullMethod := serviceName + "/" + methodName
		method, err := schema.FindMethod(fullMethod)
		if err != nil {
			return nil, nil, false, false, err
		}
		requestDesc = method.Input()
		responseDesc = method.Output()
		isClientStreaming = method.IsStreamingClient()
		isServerStreaming = method.IsStreamingServer()
	}

	return requestDesc, responseDesc, isClientStreaming, isServerStreaming, nil
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

// materializeGRPCDryRunBody makes protocol conversion deterministic without
// opening a request source more than once. It is intentionally called only
// when a descriptor is available and JSON must be converted; raw binary
// dry-runs remain one-shot and lazy.
func materializeGRPCDryRunBody(req *http.Request) error {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	source, ok := body.SourceFromContext(req.Context())
	if !ok || source == nil {
		return errors.New("gRPC request body source is unavailable")
	}
	if source.Replayable() {
		return nil
	}
	if _, err := source.Materialize(core.MaxCompositeMaterialization); err != nil {
		return fmt.Errorf("failed to materialize gRPC request body for dry-run: %w", err)
	}
	// Materialize changes the source to replayable, but req.GetBody still
	// reflects the pre-materialization one-shot state. Reattach it so the
	// streaming conversion and preview use the same replay contract.
	body.Attach(req, source)
	return nil
}

// dryRunGRPCBody adds the five-byte gRPC frame header lazily. A lengthless
// source must be materialized because the frame header cannot be emitted
// until the message length is known. This is a protocol conversion, so the
// shared 16 MiB materialization cap applies and a one-shot source is consumed
// at most once.
func dryRunGRPCBody(source *body.Body) (*body.Body, error) {
	if source == nil || source.ContentLength() == 0 {
		framed, err := fetchgrpc.FrameChecked(nil, false)
		if err != nil {
			return nil, err
		}
		return body.NewBytes(framed, fetchgrpc.ContentType), nil
	}
	length := source.ContentLength()
	if length < 0 {
		if _, err := source.Materialize(fetchgrpc.MaxMessageSize); err != nil {
			return nil, fmt.Errorf("failed to materialize gRPC request body for dry-run: %w", err)
		}
		length = source.ContentLength()
	}
	if length > fetchgrpc.MaxMessageSize {
		return nil, core.LimitError{Subsystem: "gRPC request body", Limit: fetchgrpc.MaxMessageSize}
	}
	framedLength, err := fetchgrpc.CheckedFrameLength(length)
	if err != nil {
		return nil, err
	}
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

// frameGRPCBody creates a lazy replayable unary gRPC body. Known-length
// sources are never opened while constructing the frame; the five-byte header
// is emitted immediately before each source stream.
//
// Unknown-length sources are consumed once into a private temporary file. The
// extra byte distinguishes an exact-limit body from an oversized one without
// retaining the payload in memory, and the resulting file is replayable for
// retries and authentication.
func frameGRPCBody(source *body.Body) (*body.Body, error) {
	if source == nil || source.ContentLength() >= 0 {
		length := int64(0)
		if source != nil {
			length = source.ContentLength()
		}
		return newFramedGRPCBody(source, length)
	}

	spooled, err := spoolGRPCBody(source)
	if err != nil {
		return nil, err
	}
	return newFramedGRPCBody(spooled, spooled.ContentLength())
}

func newFramedGRPCBody(source *body.Body, length int64) (*body.Body, error) {
	if length > fetchgrpc.MaxMessageSize {
		return nil, core.LimitError{Subsystem: "gRPC request body", Limit: fetchgrpc.MaxMessageSize}
	}
	frameLength, err := fetchgrpc.CheckedFrameLength(length)
	if err != nil {
		return nil, err
	}

	open := func() (io.ReadCloser, error) {
		var stream io.ReadCloser = http.NoBody
		if source != nil {
			var openErr error
			stream, openErr = source.Open()
			if openErr != nil {
				return nil, openErr
			}
		}
		var header [5]byte
		binary.BigEndian.PutUint32(header[1:], uint32(length))
		if source == nil {
			return newReaderWithCloser(bytes.NewReader(header[:]), stream), nil
		}
		return newReaderWithCloser(io.MultiReader(bytes.NewReader(header[:]), stream), stream), nil
	}

	framed := body.NewFactory(open, frameLength, fetchgrpc.ContentType, source == nil || source.Replayable())
	if source != nil {
		// Closing before the first read must still release a spool file. Keep
		// source cleanup at the body level so closing a replay stream does not
		// remove the file needed by a later retry.
		framed.SetCleanup(source.Close)
	}
	return framed, nil
}

func spoolGRPCBody(source *body.Body) (*body.Body, error) {
	stream, err := source.Open()
	if err != nil {
		return nil, err
	}
	defer source.Close()

	f, err := os.CreateTemp("", "fetch-grpc-*")
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("failed to create gRPC request spool: %w", err)
	}
	path := f.Name()
	remove := func() { _ = os.Remove(path) }

	count, copyErr := io.Copy(f, io.LimitReader(stream, fetchgrpc.MaxMessageSize+1))
	streamCloseErr := stream.Close()
	fileCloseErr := f.Close()
	if copyErr != nil || streamCloseErr != nil || fileCloseErr != nil {
		remove()
		return nil, errors.Join(
			wrapGRPCSpoolError("read", copyErr),
			wrapGRPCSpoolError("close input", streamCloseErr),
			wrapGRPCSpoolError("close spool", fileCloseErr),
		)
	}
	if count > fetchgrpc.MaxMessageSize {
		remove()
		return nil, core.LimitError{Subsystem: "gRPC request body", Limit: fetchgrpc.MaxMessageSize}
	}

	spooled, err := body.NewFile(path, fetchgrpc.ContentType)
	if err != nil {
		remove()
		return nil, err
	}
	spooled.SetCleanup(func() error { return os.Remove(path) })
	return spooled, nil
}

func wrapGRPCSpoolError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to %s gRPC request spool: %w", operation, err)
}

// streamGRPCRequest reads JSON values from data, converts each to protobuf,
// frames each as a gRPC message, and streams them through an io.Pipe.
//
// A jsontext.Decoder may read beyond one value into its internal buffer. The
// small forwarding buffer below returns decoder.UnreadBuffer to the shared input
// before the next decoder is created; without it, adjacent messages can be
// silently lost.
func streamGRPCRequest(data io.ReadCloser, desc protoreflect.MessageDescriptor) io.ReadCloser {
	pr, pw := io.Pipe()
	input := &closeOnceReadCloser{ReadCloser: data}
	go func() {
		defer pw.Close()
		defer input.Close()

		jsonInput := &streamJSONInput{r: input}
		for {
			limited := &boundedJSONReader{r: jsonInput, max: core.MaxCompositeMaterialization}
			decoder := jsontext.NewDecoder(limited)
			raw, err := decoder.ReadValue()
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
			protoData, err := proto.JSONToProtobuf([]byte(raw), desc)
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

			// The decoder owns any bytes it read after the current value. Return
			// them to the forwarding reader before decoding the next value. The
			// reader is bounded so this cannot turn a look-ahead into an
			// unbounded allocation.
			if err := jsonInput.prepend(decoder.UnreadBuffer()); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to buffer JSON message: %w", err))
				return
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

// streamJSONInput preserves the bytes that jsontext.Decoder read ahead of the
// current value. It is used by one producer goroutine only.
type streamJSONInput struct {
	r       io.Reader
	pending []byte
}

func (r *streamJSONInput) Read(p []byte) (int, error) {
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	return r.r.Read(p)
}

func (r *streamJSONInput) prepend(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if int64(len(data)) > core.MaxCompositeMaterialization || int64(len(r.pending)) > core.MaxCompositeMaterialization-int64(len(data)) {
		return core.LimitError{Subsystem: "gRPC request body", Limit: core.MaxCompositeMaterialization}
	}
	pendingLength := len(data) + len(r.pending)
	pending := make([]byte, 0, pendingLength)
	pending = append(pending, data...)
	pending = append(pending, r.pending...)
	r.pending = pending
	return nil
}

// boundedJSONReader prevents a single JSON value from making the decoder read
// without a bound. One extra byte lets a valid value be distinguished from a
// value that is exactly at the limit.
type boundedJSONReader struct {
	r    io.Reader
	max  int64
	read int64
}

func (r *boundedJSONReader) Read(p []byte) (int, error) {
	if r.read >= r.max+1 {
		return 0, core.LimitError{Subsystem: "gRPC request body", Limit: r.max}
	}
	remaining := r.max + 1 - r.read
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.r.Read(p)
	r.read += int64(n)
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
