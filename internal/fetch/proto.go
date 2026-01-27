package fetch

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	"github.com/ryanfowler/fetch/internal/proto"

	"google.golang.org/protobuf/reflect/protoreflect"
)

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
// Returns headers to add, HTTP version, and request/response descriptors.
func setupGRPC(r *Request, schema *proto.Schema) (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, error) {
	var requestDesc, responseDesc protoreflect.MessageDescriptor
	if schema != nil && r.URL != nil {
		serviceName, methodName, err := parseGRPCPath(r.URL.Path)
		if err != nil {
			return nil, nil, err
		}

		fullMethod := serviceName + "/" + methodName
		method, err := schema.FindMethod(fullMethod)
		if err != nil {
			return nil, nil, err
		}
		requestDesc = method.Input()
		responseDesc = method.Output()
	}

	if r.HTTP == core.HTTPDefault {
		r.HTTP = core.HTTP2
	}
	if r.Method == "" {
		r.Method = "POST"
	}
	r.Headers = append(r.Headers, fetchgrpc.Headers()...)
	r.Headers = append(r.Headers, fetchgrpc.AcceptHeader())

	return requestDesc, responseDesc, nil
}

// convertJSONToProtobuf converts JSON body to protobuf.
func convertJSONToProtobuf(data io.Reader, desc protoreflect.MessageDescriptor) (io.Reader, error) {
	// Read all the JSON data.
	jsonData, err := io.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Convert JSON to protobuf.
	protoData, err := proto.JSONToProtobuf(jsonData, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JSON to protobuf: %w", err)
	}

	return bytes.NewReader(protoData), nil
}

// frameGRPCRequest wraps data in gRPC framing.
// Handles nil/empty body by sending an empty framed message.
func frameGRPCRequest(data io.Reader) (io.Reader, error) {
	var rawData []byte
	if data != nil && data != http.NoBody {
		var err error
		rawData, err = io.ReadAll(data)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// Frame with gRPC format (works for empty data too).
	framedData := fetchgrpc.Frame(rawData, false)
	return bytes.NewReader(framedData), nil
}
