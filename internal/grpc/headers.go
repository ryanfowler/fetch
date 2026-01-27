package grpc

import "github.com/ryanfowler/fetch/internal/core"

// ContentType is the Content-Type header value for gRPC requests.
const ContentType = "application/grpc+proto"

// Headers returns the standard headers for gRPC requests.
func Headers() []core.KeyVal[string] {
	return []core.KeyVal[string]{
		{Key: "Content-Type", Val: ContentType},
		{Key: "Te", Val: "trailers"},
	}
}

// AcceptHeader returns the Accept header for gRPC requests.
func AcceptHeader() core.KeyVal[string] {
	return core.KeyVal[string]{Key: "Accept", Val: ContentType}
}
