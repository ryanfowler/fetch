package fetch

import (
	"net/http"
	"testing"

	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
)

func TestGRPCStatusUsesFinalTrailers(t *testing.T) {
	resp := &http.Response{
		Header:  http.Header{"Grpc-Status": {"0"}},
		Trailer: http.Header{"Grpc-Status": {"5"}, "Grpc-Message": {"not%20found"}},
	}
	status := grpcStatusFromResponse(resp)
	if status == nil {
		t.Fatal("grpcStatusFromResponse() returned nil")
	}
	if status.Code != fetchgrpc.NotFound || status.Message != "not found" {
		t.Fatalf("status = %#v, want NOT_FOUND/not found", status)
	}
}

func TestGRPCStatusUsesInitialHeadersForTrailersOnly(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Grpc-Status":  {"13"},
			"Grpc-Message": {"server%20failed"},
		},
		Trailer: make(http.Header),
	}
	status := grpcStatusFromResponse(resp)
	if status == nil || status.Code != fetchgrpc.Internal || status.Message != "server failed" {
		t.Fatalf("status = %#v, want INTERNAL/server failed", status)
	}
}

func TestGRPCStatusTrailerOKOverridesInitialStatus(t *testing.T) {
	resp := &http.Response{
		Header:  http.Header{"Grpc-Status": {"13"}},
		Trailer: http.Header{"Grpc-Status": {"0"}},
	}
	if status := grpcStatusFromResponse(resp); status != nil {
		t.Fatalf("grpcStatusFromResponse() = %#v, want nil for final OK", status)
	}
}
