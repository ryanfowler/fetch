package fetch

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	iproto "github.com/ryanfowler/fetch/internal/proto"

	"google.golang.org/protobuf/encoding/protowire"
	gproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestReadGRPCFramesEnforcesReflectionMessageLimit(t *testing.T) {
	var wire bytes.Buffer
	for range core.MaxReflectionMessages + 1 {
		frame, err := fetchgrpc.FrameChecked(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(frame)
	}
	if _, err := readGRPCFrames(&wire, ""); err == nil || !strings.Contains(err.Error(), "reflection response exceeds 128 messages") {
		t.Fatalf("readGRPCFrames() error = %v, want reflection message limit", err)
	}
}

func TestReflectionClientFallsBackToV1Alpha(t *testing.T) {
	payload := buildListResponse("zeta.Service", "alpha.Service")

	rc := &reflectionClient{
		invoke: func(_ context.Context, path string, _ []byte) ([][]byte, error) {
			if path == reflectionV1Path {
				return [][]byte{buildReflectionErrorResponse(int32(fetchgrpc.Unimplemented), "v1 unavailable")}, nil
			}
			if path == reflectionV1AlphaPath {
				return [][]byte{payload}, nil
			}
			t.Fatalf("unexpected reflection path: %s", path)
			return nil, nil
		},
	}

	names, err := rc.ListServices(context.Background())
	if err != nil {
		t.Fatalf("ListServices() error = %v", err)
	}
	if got, want := strings.Join(names, ","), "alpha.Service,zeta.Service"; got != want {
		t.Fatalf("ListServices() = %q, want %q", got, want)
	}
}

func TestReflectionClientFallsBackForProtocolErrorResponse(t *testing.T) {
	var paths []string
	rc := &reflectionClient{
		invoke: func(_ context.Context, path string, _ []byte) ([][]byte, error) {
			paths = append(paths, path)
			if path == reflectionV1Path {
				return [][]byte{buildReflectionErrorResponse(int32(fetchgrpc.Unimplemented), "v1 is unavailable")}, nil
			}
			return [][]byte{buildListResponse("legacy.Service")}, nil
		},
	}

	names, err := rc.ListServices(context.Background())
	if err != nil {
		t.Fatalf("ListServices() error = %v", err)
	}
	if got := strings.Join(names, ","); got != "legacy.Service" {
		t.Fatalf("ListServices() = %q, want legacy.Service", got)
	}
	if got, want := strings.Join(paths, ","), reflectionV1Path+","+reflectionV1AlphaPath; got != want {
		t.Fatalf("reflection paths = %q, want %q", got, want)
	}
}

func TestReflectionClientDoesNotFallbackForNonUnimplementedProtocolError(t *testing.T) {
	calledAlpha := false
	rc := &reflectionClient{
		invoke: func(_ context.Context, path string, _ []byte) ([][]byte, error) {
			if path == reflectionV1AlphaPath {
				calledAlpha = true
			}
			return [][]byte{buildReflectionErrorResponse(7, "permission denied")}, nil
		},
	}

	_, err := rc.ListServices(context.Background())
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("ListServices() error = %v, want permission error", err)
	}
	if calledAlpha {
		t.Fatal("v1alpha was attempted after a non-UNIMPLEMENTED reflection error")
	}
}

func TestReflectionListAcceptsAnEmptyServiceList(t *testing.T) {
	var response []byte
	response = protowire.AppendTag(response, 6, protowire.BytesType)
	response = protowire.AppendBytes(response, nil)
	if names, err := parseReflectionListResponse(response); err != nil || len(names) != 0 {
		t.Fatalf("parseReflectionListResponse() = %v, %v; want an empty list", names, err)
	}
}

func TestReflectionClientDoesNotFallbackForMalformedProtocolError(t *testing.T) {
	calledAlpha := false
	rc := &reflectionClient{
		invoke: func(_ context.Context, path string, _ []byte) ([][]byte, error) {
			if path == reflectionV1Path {
				return [][]byte{buildMalformedReflectionErrorResponse()}, nil
			}
			calledAlpha = true
			return [][]byte{buildListResponse("unexpected.Service")}, nil
		},
	}

	_, err := rc.ListServices(context.Background())
	if err == nil || !strings.Contains(err.Error(), "missing an error code") {
		t.Fatalf("ListServices() error = %v, want malformed response error", err)
	}
	if calledAlpha {
		t.Fatal("v1alpha was attempted after a malformed reflection response")
	}
}

func TestReflectionSymbolRequestNormalizesLeadingDot(t *testing.T) {
	request := buildReflectionSymbolRequest(".test.Service/Method")
	num, typ, n := protowire.ConsumeTag(request)
	if n < 0 || num != 4 || typ != protowire.BytesType {
		t.Fatalf("unexpected symbol request tag: num=%d type=%v n=%d", num, typ, n)
	}
	symbol, m := protowire.ConsumeString(request[n:])
	if m < 0 {
		t.Fatalf("ConsumeString() error = %v", protowire.ParseError(m))
	}
	if symbol != "test.Service.Method" {
		t.Fatalf("symbol = %q, want test.Service.Method", symbol)
	}
}

func buildReflectionErrorResponse(code int32, message string) []byte {
	var response []byte
	response = protowire.AppendTag(response, 1, protowire.VarintType)
	response = protowire.AppendVarint(response, uint64(uint32(code)))
	response = protowire.AppendTag(response, 2, protowire.BytesType)
	response = protowire.AppendString(response, message)
	var outer []byte
	outer = protowire.AppendTag(outer, 7, protowire.BytesType)
	return protowire.AppendBytes(outer, response)
}

func buildMalformedReflectionErrorResponse() []byte {
	var outer []byte
	outer = protowire.AppendTag(outer, 7, protowire.BytesType)
	return protowire.AppendBytes(outer, []byte{0x12, 0x01, 'x'})
}

func TestReflectionErrorValidatesTrailingResponseFields(t *testing.T) {
	response := buildReflectionErrorResponse(int32(fetchgrpc.Unimplemented), "not implemented")
	response = append(response, 0x80) // truncated trailing field
	if _, err := parseReflectionListResponse(response); err == nil {
		t.Fatal("parseReflectionListResponse() accepted malformed trailing data")
	} else if isReflectionUnimplemented(err) {
		t.Fatalf("malformed response was classified as UNIMPLEMENTED: %v", err)
	}
}

func buildListResponse(names ...string) []byte {
	var list []byte
	for _, name := range names {
		var service []byte
		service = protowire.AppendTag(service, 1, protowire.BytesType)
		service = protowire.AppendString(service, name)
		list = protowire.AppendTag(list, 1, protowire.BytesType)
		list = protowire.AppendBytes(list, service)
	}

	var resp []byte
	resp = protowire.AppendTag(resp, 6, protowire.BytesType)
	resp = protowire.AppendBytes(resp, list)
	return resp
}

func TestDescriptorSetBuilderDedupesFiles(t *testing.T) {
	fd := createDescribeTestDescriptorSet().File[0]
	raw, err := gproto.Marshal(fd)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}

	builder := newDescriptorSetBuilder()
	if err := builder.Add([][]byte{raw, raw}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if len(builder.files) != 1 {
		t.Fatalf("expected 1 file after dedupe, got %d", len(builder.files))
	}
	if _, err := builder.Build(); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	inconsistent := gproto.Clone(fd).(*descriptorpb.FileDescriptorProto)
	inconsistent.Package = ptr("different")
	if err := builder.Add([][]byte{mustMarshalDescriptor(t, inconsistent)}); err == nil || !strings.Contains(err.Error(), "inconsistent definitions") {
		t.Fatalf("Add() error = %v, want inconsistent descriptor error", err)
	}
}

func mustMarshalDescriptor(t *testing.T, fd *descriptorpb.FileDescriptorProto) []byte {
	t.Helper()
	raw, err := gproto.Marshal(fd)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	return raw
}

func TestRenderDescribeMessage(t *testing.T) {
	schema := createDescribeTestSchema(t)
	target, err := lookupDescribeSymbol(schema, "testpkg.TestMessage")
	if err != nil {
		t.Fatalf("lookupDescribeSymbol() error = %v", err)
	}

	p := core.TestPrinter(false)
	renderDescribe(p, target)
	got := string(p.Bytes())
	for _, want := range []string{
		"message testpkg.TestMessage",
		"1  id  optional  int64",
		"2  name  optional  string",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func createDescribeTestSchema(t *testing.T) *iproto.Schema {
	t.Helper()

	schema, err := iproto.LoadFromDescriptorSet(createDescribeTestDescriptorSet())
	if err != nil {
		t.Fatalf("LoadFromDescriptorSet() error = %v", err)
	}
	return schema
}

func createDescribeTestDescriptorSet() *descriptorpb.FileDescriptorSet {
	strType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	int64Type := descriptorpb.FieldDescriptorProto_TYPE_INT64
	return &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    ptr("describe.proto"),
				Package: ptr("testpkg"),
				Syntax:  ptr("proto3"),
				MessageType: []*descriptorpb.DescriptorProto{
					{
						Name: ptr("TestMessage"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:   ptr("id"),
								Number: ptr(int32(1)),
								Type:   &int64Type,
							},
							{
								Name:   ptr("name"),
								Number: ptr(int32(2)),
								Type:   &strType,
							},
						},
					},
				},
			},
		},
	}
}

func TestReflectionClientDigestAuth(t *testing.T) {
	var challengeResponded bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(auth, "Digest ") {
			t.Errorf("expected Digest auth, got: %s", auth)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		challengeResponded = true

		payload := buildListResponse("test.Service")
		frame := make([]byte, 5+len(payload))
		binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
		copy(frame[5:], payload)
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.WriteHeader(http.StatusOK)
		w.Write(frame)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	req := &Request{
		URL:    u,
		Digest: &core.KeyVal[string]{Key: "user", Val: "pass"},
		HTTP:   core.HTTP1,
	}
	c := client.NewClient(client.ClientConfig{HTTP: core.HTTP1})
	rc := newReflectionClient(req, c)

	names, err := rc.ListServices(context.Background())
	if err != nil {
		t.Fatalf("ListServices() error = %v", err)
	}
	if !challengeResponded {
		t.Fatal("server did not receive digest challenge response")
	}
	if got, want := strings.Join(names, ","), "test.Service"; got != want {
		t.Fatalf("ListServices() = %q, want %q", got, want)
	}
}

func ptr[T any](v T) *T {
	return &v
}
