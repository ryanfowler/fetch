package fetch

import (
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

func TestReflectionClientFallsBackToV1Alpha(t *testing.T) {
	payload := buildListResponse("zeta.Service", "alpha.Service")

	rc := &reflectionClient{
		invoke: func(_ context.Context, path string, _ []byte) ([][]byte, error) {
			if path == reflectionV1Path {
				return nil, &fetchgrpc.Status{Code: fetchgrpc.Unimplemented}
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
