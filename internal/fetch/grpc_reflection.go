package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	iproto "github.com/ryanfowler/fetch/internal/proto"

	"google.golang.org/protobuf/encoding/protowire"
	gproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	reflectionV1Path      = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
	reflectionV1AlphaPath = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
)

type reflectionUnavailableError struct {
	err error
}

func (e *reflectionUnavailableError) Error() string {
	if e.err == nil {
		return "gRPC reflection is unavailable; provide --proto-file or --proto-desc"
	}
	return fmt.Sprintf("gRPC reflection is unavailable: %s. Provide --proto-file or --proto-desc", e.err)
}

func (e *reflectionUnavailableError) Unwrap() error {
	return e.err
}

type descriptorSetBuilder struct {
	files map[string]*descriptorpb.FileDescriptorProto
}

func newDescriptorSetBuilder() *descriptorSetBuilder {
	return &descriptorSetBuilder{files: make(map[string]*descriptorpb.FileDescriptorProto)}
}

func (b *descriptorSetBuilder) Add(encoded [][]byte) error {
	for _, raw := range encoded {
		fd := &descriptorpb.FileDescriptorProto{}
		if err := gproto.Unmarshal(raw, fd); err != nil {
			return fmt.Errorf("failed to decode reflected descriptor: %w", err)
		}
		name := fd.GetName()
		if name == "" {
			return errors.New("reflected descriptor is missing a file name")
		}
		if _, exists := b.files[name]; exists {
			continue
		}
		b.files[name] = fd
	}
	return nil
}

func (b *descriptorSetBuilder) Build() (*iproto.Schema, error) {
	fds := &descriptorpb.FileDescriptorSet{
		File: make([]*descriptorpb.FileDescriptorProto, 0, len(b.files)),
	}
	names := make([]string, 0, len(b.files))
	for name := range b.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fds.File = append(fds.File, b.files[name])
	}
	return iproto.LoadFromDescriptorSet(fds)
}

type reflectionProtocol struct {
	name string
	path string
}

var reflectionProtocols = []reflectionProtocol{
	{name: "v1", path: reflectionV1Path},
	{name: "v1alpha", path: reflectionV1AlphaPath},
}

type reflectionInvoker func(ctx context.Context, path string, payload []byte) ([][]byte, error)

type reflectionClient struct {
	request *Request
	client  *client.Client
	invoke  reflectionInvoker
}

func newReflectionClient(r *Request, c *client.Client) *reflectionClient {
	rc := &reflectionClient{
		request: r,
		client:  c,
	}
	rc.invoke = rc.invokeHTTP
	return rc
}

func (rc *reflectionClient) ListServices(ctx context.Context) ([]string, error) {
	var lastErr error
	for i, protocol := range reflectionProtocols {
		frames, err := rc.invoke(ctx, protocol.path, buildReflectionListRequest())
		if err != nil {
			if i == 0 && isReflectionUnimplemented(err) {
				lastErr = err
				continue
			}
			return nil, &reflectionUnavailableError{err: err}
		}
		if len(frames) == 0 {
			return nil, &reflectionUnavailableError{err: errors.New("empty reflection response")}
		}
		names, err := parseReflectionListResponse(frames[0])
		if err != nil {
			return nil, &reflectionUnavailableError{err: err}
		}
		sort.Strings(names)
		return names, nil
	}
	return nil, &reflectionUnavailableError{err: lastErr}
}

func (rc *reflectionClient) SchemaForSymbol(ctx context.Context, symbol string) (*iproto.Schema, error) {
	var lastErr error
	for i, protocol := range reflectionProtocols {
		frames, err := rc.invoke(ctx, protocol.path, buildReflectionSymbolRequest(symbol))
		if err != nil {
			if i == 0 && isReflectionUnimplemented(err) {
				lastErr = err
				continue
			}
			return nil, &reflectionUnavailableError{err: err}
		}
		builder := newDescriptorSetBuilder()
		for _, frame := range frames {
			descs, err := parseReflectionFileDescriptorResponse(frame)
			if err != nil {
				return nil, &reflectionUnavailableError{err: err}
			}
			if err := builder.Add(descs); err != nil {
				return nil, &reflectionUnavailableError{err: err}
			}
		}
		schema, err := builder.Build()
		if err != nil {
			return nil, &reflectionUnavailableError{err: err}
		}
		return schema, nil
	}
	return nil, &reflectionUnavailableError{err: lastErr}
}

func buildReflectionListRequest() []byte {
	var data []byte
	data = protowire.AppendTag(data, 7, protowire.BytesType)
	data = protowire.AppendString(data, "*")
	return data
}

func buildReflectionSymbolRequest(symbol string) []byte {
	var data []byte
	data = protowire.AppendTag(data, 4, protowire.BytesType)
	data = protowire.AppendString(data, symbol)
	return data
}

func parseReflectionListResponse(raw []byte) ([]string, error) {
	var names []string
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 6 && typ == protowire.BytesType:
			listData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			var err error
			names, err = parseReflectionServiceList(listData)
			if err != nil {
				return nil, err
			}
		case num == 7 && typ == protowire.BytesType:
			errData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			return nil, parseReflectionError(errData)
		default:
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
		}
	}
	if names == nil {
		return nil, errors.New("missing list services response")
	}
	return names, nil
}

func parseReflectionServiceList(raw []byte) ([]string, error) {
	var names []string
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		if num != 1 || typ != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			continue
		}
		serviceData, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		raw = raw[m:]
		name, err := parseReflectionServiceName(serviceData)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func parseReflectionServiceName(raw []byte) (string, error) {
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		raw = raw[n:]
		if num == 1 && typ == protowire.BytesType {
			name, m := protowire.ConsumeString(raw)
			if m < 0 {
				return "", protowire.ParseError(m)
			}
			return name, nil
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return "", protowire.ParseError(m)
		}
		raw = raw[m:]
	}
	return "", errors.New("reflection service response missing service name")
}

func parseReflectionFileDescriptorResponse(raw []byte) ([][]byte, error) {
	var files [][]byte
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 4 && typ == protowire.BytesType:
			fdData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			var err error
			files, err = parseReflectionDescriptorList(fdData)
			if err != nil {
				return nil, err
			}
		case num == 7 && typ == protowire.BytesType:
			errData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			return nil, parseReflectionError(errData)
		default:
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
		}
	}
	if files == nil {
		return nil, errors.New("missing file descriptor response")
	}
	return files, nil
}

func parseReflectionDescriptorList(raw []byte) ([][]byte, error) {
	var files [][]byte
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		if num != 1 || typ != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			continue
		}
		fd, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		files = append(files, fd)
		raw = raw[m:]
	}
	return files, nil
}

func parseReflectionError(raw []byte) error {
	var msg string
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return protowire.ParseError(n)
		}
		raw = raw[n:]
		if num == 2 && typ == protowire.BytesType {
			val, m := protowire.ConsumeString(raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			msg = val
			raw = raw[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return protowire.ParseError(m)
		}
		raw = raw[m:]
	}
	if msg == "" {
		msg = "reflection request failed"
	}
	return errors.New(msg)
}

func (rc *reflectionClient) invokeHTTP(ctx context.Context, path string, payload []byte) ([][]byte, error) {
	if rc.client == nil {
		return nil, errors.New("reflection client is not initialized")
	}
	u, err := reflectionURL(rc.request.URL, path)
	if err != nil {
		return nil, err
	}
	headers := grpcHeaders(rc.request.Headers)
	req, err := rc.client.NewRequest(ctx, client.RequestConfig{
		AWSSigV4:    rc.request.AWSSigv4,
		Basic:       rc.request.Basic,
		Bearer:      rc.request.Bearer,
		ContentType: fetchgrpc.ContentType,
		Data:        bytes.NewReader(fetchgrpc.Frame(payload, false)),
		Headers:     headers,
		HTTP:        rc.request.HTTP,
		Method:      "POST",
		NoEncode:    true,
		URL:         u,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}
	frames, err := readGRPCFrames(resp.Body)
	if err != nil {
		return nil, err
	}
	if status := grpcStatusFromResponse(resp); status != nil {
		return nil, status
	}
	return frames, nil
}

func DiscoverGRPC(ctx context.Context, r *Request) int {
	code, err := discoverGRPC(ctx, r)
	if err == nil {
		return code
	}

	p := r.PrinterHandle.Stderr()
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
	return 1
}

func discoverGRPC(ctx context.Context, r *Request) (int, error) {
	schema, offline, c, err := loadDiscoverySchema(ctx, r)
	if err != nil {
		return 0, err
	}
	if c != nil {
		defer c.Close()
	}

	p := r.PrinterHandle.Stdout()
	if r.GRPCList {
		var names []string
		if offline {
			names = schema.ListServices()
			sort.Strings(names)
		} else {
			names, err = newReflectionClient(r, c).ListServices(ctx)
			if err != nil {
				return 0, err
			}
		}
		for _, name := range names {
			p.WriteString(name)
			p.WriteString("\n")
		}
		return 0, p.Flush()
	}

	desc, err := lookupDescribeSymbol(schema, r.GRPCDescribe)
	if err != nil {
		return 0, err
	}
	renderDescribe(p, desc)
	return 0, p.Flush()
}

func loadDiscoverySchema(ctx context.Context, r *Request) (*iproto.Schema, bool, *client.Client, error) {
	schema, err := loadProtoSchema(r)
	if err != nil {
		return nil, false, nil, err
	}
	if schema != nil {
		return schema, true, nil, nil
	}
	if r.URL == nil {
		return nil, false, nil, &reflectionUnavailableError{}
	}

	applyGRPCDefaults(r)
	c := newClient(r)
	if r.GRPCDescribe == "" {
		return nil, false, c, nil
	}
	schema, err = newReflectionClient(r, c).SchemaForSymbol(ctx, normalizeReflectionSymbol(r.GRPCDescribe))
	if err != nil {
		c.Close()
		return nil, false, nil, err
	}
	return schema, false, c, nil
}

func resolveCallSchema(ctx context.Context, r *Request, c *client.Client) (*iproto.Schema, error) {
	schema, err := loadProtoSchema(r)
	if err != nil || schema != nil {
		return schema, err
	}
	if r.URL == nil {
		return nil, nil
	}
	serviceName, _, err := parseGRPCPath(r.URL.Path)
	if err != nil {
		return nil, err
	}
	schema, err = newReflectionClient(r, c).SchemaForSymbol(ctx, serviceName)
	if err != nil {
		if requiresGRPCSchema(r) {
			return nil, err
		}
		return nil, nil
	}
	return schema, nil
}

func requiresGRPCSchema(r *Request) bool {
	if r.ContentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.ContentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.ToLower(r.ContentType))
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func applyGRPCDefaults(r *Request) {
	if r.HTTP == core.HTTPDefault {
		r.HTTP = core.HTTP2
	}
	if r.Method == "" {
		r.Method = "POST"
	}
}

func grpcHeaders(headers []core.KeyVal[string]) []core.KeyVal[string] {
	out := slices.Clone(headers)
	out = append(out, fetchgrpc.Headers()...)
	out = append(out, fetchgrpc.AcceptHeader())
	return out
}

func newClient(r *Request) *client.Client {
	return client.NewClient(client.ClientConfig{
		CACerts:        r.CACerts,
		ClientCert:     r.ClientCert,
		ConnectTimeout: r.ConnectTimeout,
		DNSServer:      r.DNSServer,
		H2C:            shouldUseH2C(r),
		HTTP:           r.HTTP,
		Insecure:       r.Insecure,
		Proxy:          r.Proxy,
		Redirects:      r.Redirects,
		TLS:            r.TLS,
		UnixSocket:     r.UnixSocket,
	})
}

func shouldUseH2C(r *Request) bool {
	if r.URL == nil || !r.HasGRPCMode() {
		return false
	}
	if r.HTTP != core.HTTP2 {
		return false
	}
	return effectiveScheme(r.URL) == "http"
}

func effectiveScheme(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Scheme != "" {
		return strings.ToLower(u.Scheme)
	}
	if client.IsLoopback(u.Hostname()) {
		return "http"
	}
	return "https"
}

func reflectionURL(base *url.URL, path string) (*url.URL, error) {
	if base == nil {
		return nil, errors.New("gRPC reflection requires a target URL")
	}
	u := *base
	u.Path = path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return &u, nil
}

func readGRPCFrames(r io.Reader) ([][]byte, error) {
	var frames [][]byte
	for {
		frame, compressed, err := fetchgrpc.ReadFrame(r)
		if err == io.EOF {
			return frames, nil
		}
		if err != nil {
			return nil, err
		}
		if compressed {
			return nil, errors.New("compressed gRPC messages are not supported")
		}
		frames = append(frames, frame)
	}
}

func grpcStatusFromResponse(resp *http.Response) *fetchgrpc.Status {
	grpcStatus := resp.Trailer.Get("Grpc-Status")
	grpcMessage := resp.Trailer.Get("Grpc-Message")
	if grpcStatus == "" {
		grpcStatus = resp.Header.Get("Grpc-Status")
		grpcMessage = resp.Header.Get("Grpc-Message")
	}
	if grpcStatus == "" || grpcStatus == "0" {
		return nil
	}
	return fetchgrpc.ParseStatus(grpcStatus, grpcMessage)
}

func isReflectionUnimplemented(err error) bool {
	var status *fetchgrpc.Status
	if errors.As(err, &status) {
		return status.Code == fetchgrpc.Unimplemented
	}
	return false
}

type describeKind int

const (
	describeService describeKind = iota
	describeMethod
	describeMessage
)

type describeTarget struct {
	kind    describeKind
	service protoreflect.ServiceDescriptor
	method  protoreflect.MethodDescriptor
	message protoreflect.MessageDescriptor
}

func lookupDescribeSymbol(schema *iproto.Schema, symbol string) (*describeTarget, error) {
	if strings.Contains(symbol, "/") {
		method, err := schema.FindMethod(symbol)
		if err != nil {
			return nil, fmt.Errorf("symbol not found: %s", symbol)
		}
		return &describeTarget{kind: describeMethod, method: method}, nil
	}

	if svc, err := schema.FindService(symbol); err == nil {
		return &describeTarget{kind: describeService, service: svc}, nil
	}
	if method, err := schema.FindMethod(symbol); err == nil {
		return &describeTarget{kind: describeMethod, method: method}, nil
	}
	if msg, err := schema.FindMessage(symbol); err == nil {
		return &describeTarget{kind: describeMessage, message: msg}, nil
	}
	return nil, fmt.Errorf("symbol not found: %s", symbol)
}

func renderDescribe(p *core.Printer, target *describeTarget) {
	switch target.kind {
	case describeService:
		renderServiceDescription(p, target.service)
	case describeMethod:
		renderMethodDescription(p, target.method)
	case describeMessage:
		renderMessageDescription(p, target.message)
	}
}

func renderServiceDescription(p *core.Printer, svc protoreflect.ServiceDescriptor) {
	p.WriteString("service ")
	p.WriteString(string(svc.FullName()))
	p.WriteString("\n")
	methods := svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		method := methods.Get(i)
		p.WriteString("\n")
		p.WriteString(string(method.Name()))
		p.WriteString("\n")
		p.WriteString("  rpc: ")
		p.WriteString(rpcType(method))
		p.WriteString("\n")
		p.WriteString("  request: ")
		p.WriteString(string(method.Input().FullName()))
		p.WriteString("\n")
		p.WriteString("  response: ")
		p.WriteString(string(method.Output().FullName()))
		p.WriteString("\n")
	}
}

func renderMethodDescription(p *core.Printer, method protoreflect.MethodDescriptor) {
	p.WriteString("method ")
	p.WriteString(string(method.Parent().FullName()))
	p.WriteString("/")
	p.WriteString(string(method.Name()))
	p.WriteString("\n")
	p.WriteString("rpc: ")
	p.WriteString(rpcType(method))
	p.WriteString("\n")
	p.WriteString("request: ")
	p.WriteString(string(method.Input().FullName()))
	p.WriteString("\n")
	p.WriteString("response: ")
	p.WriteString(string(method.Output().FullName()))
	p.WriteString("\n")
}

func renderMessageDescription(p *core.Printer, msg protoreflect.MessageDescriptor) {
	p.WriteString("message ")
	p.WriteString(string(msg.FullName()))
	p.WriteString("\n")
	fields := msg.Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		p.WriteString("\n")
		p.WriteString(fmt.Sprintf("%d  %s  %s  %s", field.Number(), field.Name(), fieldLabel(field), fieldType(field)))
		p.WriteString("\n")
	}
}

func rpcType(method protoreflect.MethodDescriptor) string {
	switch {
	case method.IsStreamingClient() && method.IsStreamingServer():
		return "bidi-stream"
	case method.IsStreamingClient():
		return "client-stream"
	case method.IsStreamingServer():
		return "server-stream"
	default:
		return "unary"
	}
}

func fieldLabel(field protoreflect.FieldDescriptor) string {
	if field.IsList() {
		return "repeated"
	}
	switch field.Cardinality() {
	case protoreflect.Required:
		return "required"
	case protoreflect.Optional:
		return "optional"
	default:
		return "singular"
	}
}

func fieldType(field protoreflect.FieldDescriptor) string {
	if field.IsMap() {
		key := field.MapKey()
		value := field.MapValue()
		return fmt.Sprintf("map<%s, %s>", scalarFieldType(key), scalarFieldType(value))
	}
	return scalarFieldType(field)
}

func scalarFieldType(field protoreflect.FieldDescriptor) string {
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return string(field.Message().FullName())
	case protoreflect.EnumKind:
		return string(field.Enum().FullName())
	default:
		return strings.TrimSuffix(strings.ToLower(field.Kind().String()), "kind")
	}
}

func normalizeReflectionSymbol(symbol string) string {
	symbol = strings.TrimPrefix(symbol, "/")
	if idx := strings.LastIndex(symbol, "/"); idx >= 0 {
		return symbol[:idx] + "." + symbol[idx+1:]
	}
	return symbol
}
