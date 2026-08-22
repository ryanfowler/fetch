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
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	fetchgrpc "github.com/ryanfowler/fetch/internal/grpc"
	iproto "github.com/ryanfowler/fetch/internal/proto"
	"github.com/ryanfowler/fetch/internal/session"

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

// reflectionResponseError is the protocol-level ErrorResponse returned by
// ServerReflectionInfo. It is distinct from a transport or gRPC status error:
// only its UNIMPLEMENTED code permits trying the v1alpha service.
type reflectionResponseError struct {
	code    int32
	message string
}

func (e *reflectionResponseError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("reflection error (%d)", e.code)
	}
	return fmt.Sprintf("reflection error (%d): %s", e.code, e.message)
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
		if existing, exists := b.files[name]; exists {
			if !gproto.Equal(existing, fd) {
				return fmt.Errorf("reflected descriptor %q was returned with inconsistent definitions", name)
			}
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

type reflectionLimitState struct {
	messages  int
	bytes     int64
	wireBytes int64
	accounted bool
}

type reflectionLimitContextKey struct{}

func withReflectionLimitState(ctx context.Context, state *reflectionLimitState) context.Context {
	return context.WithValue(ctx, reflectionLimitContextKey{}, state)
}

func reflectionLimitStateFromContext(ctx context.Context) *reflectionLimitState {
	state, _ := ctx.Value(reflectionLimitContextKey{}).(*reflectionLimitState)
	return state
}

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

// reflectionContext gives one reflection operation the same wall-clock
// request and connection budgets used by ordinary requests. In particular,
// v1 and v1alpha fallback share these absolute deadlines.
func reflectionContext(ctx context.Context, r *Request) (context.Context, context.CancelFunc, error) {
	if r == nil {
		return ctx, func() {}, nil
	}
	requestBudget, err := core.NewBudget(r.Timeout)
	if err != nil {
		return nil, nil, err
	}
	connectBudget, err := core.NewBudget(r.ConnectTimeout)
	if err != nil {
		return nil, nil, err
	}
	operationCtx, cancel := requestBudget.WithContext(ctx, "gRPC reflection")
	if connectBudget.Limited() {
		operationCtx = client.WithConnectBudget(operationCtx, connectBudget)
	}
	return operationCtx, cancel, nil
}

func (rc *reflectionClient) ListServices(ctx context.Context) ([]string, error) {
	var lastErr error
	state := new(reflectionLimitState)
	ctx = withReflectionLimitState(ctx, state)
	for i, protocol := range reflectionProtocols {
		state.accounted = false
		frames, err := rc.invoke(ctx, protocol.path, buildReflectionListRequest())
		if !state.accounted {
			if err := accountReflectionFrames(state, frames); err != nil {
				return nil, &reflectionUnavailableError{err: err}
			}
		}
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
		allNames := make(map[string]struct{})
		fallback := false
		for _, frame := range frames {
			names, parseErr := parseReflectionListResponse(frame)
			if parseErr != nil {
				if i == 0 && isReflectionUnimplemented(parseErr) {
					lastErr = parseErr
					fallback = true
					break
				}
				return nil, &reflectionUnavailableError{err: parseErr}
			}
			for _, name := range names {
				if name == "" {
					return nil, &reflectionUnavailableError{err: errors.New("reflection service response contains an empty service name")}
				}
				allNames[name] = struct{}{}
			}
		}
		if fallback {
			continue
		}
		names := make([]string, 0, len(allNames))
		for name := range allNames {
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}
	return nil, &reflectionUnavailableError{err: lastErr}
}

func (rc *reflectionClient) SchemaForSymbol(ctx context.Context, symbol string) (*iproto.Schema, error) {
	var lastErr error
	state := new(reflectionLimitState)
	ctx = withReflectionLimitState(ctx, state)
	for i, protocol := range reflectionProtocols {
		state.accounted = false
		frames, err := rc.invoke(ctx, protocol.path, buildReflectionSymbolRequest(symbol))
		if !state.accounted {
			if err := accountReflectionFrames(state, frames); err != nil {
				return nil, &reflectionUnavailableError{err: err}
			}
		}
		if err != nil {
			if i == 0 && isReflectionUnimplemented(err) {
				lastErr = err
				continue
			}
			return nil, &reflectionUnavailableError{err: err}
		}
		builder := newDescriptorSetBuilder()
		fallback := false
		for _, frame := range frames {
			descs, parseErr := parseReflectionFileDescriptorResponse(frame)
			if parseErr != nil {
				if i == 0 && isReflectionUnimplemented(parseErr) {
					lastErr = parseErr
					fallback = true
					break
				}
				return nil, &reflectionUnavailableError{err: parseErr}
			}
			if err := builder.Add(descs); err != nil {
				return nil, &reflectionUnavailableError{err: err}
			}
		}
		if fallback {
			continue
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
	data = protowire.AppendString(data, normalizeReflectionSymbol(symbol))
	return data
}

func parseReflectionListResponse(raw []byte) ([]string, error) {
	var (
		names          []string
		hasServiceList bool
		responseErr    error
	)
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 6 && typ == protowire.BytesType:
			if responseErr != nil {
				return nil, errors.New("reflection response contains conflicting result fields")
			}
			listData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			list, listErr := parseReflectionServiceList(listData)
			if listErr != nil {
				return nil, listErr
			}
			hasServiceList = true
			names = append(names, list...)
		case num == 7 && typ == protowire.BytesType:
			if hasServiceList || responseErr != nil {
				return nil, errors.New("reflection response contains conflicting result fields")
			}
			errData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			responseErr = parseReflectionError(errData)
		default:
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
		}
	}
	if responseErr != nil {
		return nil, responseErr
	}
	if !hasServiceList {
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
	var (
		name    string
		hasName bool
	)
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		raw = raw[n:]
		if num == 1 && typ == protowire.BytesType {
			if hasName {
				return "", errors.New("reflection service response contains duplicate service names")
			}
			value, m := protowire.ConsumeString(raw)
			if m < 0 {
				return "", protowire.ParseError(m)
			}
			if !utf8.ValidString(value) {
				return "", errors.New("reflection service response contains invalid UTF-8")
			}
			name, hasName = value, true
			raw = raw[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return "", protowire.ParseError(m)
		}
		raw = raw[m:]
	}
	if !hasName {
		return "", errors.New("reflection service response missing service name")
	}
	return name, nil
}

func parseReflectionFileDescriptorResponse(raw []byte) ([][]byte, error) {
	var (
		files       [][]byte
		responseErr error
	)
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 4 && typ == protowire.BytesType:
			if responseErr != nil {
				return nil, errors.New("reflection response contains conflicting result fields")
			}
			fdData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			list, listErr := parseReflectionDescriptorList(fdData)
			if listErr != nil {
				return nil, listErr
			}
			files = append(files, list...)
		case num == 7 && typ == protowire.BytesType:
			if len(files) > 0 || responseErr != nil {
				return nil, errors.New("reflection response contains conflicting result fields")
			}
			errData, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			responseErr = parseReflectionError(errData)
		default:
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
		}
	}
	if responseErr != nil {
		return nil, responseErr
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
	var (
		code    int32
		hasCode bool
		msg     string
	)
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			value, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			code = int32(value)
			hasCode = true
			raw = raw[m:]
		case num == 2 && typ == protowire.BytesType:
			value, m := protowire.ConsumeString(raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			if !utf8.ValidString(value) {
				return errors.New("reflection error response contains invalid UTF-8")
			}
			msg = value
			raw = raw[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			raw = raw[m:]
		}
	}
	if !hasCode {
		return errors.New("reflection error response is missing an error code")
	}
	return &reflectionResponseError{code: code, message: msg}
}

func (rc *reflectionClient) invokeHTTP(ctx context.Context, path string, payload []byte) ([][]byte, error) {
	if rc.client == nil {
		return nil, errors.New("reflection client is not initialized")
	}
	u, err := reflectionURL(rc.request.URL, path)
	if err != nil {
		return nil, err
	}
	framedPayload, err := fetchgrpc.FrameChecked(payload, false)
	if err != nil {
		return nil, err
	}
	headers := grpcHeaders(rc.request.Headers)
	req, err := rc.client.NewRequest(ctx, client.RequestConfig{
		Basic:       rc.request.Basic,
		Bearer:      rc.request.Bearer,
		ContentType: fetchgrpc.ContentType,
		Data:        bytes.NewReader(framedPayload),
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

	if err := signAWSRequest(rc.request, req); err != nil {
		return nil, err
	}

	// Reflection is a normal signed HTTP request. Re-sign same-origin
	// redirects after net/http has finalized their method, URL, body, and
	// headers, and remove AWS credentials at an origin boundary.
	var observerErr error
	if rc.request.AWSSigv4 != nil {
		origin := req.URL
		req = req.WithContext(client.WithRequestObserver(req.Context(), func(next *http.Request) {
			if client.RedirectCrossedOrigin(next) || !client.SameOrigin(origin, next.URL) {
				clearAWSHeaders(next)
				return
			}
			if next.Response != nil {
				clearAWSGeneratedHeaders(next)
			}
			if observerErr == nil {
				observerErr = signAWSRequest(rc.request, next)
			}
		}))
	}

	resp, err := doOnce(rc.request, rc.client, req, nil)
	if err == nil && observerErr != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		err = observerErr
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}
	state := reflectionLimitStateFromContext(ctx)
	if state != nil {
		state.accounted = true
	}
	frames, err := readGRPCFramesWithLimits(resp.Body, resp.Header.Get("grpc-encoding"), state)
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

	if core.IsBrokenPipe(err) {
		return 0
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
	// Reflection discovery uses the same session jar as ordinary gRPC calls.
	// Attach it before ListServices/Describe so cookies can authorize discovery
	// and cookie updates from the response are persisted.
	var sess *session.Session
	if c != nil && r.Session != "" {
		var loadErr error
		if r.DryRun {
			sess, loadErr = session.LoadReadOnly(r.Session)
		} else {
			sess, loadErr = session.Load(r.Session)
		}
		if loadErr != nil {
			if sess == nil {
				return 0, loadErr
			}
			msg := fmt.Sprintf("session '%s' is corrupted, starting fresh: %s", r.Session, loadErr.Error())
			core.WriteWarningMsgIf(r.PrinterHandle.Stderr(), msg, r.Verbosity == core.VSilent)
		}
		c.SetJar(sess.Jar())
		defer saveSession(r, sess)
	}

	p := r.PrinterHandle.Stdout()
	if r.GRPCList {
		var names []string
		if offline {
			names = schema.ListServices()
			sort.Strings(names)
		} else {
			reflectionCtx, cancel, budgetErr := reflectionContext(ctx, r)
			if budgetErr != nil {
				return 0, budgetErr
			}
			names, err = newReflectionClient(r, c).ListServices(reflectionCtx)
			cancel()
			if err != nil {
				return 0, err
			}
		}
		for _, name := range names {
			p.WriteString(name)
			p.WriteString("\n")
		}
		if err := p.Flush(); err != nil && core.IsBrokenPipe(err) {
			return 0, nil
		} else {
			return 0, err
		}
	}

	desc, err := lookupDescribeSymbol(schema, r.GRPCDescribe)
	if err != nil {
		return 0, err
	}
	renderDescribe(p, desc)
	if err := p.Flush(); err != nil && core.IsBrokenPipe(err) {
		return 0, nil
	} else {
		return 0, err
	}
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
	// Describe performs reflection inside this helper, before discoverGRPC can
	// attach its normal session jar. Attach it here as well so discovery
	// authentication and Set-Cookie handling use the ordinary request policy.
	var sess *session.Session
	if r.Session != "" {
		var loadErr error
		if r.DryRun {
			sess, loadErr = session.LoadReadOnly(r.Session)
		} else {
			sess, loadErr = session.Load(r.Session)
		}
		if loadErr != nil {
			if sess == nil {
				c.Close()
				return nil, false, nil, loadErr
			}
			msg := fmt.Sprintf("session '%s' is corrupted, starting fresh: %s", r.Session, loadErr.Error())
			core.WriteWarningMsgIf(r.PrinterHandle.Stderr(), msg, r.Verbosity == core.VSilent)
		}
		c.SetJar(sess.Jar())
		defer saveSession(r, sess)
	}
	if r.GRPCDescribe == "" {
		return nil, false, c, nil
	}
	reflectionCtx, cancel, budgetErr := reflectionContext(ctx, r)
	if budgetErr != nil {
		c.Close()
		return nil, false, nil, budgetErr
	}
	defer cancel()
	schema, err = newReflectionClient(r, c).SchemaForSymbol(reflectionCtx, normalizeReflectionSymbol(r.GRPCDescribe))
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
	reflectionCtx, cancel, budgetErr := reflectionContext(ctx, r)
	if budgetErr != nil {
		return nil, budgetErr
	}
	defer cancel()
	schema, err = newReflectionClient(r, c).SchemaForSymbol(reflectionCtx, serviceName)
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
	httpVersion := r.HTTP
	// The WebSocket upgrade is an HTTP/1.1 handshake. Keep the transport on
	// HTTP/1.1 even when a request is constructed directly rather than through
	// CLI validation; callers using the CLI still receive the explicit
	// HTTP/2/HTTP/3 mode error before reaching this point.
	if r.WS {
		httpVersion = core.HTTP1
	}
	return client.NewClient(client.ClientConfig{
		CACerts:          r.CACerts,
		ClientCert:       r.ClientCert,
		ConnectTimeout:   r.ConnectTimeout,
		ResolverEndpoint: r.ResolverEndpoint,
		DNSServer:        r.DNSServer,
		H2C:              shouldUseH2C(r),
		HTTP:             httpVersion,
		ECH:              r.ECH,
		Insecure:         r.Insecure,
		Proxy:            r.Proxy,
		Redirects:        r.Redirects,
		TLSMax:           r.TLSMax,
		TLSMin:           r.TLSMin,
		UnixSocket:       r.UnixSocket,
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

func readGRPCFrames(r io.Reader, encoding string) ([][]byte, error) {
	return readGRPCFramesWithLimits(r, encoding, nil)
}

func readGRPCFramesWithLimits(r io.Reader, encoding string, state *reflectionLimitState) ([][]byte, error) {
	if state == nil {
		state = new(reflectionLimitState)
	}
	frames := make([][]byte, 0, min(core.MaxReflectionMessages, 8))
	for {
		length, compressed, err := fetchgrpc.ReadFrameHeader(r)
		if err == io.EOF {
			return frames, nil
		}
		if err != nil {
			return nil, err
		}
		if state.messages >= core.MaxReflectionMessages {
			return nil, fmt.Errorf("gRPC reflection response exceeds %d messages", core.MaxReflectionMessages)
		}
		remainingWire := core.MaxReflectionBytes - state.wireBytes
		if remainingWire < 0 || uint64(length) > uint64(remainingWire) {
			return nil, fmt.Errorf("gRPC reflection response exceeds %d bytes", core.MaxReflectionBytes)
		}
		frame, err := fetchgrpc.ReadFrameBody(r, length, remainingWire)
		if err != nil {
			return nil, err
		}
		state.wireBytes += int64(len(frame))

		remainingDecoded := core.MaxReflectionBytes - state.bytes
		if remainingDecoded < 0 {
			return nil, fmt.Errorf("gRPC reflection response exceeds %d bytes", core.MaxReflectionBytes)
		}
		frame, err = fetchgrpc.DecodeMessageLimited(frame, compressed, encoding, remainingDecoded)
		if err != nil {
			if errors.Is(err, core.ErrLimitExceeded) {
				return nil, fmt.Errorf("gRPC reflection response exceeds %d bytes", core.MaxReflectionBytes)
			}
			return nil, err
		}
		if int64(len(frame)) > remainingDecoded {
			return nil, fmt.Errorf("gRPC reflection response exceeds %d bytes", core.MaxReflectionBytes)
		}
		state.bytes += int64(len(frame))
		state.messages++
		frames = append(frames, frame)
	}
}

func accountReflectionFrames(state *reflectionLimitState, frames [][]byte) error {
	for _, frame := range frames {
		if state.messages >= core.MaxReflectionMessages {
			return fmt.Errorf("gRPC reflection response exceeds %d messages", core.MaxReflectionMessages)
		}
		if int64(len(frame)) > core.MaxReflectionBytes-state.bytes {
			return fmt.Errorf("gRPC reflection response exceeds %d bytes", core.MaxReflectionBytes)
		}
		state.messages++
		state.bytes += int64(len(frame))
	}
	return nil
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
	var responseErr *reflectionResponseError
	return errors.As(err, &responseErr) && responseErr.code == int32(fetchgrpc.Unimplemented)
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
	symbol = strings.TrimLeft(symbol, "./")
	if idx := strings.LastIndex(symbol, "/"); idx >= 0 {
		return symbol[:idx] + "." + symbol[idx+1:]
	}
	return symbol
}
