// Package har records bounded HTTP Archive (HAR) 1.2 exchanges.
package har

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fileutil"
)

const (
	Version            = "1.2"
	BodyOmittedComment = "Body omitted by fetch because it exceeds the 16 MiB HAR capture limit"
)

// Timings contains the measurements available from the request transport.
// Values are converted to HAR milliseconds when the entry is written.
type Timings struct {
	DNS           time.Duration
	Connect       time.Duration
	TLS           time.Duration
	Wait          time.Duration
	Receive       time.Duration
	TransferSize  int64
	TransferKnown bool
	RemoteIP      string
	DNSKnown      bool
	ConnectKnown  bool
	TLSKnown      bool
	WaitKnown     bool
	ReceiveKnown  bool
	CompletedAt   time.Time
}

// Recorder reserves a HAR destination and records one final exchange.
// Recorder is safe for the request observer and response tee to use from
// different goroutines, although a fetch invocation normally has one stream.
type Recorder struct {
	mu        sync.Mutex
	path      string
	clobber   bool
	temp      *os.File
	tempPath  string
	committed bool
	closed    bool
	last      *requestCapture
}

// New reserves path before a request starts. It does not create the final
// destination until Finalize commits a complete HAR document.
func New(path string, clobber bool) (*Recorder, error) {
	if path == "" || path == "-" {
		return nil, errors.New("HAR destination must be a non-empty file path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to write HAR through symlink path %q", abs)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("HAR destination is not a regular file: %q", abs)
		}
		if !clobber {
			return nil, fmt.Errorf("HAR file already exists: %q (use --clobber to overwrite)", abs)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to check HAR destination %q: %w", abs, err)
	}
	if _, err := os.Stat(filepath.Dir(abs)); err != nil {
		return nil, fmt.Errorf("unable to check HAR destination directory: %w", err)
	}

	f, err := os.CreateTemp(filepath.Dir(abs), ".fetch-har-*")
	if err != nil {
		return nil, fmt.Errorf("unable to reserve HAR destination: %w", err)
	}
	return &Recorder{path: abs, clobber: clobber, temp: f, tempPath: f.Name()}, nil
}

// ObserveRequest attaches a bounded request-body capture to req. It is meant
// to be used as a client request observer, so it sees initial requests,
// redirect requests, retries, and Digest replays.
func (r *Recorder) ObserveRequest(req *http.Request) {
	if r == nil || req == nil {
		return
	}
	capture := &requestCapture{request: req, started: time.Now()}
	if req.Body != nil && req.Body != http.NoBody {
		capture.body = newBodyCapture(core.MaxHARRequestBodyBytes)
		req.Body = &captureReadCloser{ReadCloser: req.Body, capture: capture.body}
	}
	// Mutate the request value so net/http's response request, including the
	// context clone used by the response decoder, retains this capture.
	*req = *req.WithContext(context.WithValue(req.Context(), requestCaptureKey, capture))

	r.mu.Lock()
	r.last = capture
	r.mu.Unlock()
}

// CaptureResponse creates the bounded tee for resp's decoded response body.
func (r *Recorder) CaptureResponse(resp *http.Response) *ResponseCapture {
	capture := &ResponseCapture{body: newBodyCapture(core.MaxHARResponseBodyBytes)}
	if resp != nil && resp.Request != nil {
		if request, ok := resp.Request.Context().Value(requestCaptureKey).(*requestCapture); ok {
			capture.request = request
		}
	}
	if capture.request == nil {
		r.mu.Lock()
		capture.request = r.last
		r.mu.Unlock()
	}
	return capture
}

// Finalize writes and atomically commits the one-entry HAR document. The
// response body must have been consumed as far as the caller intends before
// this method is called.
func (r *Recorder) Finalize(resp *http.Response, response *ResponseCapture, timings Timings) error {
	if r == nil {
		return nil
	}
	if resp == nil {
		return errors.New("cannot record HAR without an HTTP response")
	}
	if response == nil {
		response = r.CaptureResponse(resp)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.committed {
		return nil
	}
	if r.temp == nil {
		return errors.New("HAR recorder is closed")
	}

	entry := buildEntry(resp, response, timings)
	log := harLog{Version: Version, Creator: creator(), Entries: []Entry{entry}}
	data, err := json.MarshalIndent(harDocument{Log: log}, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to encode HAR: %w", err)
	}
	data = append(data, '\n')
	if _, err := r.temp.Write(data); err != nil {
		return fmt.Errorf("unable to write HAR: %w", err)
	}
	_ = r.temp.Sync()
	if err := r.temp.Close(); err != nil {
		return fmt.Errorf("unable to close HAR: %w", err)
	}
	r.temp = nil

	var commitErr error
	if r.clobber {
		commitErr = fileutil.AtomicReplaceFileNoSymlink(r.tempPath, r.path)
	} else {
		commitErr = fileutil.AtomicWriteNewFile(r.tempPath, r.path)
	}
	if commitErr != nil {
		if errors.Is(commitErr, fileutil.ErrSymlinkTarget) {
			return fmt.Errorf("refusing to write HAR through symlink path %q", r.path)
		}
		return fmt.Errorf("unable to commit HAR: %w", commitErr)
	}
	r.tempPath = ""
	r.committed = true
	_ = fileutil.SyncDir(filepath.Dir(r.path))
	return nil
}

// Close removes an uncommitted reservation. It is safe to call after
// Finalize and should normally be deferred by the caller.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.temp != nil {
		_ = r.temp.Close()
		r.temp = nil
	}
	if r.tempPath != "" {
		if err := os.Remove(r.tempPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		r.tempPath = ""
	}
	return nil
}

// ResponseCapture is an io.Writer suitable for body.Stream.AddTee.
type ResponseCapture struct {
	request *requestCapture
	body    *bodyCapture
}

func (c *ResponseCapture) Write(p []byte) (int, error) {
	if c == nil || c.body == nil {
		return len(p), nil
	}
	return c.body.Write(p)
}

// Size reports the number of decoded response bytes observed by the tee.
func (c *ResponseCapture) Size() int64 {
	if c == nil || c.body == nil {
		return 0
	}
	_, size, _ := c.body.snapshot()
	return size
}

type requestCapture struct {
	request *http.Request
	started time.Time
	body    *bodyCapture
}

type requestCaptureKeyType struct{}

var requestCaptureKey requestCaptureKeyType

type captureReadCloser struct {
	io.ReadCloser
	capture *bodyCapture
}

func (r *captureReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		_, _ = r.capture.Write(p[:n])
	}
	return n, err
}

type bodyCapture struct {
	mu      sync.Mutex
	limit   int64
	data    []byte
	seen    int64
	omitted bool
}

func newBodyCapture(limit int64) *bodyCapture {
	return &bodyCapture{limit: limit}
}

func (c *bodyCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen += int64(len(p))
	if int64(len(c.data)) < c.limit {
		n := minInt64(int64(len(p)), c.limit-int64(len(c.data)))
		c.data = append(c.data, p[:n]...)
		if n != int64(len(p)) {
			c.omitted = true
		}
	} else if len(p) > 0 {
		c.omitted = true
	}
	return len(p), nil
}

func (c *bodyCapture) snapshot() (data []byte, seen int64, omitted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.data...), c.seen, c.omitted
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func buildEntry(resp *http.Response, response *ResponseCapture, timings Timings) Entry {
	request := response.request
	if request == nil {
		request = &requestCapture{started: time.Now()}
	}
	requestBody, requestSize, requestOmitted := []byte(nil), int64(0), false
	if request.body != nil {
		requestBody, requestSize, requestOmitted = request.body.snapshot()
	}
	responseBody, responseSize, responseOmitted := response.body.snapshot()

	started := request.started
	if started.IsZero() {
		started = time.Now()
	}
	end := time.Now()
	if !timings.CompletedAt.IsZero() {
		end = timings.CompletedAt
	}
	elapsed := end.Sub(started)
	if elapsed < 0 {
		elapsed = 0
	}
	requestVersion := resp.Proto
	if request.request != nil && request.request.Proto != "" {
		requestVersion = request.request.Proto
	}
	if requestVersion == "" {
		requestVersion = "HTTP/1.1"
	}

	requestURL := ""
	if request.request != nil && request.request.URL != nil {
		requestURL = request.request.URL.String()
	}
	if requestURL == "" && resp.Request != nil && resp.Request.URL != nil {
		requestURL = resp.Request.URL.String()
	}

	requestObject := Request{
		Method:      requestMethod(request.request),
		URL:         requestURL,
		HTTPVersion: requestVersion,
		Headers:     requestHeaders(request.request),
		Cookies:     requestCookies(request.request),
		QueryString: queryEntries(requestURL),
		HeadersSize: -1,
		BodySize:    requestSize,
	}
	if request.request != nil && request.request.Body != nil && request.request.Body != http.NoBody {
		requestObject.PostData = &PostData{MIMEType: request.request.Header.Get("Content-Type")}
		if requestOmitted {
			requestObject.PostData.Comment = BodyOmittedComment
		} else {
			requestObject.PostData.setBody(requestBody, isBinaryMIME(request.request.Header.Get("Content-Type")))
		}
	}

	responseObject := Response{
		Status:      resp.StatusCode,
		StatusText:  statusText(resp),
		HTTPVersion: resp.Proto,
		Headers:     responseHeadersWithTrailers(resp),
		Cookies:     responseCookies(resp),
		HeadersSize: -1,
		BodySize:    timings.TransferSize,
		RedirectURL: resp.Header.Get("Location"),
		Content:     Content{Size: responseSize, MIMEType: resp.Header.Get("Content-Type")},
	}
	if responseOmitted {
		responseObject.Content.Comment = BodyOmittedComment
	} else {
		responseObject.Content.setBody(responseBody, isBinaryMIME(resp.Header.Get("Content-Type")))
	}
	if responseObject.HTTPVersion == "" {
		responseObject.HTTPVersion = requestVersion
	}
	if !timings.TransferKnown && timings.TransferSize == 0 {
		responseObject.BodySize = -1
	}

	timing := TimingsHAR{
		Blocked: -1,
		DNS:     durationMS(timings.DNS, timings.DNSKnown),
		Connect: durationMS(timings.Connect, timings.ConnectKnown),
		SSL:     durationMS(timings.TLS, timings.TLSKnown),
		Send:    -1,
		Wait:    durationMS(timings.Wait, timings.WaitKnown),
		Receive: durationMS(timings.Receive, timings.ReceiveKnown),
	}
	return Entry{
		StartedDateTime: started.UTC().Format(time.RFC3339Nano),
		Time:            float64(elapsed) / float64(time.Millisecond),
		Request:         requestObject, Response: responseObject,
		Cache: map[string]any{}, Timings: timing,
		ServerIPAddress: timings.RemoteIP,
	}
}

func requestMethod(request *http.Request) string {
	if request == nil || request.Method == "" {
		return http.MethodGet
	}
	return request.Method
}

func statusText(resp *http.Response) string {
	status := strings.TrimSpace(resp.Status)
	prefix := strconv.Itoa(resp.StatusCode)
	if strings.HasPrefix(status, prefix) {
		status = strings.TrimSpace(strings.TrimPrefix(status, prefix))
	}
	if status == "" {
		status = http.StatusText(resp.StatusCode)
	}
	return status
}

func durationMS(d time.Duration, known bool) float64 {
	if d < 0 || (!known && d == 0) {
		return -1
	}
	return float64(d) / float64(time.Millisecond)
}

func requestCookies(req *http.Request) []Cookie {
	if req == nil {
		return []Cookie{}
	}
	cookies := req.Cookies()
	out := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		out = append(out, Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	return out
}

func responseCookies(resp *http.Response) []Cookie {
	if resp == nil {
		return []Cookie{}
	}
	cookies := resp.Cookies()
	out := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		item := Cookie{Name: cookie.Name, Value: cookie.Value, Path: cookie.Path, Domain: cookie.Domain, HttpOnly: cookie.HttpOnly, Secure: cookie.Secure}
		if !cookie.Expires.IsZero() {
			item.Expires = cookie.Expires.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out
}

func requestHeaders(req *http.Request) []NameValue {
	if req == nil {
		return []NameValue{}
	}
	out := headers(req.Header)
	if req.Host != "" {
		out = append(out, NameValue{Name: "Host", Value: req.Host})
	}
	return out
}

func responseHeaders(h http.Header) []NameValue { return headers(h) }

func responseHeadersWithTrailers(resp *http.Response) []NameValue {
	if resp == nil {
		return []NameValue{}
	}
	out := responseHeaders(resp.Header)
	// HAR 1.2 has no separate trailer field. Preserve trailers as additional
	// response header entries; this keeps grpc-status/grpc-message and custom
	// trailers available without pretending they were initial headers.
	for name, values := range resp.Trailer {
		for _, value := range values {
			out = append(out, NameValue{Name: name, Value: value})
		}
	}
	return out
}

func headers(h http.Header) []NameValue {
	if len(h) == 0 {
		return []NameValue{}
	}
	out := make([]NameValue, 0, len(h))
	for name, values := range h {
		for _, value := range values {
			out = append(out, NameValue{Name: name, Value: value})
		}
	}
	return out
}

func queryEntries(rawURL string) []NameValue {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return []NameValue{}
	}
	parts := strings.Split(u.RawQuery, "&")
	out := make([]NameValue, 0, len(parts))
	for _, part := range parts {
		key, value, _ := strings.Cut(part, "=")
		key, err = url.QueryUnescape(key)
		if err != nil {
			key = part
		}
		value, err = url.QueryUnescape(value)
		if err != nil {
			value = ""
		}
		out = append(out, NameValue{Name: key, Value: value})
	}
	return out
}

func creator() Creator { return Creator{Name: "fetch", Version: core.Version} }

// HAR 1.2 data model. The fields are intentionally small and explicit so the
// JSON remains stable and does not expose Go implementation details.
type harDocument struct {
	Log harLog `json:"log"`
}
type harLog struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Entries []Entry `json:"entries"`
}
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type Entry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         Request        `json:"request"`
	Response        Response       `json:"response"`
	Cache           map[string]any `json:"cache"`
	Timings         TimingsHAR     `json:"timings"`
	ServerIPAddress string         `json:"serverIPAddress,omitempty"`
}
type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	Cookies     []Cookie    `json:"cookies"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}
type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	Cookies     []Cookie    `json:"cookies"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HttpOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}
type PostData struct {
	MIMEType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}
type Content struct {
	Size     int64  `json:"size"`
	MIMEType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}
type TimingsHAR struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	SSL     float64 `json:"ssl"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func (p *PostData) setBody(data []byte, forceBinary bool) {
	if !forceBinary && isText(data) {
		p.Text = string(data)
		return
	}
	p.Text = base64.StdEncoding.EncodeToString(data)
	p.Encoding = "base64"
}
func (c *Content) setBody(data []byte, forceBinary bool) {
	if !forceBinary && isText(data) {
		c.Text = string(data)
		return
	}
	c.Text = base64.StdEncoding.EncodeToString(data)
	c.Encoding = "base64"
}
func isText(data []byte) bool {
	return utf8.Valid(data)
}

func isBinaryMIME(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		mediaType = strings.TrimSpace(strings.ToLower(strings.SplitN(value, ";", 2)[0]))
	}
	mediaType = strings.ToLower(mediaType)
	return strings.HasPrefix(mediaType, "application/grpc")
}
