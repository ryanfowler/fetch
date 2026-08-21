package aws

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/core"
)

const (
	datetimeFormat = "20060102T150405Z"

	headerContentSha256 = "X-Amz-Content-Sha256"
	emptySha256         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type Config struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Region       string
	Service      string
}

// MissingEnvVarError is returned when credentials are required for signing but
// the corresponding environment variable is not set.
type MissingEnvVarError struct {
	EnvVar string
}

func (err *MissingEnvVarError) Error() string {
	return "missing environment variable '" + err.EnvVar + "' required for option '--aws-sigv4'"
}

func (err *MissingEnvVarError) PrintTo(p *core.Printer) {
	p.WriteString("missing environment variable '")
	p.Set(core.Yellow)
	p.WriteString(err.EnvVar)
	p.Reset()

	p.WriteString("' required for option '")
	p.Set(core.Bold)
	p.WriteString("--aws-sigv4")
	p.Reset()
	p.WriteString("'")
}

// Sign signs the provided HTTP request with the information from Config,
// returning any error encountered.
func Sign(req *http.Request, cfg Config, now time.Time) error {
	if err := fillEnvCredentials(&cfg); err != nil {
		return err
	}

	if cfg.SessionToken != "" {
		setHeaderInsensitive(req, "X-Amz-Security-Token", cfg.SessionToken)
	}

	datetime := now.Format(datetimeFormat)
	setHeaderInsensitive(req, "X-Amz-Date", datetime)

	payload, err := getPayloadHash(req, cfg.Service)
	if err != nil {
		return err
	}
	setHeaderInsensitive(req, headerContentSha256, payload)

	// Build the signature.
	signedHeaders := getSignedHeaders(req)
	canonicalRequest := buildCanonicalRequest(req, signedHeaders, payload)
	stringToSign := buildStringToSign(datetime, cfg.Region, cfg.Service, canonicalRequest)
	signingKey := createSigningKey(datetime[:8], cfg.Region, cfg.Service, cfg.SecretKey)
	signature := hex.EncodeToString(hmacSha256(signingKey, stringToSign))

	// Format the Authorization header value.
	var sb strings.Builder
	sb.Grow(512)

	sb.WriteString("AWS4-HMAC-SHA256 Credential=")
	sb.WriteString(cfg.AccessKey)
	sb.WriteByte('/')
	sb.WriteString(datetime[:8])
	sb.WriteByte('/')
	sb.WriteString(cfg.Region)
	sb.WriteByte('/')
	sb.WriteString(cfg.Service)
	sb.WriteString("/aws4_request,SignedHeaders=")
	for i, kv := range signedHeaders {
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString(kv.Key)
	}
	sb.WriteString(",Signature=")
	sb.WriteString(signature)

	setHeaderInsensitive(req, "Authorization", sb.String())
	return nil
}

func setHeaderInsensitive(req *http.Request, name, value string) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for key := range req.Header {
		if strings.EqualFold(key, name) {
			delete(req.Header, key)
		}
	}
	req.Header.Set(name, value)
}

func headerValueInsensitive(header http.Header, name string) string {
	for key, values := range header {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func fillEnvCredentials(cfg *Config) error {
	if cfg.AccessKey == "" {
		cfg.AccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
		if cfg.AccessKey == "" {
			return &MissingEnvVarError{EnvVar: "AWS_ACCESS_KEY_ID"}
		}
	}
	if cfg.SecretKey == "" {
		cfg.SecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		if cfg.SecretKey == "" {
			return &MissingEnvVarError{EnvVar: "AWS_SECRET_ACCESS_KEY"}
		}
	}
	if cfg.SessionToken == "" {
		cfg.SessionToken = os.Getenv("AWS_SESSION_TOKEN")
	}
	return nil
}

// getPayloadHash returns the appropriate payload has for HTTP request and service.
func getPayloadHash(req *http.Request, service string) (string, error) {
	// If a payload header already exists, use that.
	if payload := headerValueInsensitive(req.Header, headerContentSha256); payload != "" {
		return payload, nil
	}

	// Use the empty sha256 if the request has no body.
	if req.Body == nil || req.Body == http.NoBody {
		return emptySha256, nil
	}

	if source, ok := body.SourceFromContext(req.Context()); ok {
		if source.Replayable() {
			stream, err := source.Replay()
			if err != nil {
				return "", err
			}
			defer stream.Close()
			return hexSha256Reader(stream)
		}
		if service == "s3" {
			return "UNSIGNED-PAYLOAD", nil
		}
		if _, err := source.Materialize(core.MaxCompositeMaterialization); err != nil {
			return "", err
		}
		body.Attach(req, source)
		stream, err := source.Replay()
		if err != nil {
			return "", err
		}
		defer stream.Close()
		return hexSha256Reader(stream)
	}

	// Attempt to utilize the GetBody function if it exists.
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return "", err
		}
		defer body.Close()
		return hexSha256Reader(body)
	}

	// If body implements io.ReadSeeker, calculate the hash and seek back
	// to the start afterwards.
	if rs, ok := req.Body.(io.ReadSeeker); ok && rs != os.Stdin {
		payload, err := hexSha256Reader(rs)
		if err != nil {
			return "", err
		}
		if _, err := rs.Seek(0, 0); err != nil {
			return "", err
		}
		return payload, nil
	}

	// At this point, if the service is S3, use the "UNISIGNED-PAYLOAD" to
	// avoid having to read the entire request body into memory.
	if service == "s3" {
		return "UNSIGNED-PAYLOAD", nil
	}

	// Read the entire body into memory to calculate the payload hash.
	oldBody := req.Body
	defer oldBody.Close()
	body, err := io.ReadAll(oldBody)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return hexSha256Reader(bytes.NewReader(body))
}

func getSignedHeaders(req *http.Request) []core.KeyVal[string] {
	out := make([]core.KeyVal[string], 0, len(req.Header)+1)

	// Host header is required to be signed.
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}
	if host != "" {
		out = append(out, core.KeyVal[string]{Key: "host", Val: host})
	}

	// Header maps normally contain canonicalized keys, but requests assembled
	// by integrations can contain differently cased keys. Merge those values
	// before canonicalization so each signed header appears exactly once.
	values := make(map[string][]string, len(req.Header))
	headerKeys := make([]string, 0, len(req.Header))
	for key := range req.Header {
		headerKeys = append(headerKeys, key)
	}
	slices.Sort(headerKeys)
	for _, key := range headerKeys {
		vals := req.Header[key]
		switch {
		case strings.EqualFold(key, "Host"):
			continue
		case strings.EqualFold(key, "Accept-Encoding"),
			strings.EqualFold(key, "Authorization"),
			strings.EqualFold(key, "Content-Length"),
			strings.EqualFold(key, "User-Agent"):
			// Avoid signing these headers.
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		values[key] = append(values[key], vals...)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		out = append(out, core.KeyVal[string]{Key: key, Val: canonicalHeaderValue(values[key])})
	}

	// Headers should be ordered by key.
	slices.SortFunc(out, func(a, b core.KeyVal[string]) int {
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

func canonicalHeaderValue(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	if len(vals) == 1 && isCanonicalHeaderValue(vals[0]) {
		return vals[0]
	}

	var buf strings.Builder
	buf.Grow(len(vals) - 1)
	for _, v := range vals {
		buf.Grow(len(v))
	}
	for i, v := range vals {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeCanonicalHeaderValue(&buf, v)
	}
	return buf.String()
}

func isCanonicalHeaderValue(val string) bool {
	inWhitespace := false
	wroteValue := false
	for _, r := range val {
		if !unicode.IsSpace(r) {
			inWhitespace = false
			wroteValue = true
			continue
		}
		if r != ' ' || inWhitespace || !wroteValue {
			return false
		}
		inWhitespace = true
	}
	return !inWhitespace
}

func writeCanonicalHeaderValue(buf *strings.Builder, val string) {
	inWhitespace := true
	wroteValue := false
	for _, r := range val {
		if unicode.IsSpace(r) {
			inWhitespace = true
			continue
		}
		if inWhitespace && wroteValue {
			buf.WriteByte(' ')
		}
		buf.WriteRune(r)
		inWhitespace = false
		wroteValue = true
	}
}

func buildCanonicalRequest(req *http.Request, headers []core.KeyVal[string], payload string) []byte {
	var buf bytes.Buffer
	buf.Grow(512)

	buf.WriteString(req.Method)
	buf.WriteByte('\n')

	writeCanonicalURIPath(&buf, req.URL)
	buf.WriteByte('\n')

	buf.WriteString(canonicalQuery(req.URL))
	buf.WriteByte('\n')

	for _, kv := range headers {
		buf.WriteString(kv.Key)
		buf.WriteByte(':')
		buf.WriteString(kv.Val)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')

	for i, kv := range headers {
		if i > 0 {
			buf.WriteByte(';')
		}
		buf.WriteString(kv.Key)
	}
	buf.WriteByte('\n')

	buf.WriteString(payload)

	return buf.Bytes()
}

type canonicalQueryPair struct {
	key   string
	value string
}

func canonicalQuery(u *url.URL) string {
	if u == nil || u.RawQuery == "" {
		return ""
	}

	parts := strings.Split(u.RawQuery, "&")
	pairs := make([]canonicalQueryPair, 0, len(parts))
	for _, part := range parts {
		key, value, _ := strings.Cut(part, "=")
		pairs = append(pairs, canonicalQueryPair{
			key:   awsPercentEncode(percentDecodeQuery(key)),
			value: awsPercentEncode(percentDecodeQuery(value)),
		})
	}

	slices.SortFunc(pairs, func(a, b canonicalQueryPair) int {
		if cmp := strings.Compare(a.key, b.key); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.value, b.value)
	})

	var out strings.Builder
	for i, pair := range pairs {
		if i > 0 {
			out.WriteByte('&')
		}
		out.WriteString(pair.key)
		out.WriteByte('=')
		out.WriteString(pair.value)
	}
	return out.String()
}

// percentDecodeQuery decodes valid percent escapes without applying HTML form
// semantics. In particular, '+' is a literal plus in a SigV4 query string.
func percentDecodeQuery(value string) []byte {
	decoded := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) && isHex(value[i+1]) && isHex(value[i+2]) {
			decoded = append(decoded, fromHex(value[i+1])<<4|fromHex(value[i+2]))
			i += 2
			continue
		}
		decoded = append(decoded, value[i])
	}
	return decoded
}

func fromHex(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

func awsPercentEncode(value []byte) string {
	const hexUpper = "0123456789ABCDEF"
	var out strings.Builder
	for _, b := range value {
		if validURIBytes[b] && b != '/' {
			out.WriteByte(b)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hexUpper[b>>4])
		out.WriteByte(hexUpper[b&0x0F])
	}
	return out.String()
}

func writeCanonicalURIPath(buf *bytes.Buffer, u *url.URL) {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	for i := 0; i < len(path); i++ {
		b := path[i]
		if b == '%' && i+2 < len(path) && isHex(path[i+1]) && isHex(path[i+2]) {
			buf.WriteByte('%')
			buf.WriteByte(toUpperHex(path[i+1]))
			buf.WriteByte(toUpperHex(path[i+2]))
			i += 2
			continue
		}
		if validURIBytes[b] {
			buf.WriteByte(b)
			continue
		}
		buf.WriteByte('%')
		encodeHexUpper(buf, b)
	}
}

func buildStringToSign(datetime string, region, service string, req []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(512)

	buf.WriteString("AWS4-HMAC-SHA256")
	buf.WriteByte('\n')

	buf.WriteString(datetime)
	buf.WriteByte('\n')

	buf.WriteString(datetime[:8])
	buf.WriteByte('/')
	buf.WriteString(region)
	buf.WriteByte('/')
	buf.WriteString(service)
	buf.WriteString("/aws4_request\n")

	buf.WriteString(hexSha256(req))

	return buf.Bytes()
}

func createSigningKey(date, region, service, secretKey string) []byte {
	dateKey := hmacSha256([]byte("AWS4"+secretKey), []byte(date))
	dateRegionKey := hmacSha256(dateKey, []byte(region))
	dateRegionServiceKey := hmacSha256(dateRegionKey, []byte(service))
	return hmacSha256(dateRegionServiceKey, []byte("aws4_request"))
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hexSha256(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func hexSha256Reader(r io.Reader) (string, error) {
	h := sha256.New()

	var err error
	if w, ok := r.(io.WriterTo); ok {
		_, err = w.WriteTo(h)
	} else {
		_, err = io.Copy(h, r)
	}
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
