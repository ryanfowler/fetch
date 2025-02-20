package aws

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/vars"
)

const (
	datetimeFormat = "20060102T150405Z"
	dateFormat     = "20060102"

	headerContentSha256 = "X-Amz-Content-Sha256"
	emptySha256         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type Config struct {
	AccessKey string
	SecretKey string
	Region    string
	Service   string
}

func Sign(req *http.Request, cfg Config, now time.Time) error {
	datetime := now.Format(datetimeFormat)
	req.Header.Set("X-Amz-Date", datetime)

	payload, err := getPayloadHash(req, cfg.Service)
	if err != nil {
		return err
	}
	req.Header.Set(headerContentSha256, payload)

	signedHeaders := getSignedHeaders(req)
	canonicalRequest := buildCanonicalRequest(req, signedHeaders, payload)
	stringToSign := buildStringToSign(datetime, cfg.Region, cfg.Service, canonicalRequest)
	signingKey := createSigningKey(datetime[:8], cfg.Region, cfg.Service, cfg.SecretKey)
	signature := hex.EncodeToString(hmacSha256(signingKey, stringToSign))

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

	req.Header.Set("Authorization", sb.String())
	return nil
}

func getPayloadHash(req *http.Request, service string) (string, error) {
	if payload := req.Header.Get(headerContentSha256); payload != "" {
		return payload, nil
	}

	if req.Body == nil || req.Body == http.NoBody {
		return emptySha256, nil
	}

	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return "", err
		}
		defer body.Close()
		return hexSha256Reader(body)
	}

	if rs, ok := req.Body.(io.ReadSeeker); ok {
		payload, err := hexSha256Reader(rs)
		if err != nil {
			return "", err
		}
		if _, err := rs.Seek(0, 0); err != nil {
			return "", err
		}
		return payload, nil
	}

	if service == "s3" {
		return "UNSIGNED-PAYLOAD", nil
	}

	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	return hexSha256Reader(bytes.NewReader(body))
}

func getSignedHeaders(req *http.Request) []vars.KeyVal {
	out := make([]vars.KeyVal, 0, len(req.Header)+1)
	out = append(out, vars.KeyVal{Key: "host", Val: req.URL.Host})
	for key, vals := range req.Header {
		switch key {
		case "Authorization", "Content-Length", "User-Agent":
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val := strings.TrimSpace(strings.Join(vals, ","))
		out = append(out, vars.KeyVal{Key: key, Val: val})
	}
	slices.SortFunc(out, func(a, b vars.KeyVal) int {
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

func buildCanonicalRequest(req *http.Request, headers []vars.KeyVal, payload string) []byte {
	var buf bytes.Buffer
	buf.Grow(512)

	buf.WriteString(req.Method)
	buf.WriteByte('\n')

	path := req.URL.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	escapeURIPath(&buf, path)
	buf.WriteByte('\n')

	buf.WriteString(strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20"))
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
