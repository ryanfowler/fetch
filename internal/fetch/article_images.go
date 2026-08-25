package fetch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	imageoutput "github.com/ryanfowler/fetch/internal/image"
)

const (
	maxArticleImages     = 16
	maxArticleImageBytes = 8 << 20
	maxArticleImageTotal = 32 << 20
	articleImageTimeout  = 15 * time.Second
)

// articleImageFetcher resolves and renders Markdown images for an article's
// terminal presentation. It deliberately does not modify the Markdown source.
type terminalPresentationReader struct {
	io.Reader
}

func (terminalPresentationReader) terminalPresentation() {}

type articleImageFetcher struct {
	ctx     context.Context
	client  *client.Client
	mode    core.ImageSetting
	baseURL *url.URL

	images   map[string][]byte
	failed   map[string]bool
	count    int
	total    int64
	rendered int
}

func newArticleImageFetcher(ctx context.Context, c *client.Client, mode core.ImageSetting, pageURL string) *articleImageFetcher {
	baseURL, err := url.Parse(pageURL)
	if err != nil || baseURL == nil {
		return nil
	}
	return &articleImageFetcher{
		ctx:     ctx,
		client:  c,
		mode:    mode,
		baseURL: baseURL,
		images:  make(map[string][]byte),
		failed:  make(map[string]bool),
	}
}

func (f *articleImageFetcher) render(destination string, dst io.Writer) bool {
	if f == nil || f.client == nil || dst == nil || f.rendered >= maxArticleImages {
		return false
	}
	target, ok := f.resolve(destination)
	if !ok {
		return false
	}
	key := target.String()
	data, cached := f.images[key]
	if !cached {
		if f.failed[key] || f.count >= maxArticleImages || f.total >= maxArticleImageTotal {
			return false
		}
		f.count++
		var err error
		data, err = f.fetch(target)
		if err != nil {
			f.failed[key] = true
			return false
		}
		if int64(len(data)) > maxArticleImageTotal-f.total {
			f.failed[key] = true
			return false
		}
		f.images[key] = data
		f.total += int64(len(data))
	}

	if err := imageoutput.RenderWithModeTo(f.ctx, data, f.mode, dst); err != nil {
		return false
	}
	f.rendered++
	return true
}

func (f *articleImageFetcher) fetch(target *url.URL) ([]byte, error) {
	ctx, cancel := context.WithTimeout(f.ctx, articleImageTimeout)
	defer cancel()

	req, err := f.client.NewRequest(ctx, client.RequestConfig{URL: target})
	if err != nil {
		return nil, err
	}
	// Do not forward the article request's custom headers or credentials to
	// image hosts. The shared client still supplies the configured transport,
	// proxy, TLS, compression, and cookie policy.
	req.Header.Set("Accept", "image/*")
	ctx = client.WithRedirectValidator(ctx, func(hop client.RedirectHop) error {
		if hop.NextRequest == nil || !safeArticleImageURL(ctx, hop.NextRequest.URL, f.client.LookupIPAddr) {
			return errors.New("article image redirect targets a private or non-public address")
		}
		return nil
	})
	req = req.WithContext(ctx)
	blockedPeer := false
	if !f.client.UsesProxy(req.URL) {
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if articleImagePrivatePeer(info.Conn) {
					blockedPeer = true
					_ = info.Conn.Close()
				}
			},
		}))
	}
	resp, err := f.client.Do(req)
	if blockedPeer {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, errors.New("article image connection targets a private address")
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, io.ErrUnexpectedEOF
	}
	if resp.Request == nil || !safeArticleImageURL(ctx, resp.Request.URL, f.client.LookupIPAddr) {
		return nil, io.ErrUnexpectedEOF
	}
	if resp.ContentLength > maxArticleImageBytes {
		return nil, io.ErrShortBuffer
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArticleImageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxArticleImageBytes {
		return nil, io.ErrShortBuffer
	}
	return data, nil
}

func (f *articleImageFetcher) resolve(destination string) (*url.URL, bool) {
	destination = strings.TrimSpace(destination)
	if destination == "" || f.baseURL == nil {
		return nil, false
	}
	target, err := url.Parse(destination)
	if err != nil {
		return nil, false
	}
	target = f.baseURL.ResolveReference(target)
	target.Fragment = ""
	if !safeArticleImageURL(f.ctx, target, f.client.LookupIPAddr) {
		return nil, false
	}
	return target, true
}

func safeArticleImageURL(ctx context.Context, target *url.URL, lookup func(context.Context, string) ([]net.IPAddr, error)) bool {
	if target == nil || target.User != nil || target.Host == "" {
		return false
	}
	switch strings.ToLower(target.Scheme) {
	case "http", "https":
	default:
		return false
	}

	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return safeArticleImageIP(ip)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	addresses, err := lookup(ctx, host)
	if err != nil || len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if !safeArticleImageIP(address.IP) {
			return false
		}
	}
	return true
}

func safeArticleImageIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return !nonPublicArticleIPv4(v4)
	}
	// Documentation, benchmarking, discard, and reserved IPv6 ranges are not
	// routable article destinations and must not be used to bypass this policy.
	return !(len(ip) == net.IPv6len &&
		(ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 ||
			ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x02 ||
			ip[0] == 0x3f && ip[1]&0xf0 == 0xf0 ||
			ip[0] == 0x00 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 &&
				ip[4] == 0x00 && ip[5] == 0x00 && ip[6] == 0x00 && ip[7] == 0x00))
}

func nonPublicArticleIPv4(ip net.IP) bool {
	if len(ip) < net.IPv4len {
		return true
	}
	switch {
	case ip[0] == 0 || ip[0] == 127 || ip[0] >= 224:
		return true
	case ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127:
		return true // Shared address space, RFC 6598.
	case ip[0] == 169 && ip[1] == 254:
		return true
	case ip[0] == 192 && (ip[1] == 0 || ip[1] == 2 || ip[1] == 88 || ip[1] == 168):
		return true
	case ip[0] == 198 && (ip[1] == 18 || ip[1] == 19 || ip[1] == 51):
		return true
	case ip[0] == 203 && ip[1] == 0 && ip[2] == 113:
		return true
	case ip[0] >= 240:
		return true
	default:
		return false
	}
}

func articleImagePrivatePeer(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && !safeArticleImageIP(ip)
}
