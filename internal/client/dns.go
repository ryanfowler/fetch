package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"

	"github.com/ryanfowler/fetch/internal/core"
)

// dialContextUDP returns a DialContext function that performs a DNS lookup
// using the provided DNS server address and port.
func dialContextUDP(serverAddr string) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Resolver: udpResolver(serverAddr)}
	return dialer.DialContext
}

func udpResolver(serverAddr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, serverAddr)
		},
	}
}

// dialContextDOH returns a DialContext function that performs a DoH lookup
// using the provided DoH server address.
func dialContextDOH(serverURL *url.URL) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ips, port, err := resolveDOH(ctx, serverURL, address)
		if err != nil {
			return nil, err
		}

		var d net.Dialer
		for _, ip := range ips {
			var conn net.Conn
			conn, err = d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
}

func resolveDOH(ctx context.Context, serverURL *url.URL, address string) ([]net.IPAddr, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, "", err
	}

	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.DNSStart != nil {
		trace.DNSStart(httptrace.DNSStartInfo{Host: host})
	}

	// Lookup A record first, fallback to AAAA.
	ipStrs, err := lookupDOH(ctx, serverURL, host, "A")
	if err != nil {
		ipStrs, err = lookupDOH(ctx, serverURL, host, "AAAA")
	}

	ips := make([]net.IPAddr, 0, len(ipStrs))
	for _, ip := range ipStrs {
		ips = append(ips, net.IPAddr{IP: net.ParseIP(ip)})
	}

	if trace != nil && trace.DNSDone != nil {
		info := httptrace.DNSDoneInfo{Err: err}
		if err == nil {
			info.Addrs = append(info.Addrs, ips...)
		}
		trace.DNSDone(info)
	}

	if err != nil {
		return nil, "", fmt.Errorf("lookup %s: %w", host, err)
	}

	return ips, port, nil
}

// lookupDOH performs a DNS lookup via DoH with the provided DoH server URL,
// host to lookup, and DNS type.
func lookupDOH(ctx context.Context, serverURL *url.URL, host, dnsType string) ([]string, error) {
	type Answer struct {
		Data string `json:"data"`
	}
	type Response struct {
		Status int      `json:"Status"`
		Answer []Answer `json:"Answer"`
	}

	u := *serverURL
	q := u.Query()
	q.Set("name", host)
	q.Set("type", dnsType)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", core.UserAgent)

	var client http.Client
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		if err != nil {
			return nil, fmt.Errorf("http response code: %d", resp.StatusCode)
		}
		type ErrRes struct {
			Error string `json:"error"`
		}
		var errRes ErrRes
		err = json.Unmarshal(raw, &errRes)
		if err == nil && errRes.Error != "" {
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, errRes.Error)
		}
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, raw)
	}

	var res Response
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	if res.Status != 0 || len(res.Answer) == 0 {
		name := rcodeName(res.Status)
		if name == "" {
			return nil, errors.New("no such host")
		}
		return nil, fmt.Errorf("no such host: %s", name)
	}

	addrs := make([]string, len(res.Answer))
	for i, answer := range res.Answer {
		addrs[i] = answer.Data
	}
	return addrs, nil
}

// rcodeName returns the text for the provided rcode integer.
func rcodeName(n int) string {
	switch n {
	case 0:
		return "NoError"
	case 1:
		return "FormErr"
	case 2:
		return "ServFail"
	case 3:
		return "NXDomain"
	case 4:
		return "NotImp"
	case 5:
		return "Refused"
	case 6:
		return "YXDomain"
	case 7:
		return "YXRRSet"
	case 8:
		return "NXRRSet"
	case 9:
		return "NotAuth"
	case 10:
		return "NotZone"
	case 11:
		return "DSOTYPENI"
	case 16:
		return "BADSIG"
	case 17:
		return "BADKEY"
	case 18:
		return "BADTIME"
	case 19:
		return "BADMODE"
	case 20:
		return "BADNAME"
	case 21:
		return "BADALG"
	case 22:
		return "BADTRUNC"
	case 23:
		return "BADCOOKIE"
	default:
		return ""
	}
}
