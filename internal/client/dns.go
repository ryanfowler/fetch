package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/ryanfowler/fetch/internal/core"
)

// dialContextUDP returns a DialContext function that performs a DNS lookup
// using the provided DNS server address and port.
func dialContextUDP(serverAddr string) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, serverAddr)
			},
		},
	}
	return dialer.DialContext
}

// dialContextDOH returns a DialContext function that performs a DoH lookup
// using the provided DoH server address.
func dialContextDOH(serverURL *url.URL) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		// Lookup A record first, fallback to AAAA.
		ip, err := lookupDOH(ctx, serverURL, host, "A")
		if err != nil {
			ip, err = lookupDOH(ctx, serverURL, host, "AAAA")
			if err != nil {
				return nil, fmt.Errorf("lookup %s: %w", host, err)
			}
		}

		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// lookupDOH performs a DNS lookup via DoH with the provided DoH server URL,
// host to lookup, and DNS type.
func lookupDOH(ctx context.Context, serverURL *url.URL, host, dnsType string) (string, error) {
	type Answer struct {
		Data string `json:"data"`
	}
	type Response struct {
		Status int      `json:"Status"`
		Answer []Answer `json:"Answer"`
	}

	q := serverURL.Query()
	q.Set("name", host)
	q.Set("type", dnsType)
	serverURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", serverURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", core.UserAgent)

	var client http.Client
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		if err != nil {
			return "", fmt.Errorf("http response code: %d", resp.StatusCode)
		}
		type ErrRes struct {
			Error string `json:"error"`
		}
		var errRes ErrRes
		err = json.Unmarshal(raw, &errRes)
		if err == nil && errRes.Error != "" {
			return "", fmt.Errorf("%d: %s", resp.StatusCode, errRes.Error)
		}
		return "", fmt.Errorf("%d: %s", resp.StatusCode, raw)
	}

	var res Response
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return "", err
	}

	if res.Status != 0 || len(res.Answer) == 0 {
		name := rcodeName(res.Status)
		if name == "" {
			return "", errors.New("no such host")
		}
		return "", fmt.Errorf("no such host: %s", name)
	}

	return res.Answer[0].Data, nil
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
		return "NXRRSet"
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
