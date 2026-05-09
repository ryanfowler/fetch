package resolver

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

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

func lookupDOH(ctx context.Context, serverURL *url.URL, host string) ([]net.IPAddr, error) {
	a, aErr := LookupDOHType(ctx, serverURL, host, "A", dnsTypeA)
	aaaa, aaaaErr := LookupDOHType(ctx, serverURL, host, "AAAA", dnsTypeAAAA)

	addrs := make([]net.IPAddr, 0, len(a)+len(aaaa))
	for _, record := range a {
		addrs = append(addrs, net.IPAddr{IP: record.IP})
	}
	for _, record := range aaaa {
		addrs = append(addrs, net.IPAddr{IP: record.IP})
	}
	if len(addrs) > 0 {
		return addrs, nil
	}
	if aErr != nil {
		return nil, aErr
	}
	if aaaaErr != nil {
		return nil, aaaaErr
	}
	return nil, errors.New("no such host")
}

// DNSRecord is a resolved DNS answer with optional TTL metadata.
type DNSRecord struct {
	IP  net.IP
	TTL int
}

// LookupDOHType resolves one DNS record family through a DNS-over-HTTPS JSON endpoint.
func LookupDOHType(ctx context.Context, serverURL *url.URL, host, dnsType string, answerType int) ([]DNSRecord, error) {
	type answer struct {
		Type int    `json:"type"`
		Data string `json:"data"`
		TTL  int    `json:"TTL"`
	}
	type response struct {
		Status int      `json:"Status"`
		Answer []answer `json:"Answer"`
	}

	u := *serverURL
	q := u.Query()
	q.Set("name", host)
	q.Set("type", dnsType)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
		type errorResponse struct {
			Error string `json:"error"`
		}
		var errRes errorResponse
		err = json.Unmarshal(raw, &errRes)
		if err == nil && errRes.Error != "" {
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, errRes.Error)
		}
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, raw)
	}

	var res response
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	if res.Status != 0 || len(res.Answer) == 0 {
		name := rcodeName(res.Status)
		if name == "" {
			return nil, errors.New("no such host")
		}
		return nil, fmt.Errorf("no such host: %s", name)
	}

	records := make([]DNSRecord, 0, len(res.Answer))
	for _, answer := range res.Answer {
		if answer.Type != answerType {
			continue
		}
		ip := net.ParseIP(answer.Data)
		if ip != nil {
			records = append(records, DNSRecord{IP: ip, TTL: answer.TTL})
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no such host")
	}
	return records, nil
}
