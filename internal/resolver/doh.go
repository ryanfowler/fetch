package resolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

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

// ErrDOHProtocolIncompatible indicates that a DoH endpoint clearly does not
// implement RFC 8484 wire messages. Only this error permits JSON fallback.
var ErrDOHProtocolIncompatible = errors.New("DoH endpoint does not support DNS wire messages")

func lookupDOHWireMessage(ctx context.Context, serverURL *url.URL, host string, answerType int) (*Message, error) {
	qname, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	query, id, err := EncodeQuery(host, uint16(answerType))
	if err != nil {
		return nil, err
	}
	question := Question{Name: qname, Type: uint16(answerType), Class: 1}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", core.UserAgent)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotAcceptable || resp.StatusCode == http.StatusUnsupportedMediaType {
			return nil, ErrDOHProtocolIncompatible
		}
		return nil, fmt.Errorf("DoH response code: %d", resp.StatusCode)
	}
	if contentType != "application/dns-message" {
		return nil, ErrDOHProtocolIncompatible
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(raw) > 65535 {
		return nil, errors.New("DoH wire response exceeds the 65535-byte limit")
	}
	message, err := DecodeResponse(raw, id, question)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH wire response: %w", err)
	}
	if message.Header.RCode != 0 {
		return nil, fmt.Errorf("DoH response: %s", RCodeName(message.Header.RCode))
	}
	if _, err := AuthorizeAnswers(message, question); err != nil {
		return nil, err
	}
	return message, nil
}

// LookupDOHWireMessage performs one strict RFC 8484 query. It is used by DNS
// inspection so wire and address-resolution paths share validation.
func LookupDOHWireMessage(ctx context.Context, serverURL *url.URL, host string, answerType int) (*Message, error) {
	return lookupDOHWireMessage(ctx, serverURL, host, answerType)
}

func lookupDOHWireType(ctx context.Context, serverURL *url.URL, host string, answerType int) ([]DNSRecord, error) {
	message, err := lookupDOHWireMessage(ctx, serverURL, host, answerType)
	if err != nil {
		return nil, err
	}
	name, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	authorized, err := AuthorizeAddressAnswers(message, Question{Name: name, Type: uint16(answerType), Class: 1})
	if err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(authorized))
	for _, answer := range authorized {
		if int(answer.Type) != answerType {
			continue
		}
		if ip := RecordAddress(answer); ip != nil {
			out = append(out, DNSRecord{IP: ip, TTL: int(answer.TTL)})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

// LookupDOHType resolves one DNS record family through a DNS-over-HTTPS
// endpoint. RFC 8484 wire format is authoritative; JSON is retained only for
// endpoints that clearly do not implement the wire protocol.
func LookupDOHType(ctx context.Context, serverURL *url.URL, host, dnsType string, answerType int) ([]DNSRecord, error) {
	if records, err := lookupDOHWireType(ctx, serverURL, host, answerType); err == nil {
		return records, nil
	} else if !errors.Is(err, ErrDOHProtocolIncompatible) {
		return nil, err
	}
	type answer struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
		TTL  uint32 `json:"TTL"`
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

	rawJSON, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(rawJSON) > 1<<20 {
		return nil, errors.New("DoH JSON response exceeds the 1 MiB limit")
	}
	var res response
	if err := json.Unmarshal(rawJSON, &res); err != nil {
		return nil, err
	}

	if res.Status != 0 || len(res.Answer) == 0 {
		name := rcodeName(res.Status)
		if name == "" {
			return nil, errors.New("no such host")
		}
		return nil, fmt.Errorf("no such host: %s", name)
	}

	qname, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	question := Question{Name: qname, Type: uint16(answerType), Class: 1}
	message := &Message{Answers: make([]Record, 0, len(res.Answer))}
	for _, answer := range res.Answer {
		owner := qname
		if answer.Name != "" {
			owner, err = ParseName(answer.Name)
			if err != nil {
				return nil, fmt.Errorf("invalid DoH JSON answer owner: %w", err)
			}
		}
		record := Record{Owner: owner, Type: uint16(answer.Type), Class: 1, TTL: answer.TTL}
		switch answer.Type {
		case dnsTypeA, dnsTypeAAAA:
			ip := net.ParseIP(answer.Data)
			if ip == nil || (answer.Type == dnsTypeA && ip.To4() == nil) || (answer.Type == dnsTypeAAAA && (ip.To16() == nil || ip.To4() != nil)) {
				return nil, errors.New("invalid DoH JSON address")
			}
			if answer.Type == dnsTypeA {
				record.RData = append([]byte(nil), ip.To4()...)
			} else {
				record.RData = append([]byte(nil), ip.To16()...)
			}
		case 5:
			target, parseErr := ParseName(answer.Data)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid DoH JSON CNAME: %w", parseErr)
			}
			record.Target = &target
			record.RData, _ = target.Wire()
		default:
			continue
		}
		message.Answers = append(message.Answers, record)
	}
	answers, err := AuthorizeAddressAnswers(message, question)
	if err != nil {
		return nil, err
	}
	records := make([]DNSRecord, 0, len(answers))
	for _, answer := range answers {
		if int(answer.Type) == answerType {
			if ip := RecordAddress(answer); ip != nil {
				records = append(records, DNSRecord{IP: ip, TTL: int(answer.TTL)})
			}
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no such host")
	}
	return records, nil
}
