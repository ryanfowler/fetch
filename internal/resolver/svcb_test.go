package resolver

import (
	"encoding/binary"
	"strings"
	"testing"
)

func svcbName(labels ...string) []byte {
	var out []byte
	for _, label := range labels {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func svcbParam(key uint16, value []byte) []byte {
	out := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(out, key)
	binary.BigEndian.PutUint16(out[2:], uint16(len(value)))
	return append(out, value...)
}

func svcbRData(priority uint16, target []string, params ...[]byte) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, priority)
	out = append(out, svcbName(target...)...)
	for _, param := range params {
		out = append(out, param...)
	}
	return out
}

func TestParseSVCBRDataValidatesServiceParameters(t *testing.T) {
	alpn := []byte{2, 'h', '3'}
	raw := svcbRData(1, nil,
		svcbParam(svcParamALPN, alpn),
		svcbParam(svcParamNoDefaultALPN, nil),
		svcbParam(svcParamPort, []byte{0x11, 0x5c}),
		svcbParam(svcParamIPv4Hint, []byte{192, 0, 2, 1}),
		svcbParam(svcParamIPv6Hint, make([]byte, 16)),
	)
	parsed, err := ParseSVCBRData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Priority != 1 || !parsed.Target.Equal(Name{}) || !parsed.HasPort || parsed.Port != 4444 {
		t.Fatalf("parsed record = %#v", parsed)
	}
	if len(parsed.ALPN) != 1 || string(parsed.ALPN[0]) != "h3" || !parsed.NoDefaultALPN {
		t.Fatalf("ALPN = %#v, no-default-alpn = %v", parsed.ALPN, parsed.NoDefaultALPN)
	}
	if len(parsed.IPv4Hints) != 1 || len(parsed.IPv6Hints) != 1 {
		t.Fatalf("hints = %#v/%#v", parsed.IPv4Hints, parsed.IPv6Hints)
	}
}

func TestSortSVCBRecordsOrdersPriorityAndUsesInjectedRandomness(t *testing.T) {
	input := []SVCBRecord{{Priority: 20}, {Priority: 10}, {Priority: 10}}
	calls := 0
	got := SortSVCBRecords(input, func(bound int) int {
		calls++
		if bound < 1 {
			t.Fatal("random bound was empty")
		}
		return 0
	})
	if got[0].Priority != 10 || got[1].Priority != 10 || got[2].Priority != 20 {
		t.Fatalf("priorities = %#v", got)
	}
	if calls == 0 {
		t.Fatal("equal-priority records were not randomized")
	}
	if input[0].Priority != 20 {
		t.Fatalf("SortSVCBRecords mutated its input")
	}
}

func TestParseSVCBRDataPreservesUnknownOptionalAndTracksMandatory(t *testing.T) {
	raw := svcbRData(1, nil,
		svcbParam(svcParamMandatory, []byte{0, 1, 0, 9}),
		svcbParam(svcParamALPN, []byte{2, 'h', '3'}),
		svcbParam(9, []byte("opaque")),
	)
	parsed, err := ParseSVCBRData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.IsUsable() || len(parsed.UnsupportedMandatory) != 1 || parsed.UnsupportedMandatory[0] != 9 {
		t.Fatalf("mandatory usability = %#v", parsed)
	}
	if len(parsed.Params) != 3 || string(parsed.Params[2].Value) != "opaque" {
		t.Fatalf("params = %#v", parsed.Params)
	}
}

func TestParseSVCBRDataRejectsMalformedParameters(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"duplicate", svcbRData(1, nil, svcbParam(svcParamALPN, []byte{2, 'h', '3'}), svcbParam(svcParamALPN, []byte{2, 'h', '2'})), "repeated"},
		{"out of order", svcbRData(1, nil, svcbParam(svcParamPort, []byte{0, 1}), svcbParam(svcParamALPN, []byte{2, 'h', '3'})), "not greater"},
		{"missing mandatory", svcbRData(1, nil, svcbParam(svcParamMandatory, []byte{0, 3}), svcbParam(svcParamALPN, []byte{2, 'h', '3'})), "absent"},
		{"mandatory zero", svcbRData(1, nil, svcbParam(svcParamMandatory, []byte{0, 0})), "key 0"},
		{"empty ALPN", svcbRData(1, nil, svcbParam(svcParamALPN, nil)), "empty value"},
		{"truncated ALPN", svcbRData(1, nil, svcbParam(svcParamALPN, []byte{3, 'h', '3'})), "only 2 remain"},
		{"valued no-default-alpn", svcbRData(1, nil, svcbParam(svcParamNoDefaultALPN, []byte{1})), "empty value"},
		{"no-default-alpn without ALPN", svcbRData(1, nil, svcbParam(svcParamNoDefaultALPN, nil)), "without alpn"},
		{"bad port", svcbRData(1, nil, svcbParam(svcParamPort, []byte{1})), "not 2"},
		{"empty IPv4 hint", svcbRData(1, nil, svcbParam(svcParamIPv4Hint, nil)), "nonzero multiple"},
		{"bad IPv6 hint", svcbRData(1, nil, svcbParam(svcParamIPv6Hint, make([]byte, 15))), "nonzero multiple"},
		{"bad ECH framing", svcbRData(1, nil, svcbParam(svcParamECH, []byte{0, 2, 0xfe})), "declares 2"},
		{"alias parameters", svcbRData(0, []string{"alias", "example"}, svcbParam(svcParamALPN, []byte{2, 'h', '3'})), "AliasMode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseSVCBRData(test.raw)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseSVCBRRSetRejectsMalformedRecordAtomically(t *testing.T) {
	valid := Record{Type: dnsTypeHTTPS, RData: svcbRData(1, nil, svcbParam(svcParamALPN, []byte{2, 'h', '3'}))}
	malformed := Record{Type: dnsTypeHTTPS, RData: svcbRData(2, nil, svcbParam(svcParamALPN, []byte{2, 'h', '3'}), svcbParam(svcParamALPN, []byte{2, 'h', '2'}))}
	parsed, err := ParseSVCBRRSet([]Record{valid, malformed})
	if err == nil || !strings.Contains(err.Error(), "record 1") {
		t.Fatalf("error = %v", err)
	}
	if parsed != nil {
		t.Fatalf("malformed RRset returned partial records: %#v", parsed)
	}
}

func TestDecodeMessageRejectsMalformedHTTPSRecord(t *testing.T) {
	packet := recordPacket([]byte{0}, dnsTypeHTTPS, svcbRData(1, nil, svcbParam(svcParamPort, []byte{1})))
	if _, err := DecodeMessage(packet); err == nil || !strings.Contains(err.Error(), "not 2") {
		t.Fatalf("DecodeMessage error = %v", err)
	}
}

func TestDecodeMessageRejectsCompressedSVCBTarget(t *testing.T) {
	tests := [][]byte{
		{0, 1, 0xc0, 0x0c},
		{0, 1, 1, 'a', 0xc0, 0x0c},
	}
	for _, rdata := range tests {
		packet := recordPacket([]byte{0}, dnsTypeHTTPS, rdata)
		if _, err := DecodeMessage(packet); err == nil || !strings.Contains(err.Error(), "must not use compression") {
			t.Fatalf("DecodeMessage error = %v", err)
		}
	}
}

func TestDecodeMessageRejectsReservedSVCBParameterKey(t *testing.T) {
	packet := recordPacket([]byte{0}, dnsTypeHTTPS, svcbRData(1, nil, svcbParam(^uint16(0), nil)))
	if _, err := DecodeMessage(packet); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("DecodeMessage error = %v", err)
	}
}

func TestParseJSONSVCBPresentationDecodesDNSValueEscapes(t *testing.T) {
	parsed, _, err := parseJSONSVCBPresentation(`1 . alpn="h3\044foo,h2"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.ALPN) != 2 || string(parsed.ALPN[0]) != "h3,foo" || string(parsed.ALPN[1]) != "h2" {
		t.Fatalf("ALPN = %#v", parsed.ALPN)
	}
}

func TestParseJSONSVCBPresentationNormalizesParameterOrder(t *testing.T) {
	parsed, _, err := parseJSONSVCBPresentation("1 . alpn=h2 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Mandatory) != 2 || parsed.Mandatory[0] != svcParamALPN || parsed.Mandatory[1] != svcParamIPv4Hint {
		t.Fatalf("mandatory = %#v", parsed.Mandatory)
	}
}

func TestParseJSONSVCBPresentationAcceptsEscapedWhitespaceAndEmptyUnknownValue(t *testing.T) {
	parsed, _, err := parseJSONSVCBPresentation(`1 . key9=4\ 3 key10`)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Params) != 2 || string(parsed.Params[0].Value) != "4 3" || len(parsed.Params[1].Value) != 0 {
		t.Fatalf("params = %#v", parsed.Params)
	}
}

func TestParseSVCBRDataRejectsReservedParameterKey(t *testing.T) {
	_, err := ParseSVCBRData(svcbRData(1, nil, svcbParam(^uint16(0), nil)))
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error = %v, want reserved-key error", err)
	}
}

func TestParseSVCBRDataAcceptsFramedECHConfigList(t *testing.T) {
	contents := []byte{
		0,       // config ID
		0, 0x20, // KEM ID
		0, 1, 7, // public key
		0, 4, 0, 1, 0, 1, // cipher suites
		0,      // maximum name length
		1, 'x', // public name
		0, 0, // extensions
	}
	value := make([]byte, 6+len(contents))
	binary.BigEndian.PutUint16(value, uint16(len(value)-2))
	binary.BigEndian.PutUint16(value[2:], 0xfe0d)
	binary.BigEndian.PutUint16(value[4:], uint16(len(contents)))
	copy(value[6:], contents)
	raw := svcbRData(1, nil, svcbParam(svcParamECH, value))
	parsed, err := ParseSVCBRData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.ECH) != string(value) {
		t.Fatalf("ECH value was not preserved")
	}
}
