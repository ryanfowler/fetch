package resolver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	svcParamMandatory     uint16 = 0
	svcParamALPN          uint16 = 1
	svcParamNoDefaultALPN uint16 = 2
	svcParamPort          uint16 = 3
	svcParamIPv4Hint      uint16 = 4
	svcParamECH           uint16 = 5
	svcParamIPv6Hint      uint16 = 6
)

// SVCBRecord is the validated service-binding form of an HTTPS or SVCB
// record. Params retains unknown optional parameters so callers can preserve
// them without guessing their meaning.
type SVCBRecord struct {
	Owner                Name
	TTL                  uint32
	TTLPresent           bool
	Priority             uint16
	Target               Name
	Params               []SVCParam
	Mandatory            []uint16
	UnsupportedMandatory []uint16
	ALPN                 [][]byte
	NoDefaultALPN        bool
	Port                 uint16
	HasPort              bool
	IPv4Hints            []net.IP
	IPv6Hints            []net.IP
	ECH                  []byte
}

func (r SVCBRecord) IsAliasMode() bool { return r.Priority == 0 }

// IsUsable reports whether all mandatory parameters are understood by this
// implementation. An unknown optional parameter does not make a record
// unusable.
func (r SVCBRecord) IsUsable() bool { return len(r.UnsupportedMandatory) == 0 }

// AdvertisesALPN reports whether the record contains the exact protocol ID.
func (r SVCBRecord) AdvertisesALPN(protocol string) bool {
	for _, alpn := range r.ALPN {
		if string(alpn) == protocol {
			return true
		}
	}
	return false
}

// ParseSVCBRData strictly parses one uncompressed SVCB/HTTPS RDATA value.
// It returns no partially parsed record on error.
func ParseSVCBRData(raw []byte) (SVCBRecord, error) {
	if len(raw) < 3 {
		return SVCBRecord{}, errors.New("SVCB RDATA is too short")
	}
	priority := binary.BigEndian.Uint16(raw[:2])
	target, offset, err := parseSVCBName(raw, 2)
	if err != nil {
		return SVCBRecord{}, fmt.Errorf("SVCB target: %w", err)
	}
	params, err := parseSVCBParams(raw[offset:])
	if err != nil {
		return SVCBRecord{}, err
	}
	return buildSVCBRecord(priority, target, params)
}

// SortSVCBRecords returns service records in priority order. Records with the
// same priority are shuffled with randomInt, which makes production selection
// unbiased while allowing deterministic tests. If randomInt is nil, crypto/rand
// supplies the shuffle values.
func SortSVCBRecords(records []SVCBRecord, randomInt func(int) int) []SVCBRecord {
	out := append([]SVCBRecord(nil), records...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	for start := 0; start < len(out); {
		end := start + 1
		for end < len(out) && out[end].Priority == out[start].Priority {
			end++
		}
		for i := end - 1; i > start; i-- {
			bound := i - start + 1
			var index int
			if randomInt != nil {
				index = randomInt(bound)
			} else if n, err := rand.Int(rand.Reader, big.NewInt(int64(bound))); err == nil {
				index = int(n.Int64())
			} else {
				index = 0
			}
			if index < 0 || index >= bound {
				index = 0
			}
			out[start+i], out[start+index] = out[start+index], out[start+i]
		}
		start = end
	}
	return out
}

// parseJSONSVCBPresentation validates the presentation form used by DoH JSON
// answers and returns the same typed model as wire parsing. It is deliberately
// strict so a valid answer cannot hide a malformed record in the same RRset.
func parseJSONSVCBPresentation(value string) (SVCBRecord, []byte, error) {
	fields, err := splitSVCBFields(value)
	if err != nil {
		return SVCBRecord{}, nil, err
	}
	if len(fields) < 2 {
		return SVCBRecord{}, nil, errors.New("SVCB presentation has no priority or target")
	}
	priority, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return SVCBRecord{}, nil, errors.New("SVCB priority is invalid")
	}
	target, err := ParseName(fields[1])
	if err != nil {
		return SVCBRecord{}, nil, fmt.Errorf("SVCB target: %w", err)
	}
	params := make([][]byte, 0, len(fields)-2)
	for _, field := range fields[2:] {
		keyText, valueText, hasValue := strings.Cut(field, "=")
		key, ok := parseSVCBPresentationKey(keyText)
		if !ok {
			return SVCBRecord{}, nil, fmt.Errorf("SVCB parameter key %q is invalid", keyText)
		}
		if key == svcParamNoDefaultALPN && hasValue {
			return SVCBRecord{}, nil, errors.New("SVCB no-default-alpn must not have a value")
		}
		if key != svcParamNoDefaultALPN && !hasValue && isKnownSVCBPresentationKey(key) {
			return SVCBRecord{}, nil, fmt.Errorf("SVCB parameter %q has no value", keyText)
		}
		encoded, err := encodeSVCBPresentationValue(key, valueText)
		if err != nil {
			return SVCBRecord{}, nil, err
		}
		params = append(params, encodeSVCBParam(key, encoded))
	}
	raw := make([]byte, 2, 2+len(target.labels)*2+len(fields)*8)
	binary.BigEndian.PutUint16(raw, uint16(priority))
	nameWire, _ := target.Wire()
	raw = append(raw, nameWire...)
	sort.SliceStable(params, func(i, j int) bool {
		return binary.BigEndian.Uint16(params[i]) < binary.BigEndian.Uint16(params[j])
	})
	for _, param := range params {
		raw = append(raw, param...)
	}
	parsed, err := ParseSVCBRData(raw)
	if err != nil {
		return SVCBRecord{}, nil, err
	}
	return parsed, raw, nil
}

func splitSVCBFields(value string) ([]string, error) {
	var fields []string
	start := -1
	quoted := false
	escaped := false
	for i, c := range value {
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			if start < 0 {
				start = i
			}
			continue
		}
		if !quoted && (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			if start >= 0 {
				fields = append(fields, value[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if quoted || escaped {
		return nil, errors.New("SVCB presentation has an unterminated quote")
	}
	if start >= 0 {
		fields = append(fields, value[start:])
	}
	return fields, nil
}

func isKnownSVCBPresentationKey(key uint16) bool {
	return key <= svcParamIPv6Hint || key == 7
}

func parseSVCBPresentationKey(value string) (uint16, bool) {
	switch strings.ToLower(value) {
	case "mandatory":
		return svcParamMandatory, true
	case "alpn":
		return svcParamALPN, true
	case "no-default-alpn":
		return svcParamNoDefaultALPN, true
	case "port":
		return svcParamPort, true
	case "ipv4hint":
		return svcParamIPv4Hint, true
	case "ech":
		return svcParamECH, true
	case "ipv6hint":
		return svcParamIPv6Hint, true
	case "dohpath":
		return 7, true
	}
	if strings.HasPrefix(strings.ToLower(value), "key") {
		key, err := strconv.ParseUint(value[3:], 10, 16)
		return uint16(key), err == nil
	}
	return 0, false
}

func unquoteSVCBValue(value string) (string, error) {
	value, err := stripSVCBQuotes(value)
	if err != nil {
		return "", err
	}
	return decodeDNSPresentationValue(value)
}

func stripSVCBQuotes(value string) (string, error) {
	if strings.HasPrefix(value, "\"") {
		if len(value) < 2 || !strings.HasSuffix(value, "\"") {
			return "", errors.New("SVCB parameter value has an unterminated quote")
		}
		return value[1 : len(value)-1], nil
	}
	if strings.Contains(value, "\"") {
		return "", errors.New("SVCB parameter value has an invalid quote")
	}
	return value, nil
}

func decodeDNSPresentationValue(value string) (string, error) {
	var out []byte
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out = append(out, value[i])
			continue
		}
		if i+1 >= len(value) {
			return "", errors.New("SVCB parameter value has an incomplete escape")
		}
		if i+3 < len(value) && isDecimalDigit(value[i+1]) && isDecimalDigit(value[i+2]) && isDecimalDigit(value[i+3]) {
			n := int(value[i+1]-'0')*100 + int(value[i+2]-'0')*10 + int(value[i+3]-'0')
			if n > 255 {
				return "", errors.New("SVCB parameter escape is outside the octet range")
			}
			out = append(out, byte(n))
			i += 3
			continue
		}
		out = append(out, value[i+1])
		i++
	}
	return string(out), nil
}

func isDecimalDigit(value byte) bool { return value >= '0' && value <= '9' }

func splitSVCBList(value string) ([]string, error) {
	value, err := stripSVCBQuotes(value)
	if err != nil {
		return nil, err
	}
	var parts []string
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			if i+1 >= len(value) {
				return nil, errors.New("SVCB parameter value has an incomplete escape")
			}
			if i+3 < len(value) && isDecimalDigit(value[i+1]) && isDecimalDigit(value[i+2]) && isDecimalDigit(value[i+3]) {
				i += 3
			} else {
				i++
			}
			continue
		}
		if value[i] == ',' {
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	parts = append(parts, value[start:])
	return parts, nil
}

func encodeSVCBPresentationValue(key uint16, value string) ([]byte, error) {
	switch key {
	case svcParamMandatory:
		if value == "" {
			return nil, errors.New("SVCB mandatory has an empty value")
		}
		parts, err := splitSVCBList(value)
		if err != nil {
			return nil, err
		}
		keys := make([]uint16, 0, len(parts))
		for _, item := range parts {
			decoded, err := unquoteSVCBValue(item)
			if err != nil {
				return nil, err
			}
			parsed, ok := parseSVCBPresentationKey(decoded)
			if !ok {
				return nil, fmt.Errorf("SVCB mandatory key %q is invalid", item)
			}
			keys = append(keys, parsed)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var out []byte
		for _, parsed := range keys {
			var keyBytes [2]byte
			binary.BigEndian.PutUint16(keyBytes[:], parsed)
			out = append(out, keyBytes[:]...)
		}
		return out, nil
	case svcParamALPN:
		parts, err := splitSVCBList(value)
		if err != nil {
			return nil, err
		}
		var out []byte
		for _, item := range parts {
			decoded, err := unquoteSVCBValue(item)
			if err != nil {
				return nil, err
			}
			if decoded == "" || len(decoded) > 255 {
				return nil, errors.New("SVCB alpn contains an invalid protocol ID")
			}
			out = append(out, byte(len(decoded)))
			out = append(out, decoded...)
		}
		return out, nil
	case svcParamPort:
		decoded, err := unquoteSVCBValue(value)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(decoded, 10, 16)
		if err != nil {
			return nil, errors.New("SVCB port is invalid")
		}
		return []byte{byte(port >> 8), byte(port)}, nil
	case svcParamIPv4Hint:
		decoded, err := unquoteSVCBValue(value)
		if err != nil {
			return nil, err
		}
		return encodeSVCBHints(decoded, false)
	case svcParamIPv6Hint:
		decoded, err := unquoteSVCBValue(value)
		if err != nil {
			return nil, err
		}
		return encodeSVCBHints(decoded, true)
	case svcParamECH:
		decodedValue, err := unquoteSVCBValue(value)
		if err != nil {
			return nil, err
		}
		decoded, err := base64.StdEncoding.DecodeString(decodedValue)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(decodedValue)
		}
		if err != nil {
			return nil, errors.New("SVCB ech is not valid base64")
		}
		return decoded, nil
	default:
		decoded, err := unquoteSVCBValue(value)
		if err != nil {
			return nil, err
		}
		return []byte(decoded), nil
	}
}

func encodeSVCBHints(value string, ipv6 bool) ([]byte, error) {
	if value == "" {
		return nil, errors.New("SVCB address hint has an empty value")
	}
	var out []byte
	for _, item := range strings.Split(value, ",") {
		ip := net.ParseIP(item)
		if (!ipv6 && ip == nil) || (!ipv6 && ip.To4() == nil) || (ipv6 && (ip == nil || ip.To16() == nil || ip.To4() != nil)) {
			return nil, errors.New("SVCB address hint contains an invalid address")
		}
		if ipv6 {
			out = append(out, ip.To16()...)
		} else {
			out = append(out, ip.To4()...)
		}
	}
	return out, nil
}

// ParseSVCBRRSet validates every record in an HTTPS or SVCB RRset before
// returning any of them. A single malformed record rejects the whole set.
func ParseSVCBRRSet(records []Record) ([]SVCBRecord, error) {
	if len(records) == 0 {
		return []SVCBRecord{}, nil
	}
	firstType := records[0].Type
	if firstType != dnsTypeSVCB && firstType != dnsTypeHTTPS {
		return nil, fmt.Errorf("record type %d is not SVCB or HTTPS", firstType)
	}
	firstOwner := records[0].Owner
	firstClass := records[0].Class
	parsed := make([]SVCBRecord, 0, len(records))
	for i, record := range records {
		if record.Type != firstType {
			return nil, fmt.Errorf("SVCB RRset mixes record types at record %d", i)
		}
		if record.Class != firstClass || !record.Owner.Equal(firstOwner) {
			return nil, fmt.Errorf("SVCB RRset contains a record with a different owner or class at record %d", i)
		}
		value, err := parseSVCBRecord(record)
		if err != nil {
			return nil, fmt.Errorf("malformed SVCB RRset record %d: %w", i, err)
		}
		parsed = append(parsed, value)
	}
	return parsed, nil
}

// ValidateSVCBRRSet rejects an HTTPS/SVCB RRset atomically without exposing a
// partially validated result.
func ValidateSVCBRRSet(records []Record) error {
	_, err := ParseSVCBRRSet(records)
	return err
}

func parseSVCBRecord(record Record) (SVCBRecord, error) {
	if record.Type != dnsTypeSVCB && record.Type != dnsTypeHTTPS {
		return SVCBRecord{}, fmt.Errorf("record type %d is not SVCB or HTTPS", record.Type)
	}
	var parsed SVCBRecord
	var err error
	if record.Target == nil {
		parsed, err = ParseSVCBRData(record.RData)
	} else {
		parsed, err = buildSVCBRecord(record.Priority, *record.Target, record.Params)
	}
	if err != nil {
		return SVCBRecord{}, err
	}
	parsed.Owner = record.Owner
	parsed.TTL = record.TTL
	parsed.TTLPresent = record.TTLPresent
	return parsed, nil
}

func parseSVCBParams(raw []byte) ([]SVCParam, error) {
	params := make([]SVCParam, 0, 4)
	var previous uint16
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < 4 {
			return nil, fmt.Errorf("SVCB parameter header at offset %d is truncated", offset)
		}
		key := binary.BigEndian.Uint16(raw[offset:])
		if key == ^uint16(0) {
			return nil, errors.New("SVCB parameter key 65535 is reserved")
		}
		length := int(binary.BigEndian.Uint16(raw[offset+2:]))
		offset += 4
		if length > len(raw)-offset {
			return nil, fmt.Errorf("SVCB parameter key %d declares %d bytes but only %d remain", key, length, len(raw)-offset)
		}
		if len(params) > 0 && key <= previous {
			if key == previous {
				return nil, fmt.Errorf("SVCB parameter key %d is repeated", key)
			}
			return nil, fmt.Errorf("SVCB parameter key %d is not greater than preceding key %d", key, previous)
		}
		params = append(params, SVCParam{Key: key, Value: append([]byte(nil), raw[offset:offset+length]...)})
		previous = key
		offset += length
	}
	return params, nil
}

func buildSVCBRecord(priority uint16, target Name, params []SVCParam) (SVCBRecord, error) {
	if err := target.validate(); err != nil {
		return SVCBRecord{}, fmt.Errorf("invalid SVCB target: %w", err)
	}
	if priority == 0 && len(params) != 0 {
		return SVCBRecord{}, errors.New("SVCB AliasMode must not contain service parameters")
	}
	record := SVCBRecord{
		Priority: priority,
		Target:   target,
		Params:   cloneSVCBParams(params),
	}
	if priority == 0 {
		return record, nil
	}

	present := make(map[uint16]struct{}, len(params))
	for _, param := range params {
		present[param.Key] = struct{}{}
		switch param.Key {
		case svcParamMandatory:
			mandatory, err := parseMandatory(param.Value)
			if err != nil {
				return SVCBRecord{}, err
			}
			record.Mandatory = mandatory
		case svcParamALPN:
			alpn, err := parseALPN(param.Value)
			if err != nil {
				return SVCBRecord{}, err
			}
			record.ALPN = alpn
		case svcParamNoDefaultALPN:
			if len(param.Value) != 0 {
				return SVCBRecord{}, errors.New("SVCB no-default-alpn must have an empty value")
			}
			record.NoDefaultALPN = true
		case svcParamPort:
			if len(param.Value) != 2 {
				return SVCBRecord{}, fmt.Errorf("SVCB port value length is %d, not 2", len(param.Value))
			}
			record.Port = binary.BigEndian.Uint16(param.Value)
			record.HasPort = true
		case svcParamIPv4Hint:
			if len(param.Value) == 0 || len(param.Value)%4 != 0 {
				return SVCBRecord{}, fmt.Errorf("SVCB ipv4hint value length %d is not a nonzero multiple of 4", len(param.Value))
			}
			for offset := 0; offset < len(param.Value); offset += 4 {
				record.IPv4Hints = append(record.IPv4Hints, net.IP(append([]byte(nil), param.Value[offset:offset+4]...)))
			}
		case svcParamECH:
			if err := validateECHConfigList(param.Value); err != nil {
				return SVCBRecord{}, err
			}
			record.ECH = append([]byte(nil), param.Value...)
		case svcParamIPv6Hint:
			if len(param.Value) == 0 || len(param.Value)%16 != 0 {
				return SVCBRecord{}, fmt.Errorf("SVCB ipv6hint value length %d is not a nonzero multiple of 16", len(param.Value))
			}
			for offset := 0; offset < len(param.Value); offset += 16 {
				record.IPv6Hints = append(record.IPv6Hints, net.IP(append([]byte(nil), param.Value[offset:offset+16]...)))
			}
		}
	}
	if record.NoDefaultALPN && len(record.ALPN) == 0 {
		return SVCBRecord{}, errors.New("SVCB no-default-alpn is present without alpn")
	}
	for _, key := range record.Mandatory {
		if _, ok := present[key]; !ok {
			return SVCBRecord{}, fmt.Errorf("SVCB mandatory lists absent parameter key %d", key)
		}
		if !isSupportedSVCBMandatory(key) {
			record.UnsupportedMandatory = append(record.UnsupportedMandatory, key)
		}
	}
	return record, nil
}

func encodeSVCBParam(key uint16, value []byte) []byte {
	out := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(out, key)
	binary.BigEndian.PutUint16(out[2:], uint16(len(value)))
	return append(out, value...)
}

func cloneSVCBParams(params []SVCParam) []SVCParam {
	out := make([]SVCParam, len(params))
	for i, param := range params {
		out[i] = SVCParam{Key: param.Key, Value: append([]byte(nil), param.Value...)}
	}
	return out
}

func isSupportedSVCBMandatory(key uint16) bool {
	switch key {
	case svcParamALPN, svcParamNoDefaultALPN, svcParamPort, svcParamIPv4Hint, svcParamECH, svcParamIPv6Hint:
		return true
	default:
		return false
	}
}

func parseMandatory(value []byte) ([]uint16, error) {
	if len(value) == 0 || len(value)%2 != 0 {
		return nil, fmt.Errorf("SVCB mandatory value length %d is not a nonzero multiple of 2", len(value))
	}
	keys := make([]uint16, 0, len(value)/2)
	for offset := 0; offset < len(value); offset += 2 {
		key := binary.BigEndian.Uint16(value[offset:])
		if key == svcParamMandatory {
			return nil, errors.New("SVCB mandatory lists key 0")
		}
		if len(keys) > 0 && key <= keys[len(keys)-1] {
			if key == keys[len(keys)-1] {
				return nil, fmt.Errorf("SVCB mandatory key %d is repeated", key)
			}
			return nil, fmt.Errorf("SVCB mandatory key %d is not greater than preceding key %d", key, keys[len(keys)-1])
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func parseALPN(value []byte) ([][]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("SVCB alpn has an empty value")
	}
	var out [][]byte
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 {
			return nil, errors.New("SVCB alpn contains an empty protocol ID")
		}
		if length > len(value)-offset {
			return nil, fmt.Errorf("SVCB alpn protocol ID declares %d bytes but only %d remain", length, len(value)-offset)
		}
		out = append(out, append([]byte(nil), value[offset:offset+length]...))
		offset += length
	}
	return out, nil
}

func validateSVCBTargetEncoding(packet []byte, offset, end int) error {
	if offset < 0 || offset >= end || end > len(packet) {
		return errors.New("SVCB target name is truncated")
	}
	for {
		if offset >= end {
			return errors.New("SVCB target name is truncated")
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			return nil
		}
		if length&0xc0 != 0 {
			return errors.New("SVCB target name must not use compression")
		}
		if length > maxDNSLabelBytes || length > end-offset {
			return errors.New("SVCB target label exceeds RDATA bounds")
		}
		offset += length
	}
}

func parseSVCBName(raw []byte, offset int) (Name, int, error) {
	if offset < 0 || offset >= len(raw) {
		return Name{}, 0, errors.New("name is truncated")
	}
	labels := make([][]byte, 0, 4)
	wireSize := 1
	for {
		if offset >= len(raw) {
			return Name{}, 0, errors.New("name is truncated")
		}
		length := int(raw[offset])
		offset++
		if length == 0 {
			name := Name{labels: labels}
			if err := name.validate(); err != nil {
				return Name{}, 0, err
			}
			return name, offset, nil
		}
		if length&0xc0 != 0 {
			return Name{}, 0, errors.New("name contains a compression pointer")
		}
		if length > maxDNSLabelBytes || length > len(raw)-offset {
			return Name{}, 0, errors.New("name label exceeds RDATA bounds")
		}
		wireSize += 1 + length
		if wireSize > maxDNSNameBytes {
			return Name{}, 0, errors.New("name exceeds 255 octets")
		}
		labels = append(labels, append([]byte(nil), raw[offset:offset+length]...))
		offset += length
	}
}

func validateECHConfigList(value []byte) error {
	if len(value) < 2 {
		return fmt.Errorf("SVCB ech ECHConfigList is shorter than its length prefix")
	}
	declared := int(binary.BigEndian.Uint16(value[:2]))
	actual := len(value) - 2
	if declared != actual {
		return fmt.Errorf("SVCB ech ECHConfigList declares %d bytes but contains %d", declared, actual)
	}
	if declared == 0 {
		return errors.New("SVCB ech ECHConfigList is empty")
	}
	for offset := 2; offset < len(value); {
		if len(value)-offset < 4 {
			return fmt.Errorf("SVCB ech ECHConfig header at offset %d is truncated", offset-2)
		}
		version := binary.BigEndian.Uint16(value[offset:])
		length := int(binary.BigEndian.Uint16(value[offset+2:]))
		offset += 4
		if length > len(value)-offset {
			return fmt.Errorf("SVCB ech ECHConfig at offset %d is truncated", offset-6)
		}
		if version == 0xfe0d {
			if err := validateECHConfigContents(value[offset : offset+length]); err != nil {
				return fmt.Errorf("SVCB ech ECHConfigContents is malformed: %w", err)
			}
		}
		offset += length
	}
	return nil
}

func validateECHConfigContents(value []byte) error {
	offset := 0
	if err := takeECH(value, &offset, 1, "missing config_id"); err != nil {
		return err
	}
	if err := takeECH(value, &offset, 2, "missing kem_id"); err != nil {
		return err
	}
	publicKeyLength, err := readECHUint16(value, &offset, "missing public_key length")
	if err != nil {
		return err
	}
	if publicKeyLength == 0 {
		return errors.New("public_key is empty")
	}
	if err := takeECH(value, &offset, publicKeyLength, "truncated public_key"); err != nil {
		return err
	}
	suitesLength, err := readECHUint16(value, &offset, "missing cipher suite list length")
	if err != nil {
		return err
	}
	if suitesLength == 0 || suitesLength%4 != 0 {
		return errors.New("cipher suite list length is not a nonzero multiple of 4")
	}
	if err := takeECH(value, &offset, suitesLength, "truncated cipher suite list"); err != nil {
		return err
	}
	if err := takeECH(value, &offset, 1, "missing maximum_name_length"); err != nil {
		return err
	}
	if offset >= len(value) {
		return errors.New("missing public_name length")
	}
	publicNameLength := int(value[offset])
	offset++
	if publicNameLength == 0 {
		return errors.New("public_name is empty")
	}
	if err := takeECH(value, &offset, publicNameLength, "truncated public_name"); err != nil {
		return err
	}
	extensionsLength, err := readECHUint16(value, &offset, "missing extensions length")
	if err != nil {
		return err
	}
	extensionsStart := offset
	if err := takeECH(value, &offset, extensionsLength, "truncated extensions"); err != nil {
		return err
	}
	for extensionOffset := extensionsStart; extensionOffset < offset; {
		if err := takeECH(value[:offset], &extensionOffset, 2, "truncated extension type"); err != nil {
			return err
		}
		length, err := readECHUint16(value[:offset], &extensionOffset, "truncated extension length")
		if err != nil {
			return err
		}
		if err := takeECH(value[:offset], &extensionOffset, length, "truncated extension data"); err != nil {
			return err
		}
	}
	if offset != len(value) {
		return errors.New("trailing bytes after extensions")
	}
	return nil
}

func readECHUint16(value []byte, offset *int, reason string) (int, error) {
	if err := takeECH(value, offset, 2, reason); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(value[*offset-2:])), nil
}

func takeECH(value []byte, offset *int, length int, reason string) error {
	if length < 0 || *offset > len(value)-length {
		return errors.New(reason)
	}
	*offset += length
	return nil
}
