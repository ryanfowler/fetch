package dnsinspect

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
)

func recordFromWire(res resolver.Record) (record, bool) {
	return semanticRecord(res, "", res.TTLPresent), true
}

func recordFromDOH(answer resolver.DOHRecord) (record, bool) {
	rec := semanticRecord(answer.Record, answer.Data, answer.TTLPresent)
	return rec, rec.hasSemanticData()
}

func (rec record) hasSemanticData() bool {
	switch rec.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		return len(rec.address) > 0
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		return rec.target != ""
	case dnsmessage.TypeTXT:
		return rec.txt != nil
	case dnsmessage.TypeMX, dnsmessage.TypeSRV:
		return rec.target != ""
	case dnsmessage.TypeSOA:
		return rec.target != "" && rec.target2 != ""
	case dnsTypeCAA:
		return len(rec.rawRData) >= 2
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		return rec.target != ""
	default:
		return rec.presentation != "" || rec.rawRData != nil
	}
}

func semanticRecord(res resolver.Record, presentation string, ttlPresent bool) record {
	rec := record{
		owner:        normalizeOwnerPresentation(res.Owner.String()),
		typ:          dnsmessage.Type(res.Type),
		ttl:          res.TTL,
		hasTTL:       ttlPresent,
		source:       recordSourceDNS,
		preference:   res.Preference,
		priority:     res.Priority,
		weight:       res.Weight,
		port:         res.Port,
		soa:          res.SOAValues,
		rawRData:     append([]byte(nil), res.RData...),
		presentation: presentation,
	}
	if ip := resolver.RecordAddress(res); ip != nil {
		rec.address = append(net.IP(nil), ip...)
	}
	if res.Target != nil {
		rec.target = res.Target.String()
	}
	if res.Target2 != nil {
		rec.target2 = res.Target2.String()
	}
	for _, chunk := range res.TXT {
		rec.txt = append(rec.txt, append([]byte(nil), chunk...))
	}
	for _, param := range res.Params {
		rec.params = append(rec.params, resolver.SVCParam{Key: param.Key, Value: append([]byte(nil), param.Value...)})
	}
	populateRecordData(&rec)
	rec.target = strings.ToLower(rec.target)
	rec.target2 = strings.ToLower(rec.target2)
	return rec
}

func populateRecordData(rec *record) {
	if len(rec.rawRData) > 0 {
		populateRecordFromRaw(rec)
	}
	if rec.presentation == "" {
		return
	}
	if _, generic := parseGenericRDATA(rec.presentation); generic {
		return
	}
	populateRecordFromPresentation(rec)
}

func populateRecordFromRaw(rec *record) {
	raw := rec.rawRData
	switch rec.typ {
	case dnsmessage.TypeNS:
		if target, end, ok := unpackDNSName(raw, 0); ok && end == len(raw) {
			rec.target = target
		}
	case dnsmessage.TypeMX:
		if len(raw) >= 3 {
			if target, end, ok := unpackDNSName(raw, 2); ok && end == len(raw) {
				rec.preference = binary.BigEndian.Uint16(raw)
				rec.target = target
			}
		}
	case dnsmessage.TypeSOA:
		if first, off, ok := unpackDNSName(raw, 0); ok {
			if second, off2, ok := unpackDNSName(raw, off); ok && len(raw)-off2 == 20 {
				rec.target, rec.target2 = first, second
				for i := range rec.soa {
					rec.soa[i] = binary.BigEndian.Uint32(raw[off2+i*4:])
				}
			}
		}
	case dnsmessage.TypeTXT:
		var chunks [][]byte
		for off := 0; off < len(raw); {
			length := int(raw[off])
			off++
			if length > len(raw)-off {
				return
			}
			chunks = append(chunks, append([]byte(nil), raw[off:off+length]...))
			off += length
		}
		rec.txt = chunks
	case dnsmessage.TypeSRV:
		if len(raw) >= 7 {
			if target, end, ok := unpackDNSName(raw, 6); ok && end == len(raw) {
				rec.priority = binary.BigEndian.Uint16(raw)
				rec.weight = binary.BigEndian.Uint16(raw[2:])
				rec.port = binary.BigEndian.Uint16(raw[4:])
				rec.target = target
			}
		}
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		// DoH JSON and wire responses normally provide Params directly. Parse
		// raw RDATA as well so records from generic fixtures remain semantic
		// and malformed values can still be shown safely by the renderer.
		priority, target, params, ok := parseRawSVCB(rec.rawRData)
		rec.malformedRData = !ok
		if target != "" {
			rec.priority = priority
			rec.target = target
		}
		if len(params) > 0 {
			rec.params = params
		}
	}
}

func populateRecordFromPresentation(rec *record) {
	fields := strings.Fields(rec.presentation)
	parseUint16 := func(value string) (uint16, bool) {
		parsed, err := strconv.ParseUint(value, 10, 16)
		return uint16(parsed), err == nil
	}
	parseUint32 := func(value string) (uint32, bool) {
		parsed, err := strconv.ParseUint(value, 10, 32)
		return uint32(parsed), err == nil
	}
	name := func(value string) (string, bool) {
		parsed, err := resolver.ParseName(value)
		if err != nil {
			return "", false
		}
		return parsed.String(), true
	}

	switch rec.typ {
	case dnsmessage.TypeNS:
		if len(fields) == 1 {
			rec.target, _ = name(fields[0])
		}
	case dnsmessage.TypeTXT:
		if chunks, ok := parseDNSCharacterStrings(rec.presentation); ok {
			rec.txt = chunks
		} else {
			// Some JSON resolvers omit the presentation quotes for a single
			// TXT character-string. Preserve that response as one chunk.
			rec.txt = [][]byte{[]byte(rec.presentation)}
		}
	case dnsmessage.TypeMX:
		if len(fields) == 2 {
			preference, numberOK := parseUint16(fields[0])
			target, nameOK := name(fields[1])
			if numberOK && nameOK {
				rec.preference, rec.target = preference, target
			}
		}
	case dnsmessage.TypeSOA:
		if len(fields) == 7 {
			primary, primaryOK := name(fields[0])
			mailbox, mailboxOK := name(fields[1])
			values := [5]uint32{}
			valuesOK := true
			for i := range values {
				values[i], valuesOK = parseUint32(fields[i+2])
				if !valuesOK {
					break
				}
			}
			if primaryOK && mailboxOK && valuesOK {
				rec.target, rec.target2, rec.soa = primary, mailbox, values
			}
		}
	case dnsmessage.TypeSRV:
		if len(fields) == 4 {
			priority, priorityOK := parseUint16(fields[0])
			weight, weightOK := parseUint16(fields[1])
			port, portOK := parseUint16(fields[2])
			target, targetOK := name(fields[3])
			if priorityOK && weightOK && portOK && targetOK {
				rec.priority, rec.weight, rec.port, rec.target = priority, weight, port, target
			}
		}
	case dnsTypeCAA:
		flagsText, rest, flagsFieldOK := cutDNSField(rec.presentation)
		tag, valueText, tagFieldOK := cutDNSField(rest)
		flags, flagsOK := parseUint16(flagsText)
		if flagsFieldOK && tagFieldOK && flagsOK && flags <= 255 && len(tag) <= 255 {
			if values, ok := parseDNSCharacterStrings(valueText); ok && len(values) == 1 {
				rec.rawRData = append([]byte{byte(flags), byte(len(tag))}, []byte(tag)...)
				rec.rawRData = append(rec.rawRData, values[0]...)
			}
		}
	}
}

func cutDNSField(text string) (field, rest string, ok bool) {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return "", "", false
	}
	end := strings.IndexAny(text, " \t")
	if end < 0 {
		return text, "", true
	}
	return text[:end], strings.TrimLeft(text[end:], " \t"), true
}

func parseDNSCharacterStrings(text string) ([][]byte, bool) {
	var out [][]byte
	for offset := 0; ; {
		for offset < len(text) && (text[offset] == ' ' || text[offset] == '\t') {
			offset++
		}
		if offset == len(text) {
			return out, len(out) > 0
		}
		if text[offset] != '"' {
			return nil, false
		}
		offset++
		var value []byte
		closed := false
		for offset < len(text) {
			if text[offset] == '"' {
				offset++
				closed = true
				break
			}
			if text[offset] != '\\' {
				value = append(value, text[offset])
				offset++
				continue
			}
			offset++
			if offset == len(text) {
				return nil, false
			}
			if offset+3 <= len(text) && text[offset] >= '0' && text[offset] <= '9' && text[offset+1] >= '0' && text[offset+1] <= '9' && text[offset+2] >= '0' && text[offset+2] <= '9' {
				octet, err := strconv.ParseUint(text[offset:offset+3], 10, 8)
				if err != nil {
					return nil, false
				}
				value = append(value, byte(octet))
				offset += 3
				continue
			}
			value = append(value, text[offset])
			offset++
		}
		if !closed || len(value) > 255 {
			return nil, false
		}
		out = append(out, value)
	}
}

func (rec record) semanticKey() string {
	var b strings.Builder
	switch rec.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		fmt.Fprintf(&b, "%x", []byte(rec.address))
		if rec.zone != "" {
			b.WriteByte('%')
			b.WriteString(rec.zone)
		}
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		if rec.target == "" && rec.presentation != "" {
			return rec.presentation
		}
		b.WriteString(strings.ToLower(rec.target))
	case dnsmessage.TypeTXT:
		if rec.txt == nil && rec.presentation != "" {
			return rec.presentation
		}
		for _, chunk := range rec.txt {
			fmt.Fprintf(&b, "%d:%x,", len(chunk), chunk)
		}
	case dnsmessage.TypeMX:
		if rec.target == "" && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%d|%s", rec.preference, strings.ToLower(rec.target))
	case dnsmessage.TypeSOA:
		if (rec.target == "" || rec.target2 == "") && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%s|%s|", strings.ToLower(rec.target), strings.ToLower(rec.target2))
		for _, value := range rec.soa {
			fmt.Fprintf(&b, "%d,", value)
		}
	case dnsmessage.TypeSRV:
		if rec.target == "" && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%d|%d|%d|%s", rec.priority, rec.weight, rec.port, strings.ToLower(rec.target))
	case dnsTypeCAA:
		if len(rec.rawRData) == 0 && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%x", rec.rawRData)
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		fmt.Fprintf(&b, "%d|%s|", rec.priority, strings.ToLower(rec.target))
		for _, param := range canonicalSVCParams(rec.params) {
			fmt.Fprintf(&b, "%d:%d:%x,", param.Key, len(param.Value), param.Value)
		}
		if rec.malformedRData {
			fmt.Fprintf(&b, "malformed:%x", rec.rawRData)
		}
	default:
		fmt.Fprintf(&b, "%x", rec.rawRData)
	}
	if b.Len() == 0 {
		b.WriteString(rec.presentation)
	}
	return b.String()
}

func canonicalSVCParams(params []resolver.SVCParam) []resolver.SVCParam {
	params = slices.Clone(params)
	slices.SortFunc(params, func(a, b resolver.SVCParam) int {
		if order := cmp.Compare(a.Key, b.Key); order != 0 {
			return order
		}
		return bytes.Compare(a.Value, b.Value)
	})
	return params
}

func normalizedOwner(host string) string {
	if queryHost, err := dnsQueryHost(host); err == nil {
		return normalizeOwnerPresentation(queryHost)
	}
	return normalizeOwnerPresentation(host)
}

func normalizeOwnerPresentation(owner string) string {
	return strings.ToLower(absoluteName(owner))
}

func safeRecordText(text string) string {
	for _, r := range text {
		if r == '\n' || r == '\t' || r == '\r' || r == '\\' || r == '"' || r < 0x20 || r >= 0x7f && r <= 0x9f {
			return strconv.Quote(text)
		}
	}
	return text
}

func formatCAA(raw []byte) string {
	flags, tag, value, ok := caaFields(raw)
	if !ok {
		return "0x" + hex.EncodeToString(raw)
	}
	return fmt.Sprintf("%d %s %q", flags, safeRecordText(tag), value)
}

func formatSVCBValue(priority uint16, target string, params []dnsmessage.SVCParam) string {
	parts := []string{fmt.Sprintf("%d", priority), target}
	for _, param := range params {
		parts = append(parts, formatSVCParam(param))
	}
	return strings.Join(parts, " ")
}

func svcParamRenderOrder(key uint16) int {
	// This order follows the diagnostic fields rather than the wire key order:
	// address hints stay together and ECH remains easy to find after them.
	switch key {
	case uint16(dnsmessage.SVCParamMandatory):
		return 0
	case uint16(dnsmessage.SVCParamALPN):
		return 1
	case uint16(dnsmessage.SVCParamNoDefaultALPN):
		return 2
	case uint16(dnsmessage.SVCParamPort):
		return 3
	case uint16(dnsmessage.SVCParamIPv4Hint):
		return 4
	case uint16(dnsmessage.SVCParamIPv6Hint):
		return 5
	case uint16(dnsmessage.SVCParamECH):
		return 6
	case uint16(dnsmessage.SVCParamDOHPath):
		return 7
	case uint16(dnsmessage.SVCParamOHTTP):
		return 8
	case uint16(dnsmessage.SVCParamTLSSupportedGroups):
		return 9
	default:
		return 10
	}
}

func formatStructuredSVCParam(param resolver.SVCParam) (label, value string) {
	switch dnsmessage.SVCParamKey(param.Key) {
	case dnsmessage.SVCParamMandatory:
		return "Mandatory", formatSVCBKeyList(param.Value)
	case dnsmessage.SVCParamALPN:
		if value, ok := formatSVCBALPN(param.Value); ok {
			return "ALPN", value
		}
		return "ALPN", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamNoDefaultALPN:
		if len(param.Value) == 0 {
			return "No default ALPN", "true"
		}
		return "No default ALPN", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamPort:
		if len(param.Value) == 2 {
			return "Port", strconv.Itoa(int(binary.BigEndian.Uint16(param.Value)))
		}
		return "Port", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamIPv4Hint:
		if value, ok := formatSVCBHints(param.Value, 4); ok {
			return "IPv4 hints", value
		}
		return "IPv4 hints", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamIPv6Hint:
		if value, ok := formatSVCBHints(param.Value, 16); ok {
			return "IPv6 hints", value
		}
		return "IPv6 hints", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamECH:
		// ECH is already an opaque, length-prefixed binary value. Preserve its
		// complete base64 representation; do not expose only a preview.
		return "ECH", base64.StdEncoding.EncodeToString(param.Value)
	case dnsmessage.SVCParamDOHPath:
		return "DoH path", string(param.Value)
	case dnsmessage.SVCParamOHTTP:
		if len(param.Value) == 0 {
			return "OHTTP", "true"
		}
		return "OHTTP", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamTLSSupportedGroups:
		if value, ok := formatSVCBUint16List(param.Value); ok {
			return "TLS supported groups", value
		}
		return "TLS supported groups", formatSVCBBytes(param.Value)
	default:
		return formatSVCBParamName(param.Key), formatSVCBBytes(param.Value)
	}
}

func formatSVCBParamName(key uint16) string {
	name := dnsmessage.SVCParamKey(key).String()
	// x/net prints unknown SvcParam keys as bare numbers. The key prefix makes
	// those values unambiguous and matches DNS presentation terminology.
	if _, err := strconv.ParseUint(name, 10, 16); err == nil {
		return "key" + name
	}
	return name
}

func formatSVCBBytes(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func formatSVCBALPN(value []byte) (string, bool) {
	var values []string
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 || length > len(value)-offset {
			return "", false
		}
		values = append(values, string(value[offset:offset+length]))
		offset += length
	}
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

func formatSVCBUint16List(value []byte) (string, bool) {
	if len(value) == 0 || len(value)%2 != 0 {
		return "", false
	}
	values := make([]string, 0, len(value)/2)
	for offset := 0; offset < len(value); offset += 2 {
		values = append(values, strconv.Itoa(int(binary.BigEndian.Uint16(value[offset:]))))
	}
	return strings.Join(values, ", "), true
}

func formatSVCBHints(value []byte, width int) (string, bool) {
	if len(value) == 0 || len(value)%width != 0 {
		return "", false
	}
	values := make([]string, 0, len(value)/width)
	for offset := 0; offset < len(value); offset += width {
		values = append(values, net.IP(value[offset:offset+width]).String())
	}
	return strings.Join(values, ", "), true
}

func formatSVCBKeyList(value []byte) string {
	if len(value) == 0 || len(value)%2 != 0 {
		return formatSVCBBytes(value)
	}
	keys := make([]string, 0, len(value)/2)
	for offset := 0; offset < len(value); offset += 2 {
		key := binary.BigEndian.Uint16(value[offset:])
		keys = append(keys, formatSVCBKey(key))
	}
	return strings.Join(keys, ", ")
}

func formatSVCBKey(key uint16) string {
	switch dnsmessage.SVCParamKey(key) {
	case dnsmessage.SVCParamMandatory:
		return "mandatory"
	case dnsmessage.SVCParamALPN:
		return "alpn"
	case dnsmessage.SVCParamNoDefaultALPN:
		return "no-default-alpn"
	case dnsmessage.SVCParamPort:
		return "port"
	case dnsmessage.SVCParamIPv4Hint:
		return "ipv4hint"
	case dnsmessage.SVCParamECH:
		return "ech"
	case dnsmessage.SVCParamIPv6Hint:
		return "ipv6hint"
	case dnsmessage.SVCParamDOHPath:
		return "dohpath"
	case dnsmessage.SVCParamOHTTP:
		return "ohttp"
	case dnsmessage.SVCParamTLSSupportedGroups:
		return "tls-supported-groups"
	default:
		return formatSVCBParamName(key)
	}
}

// parseRawSVCB returns as much of a generic SVCB/HTTPS RDATA value as can be
// safely decoded. The final boolean reports whether the complete value is
// well-formed, which lets the renderer retain malformed data as raw hex.
func parseRawSVCB(raw []byte) (priority uint16, target string, params []resolver.SVCParam, ok bool) {
	if len(raw) < 3 {
		return 0, "", nil, false
	}

	// Use the resolver's strict parser for the validity bit. It checks more
	// than framing, including parameter ordering, duplicate keys, reserved
	// keys, and the semantics of known values. The local decode below still
	// recovers a target and any complete parameters for a useful fallback.
	if parsed, err := resolver.ParseSVCBRData(raw); err == nil {
		params = make([]resolver.SVCParam, len(parsed.Params))
		for i, param := range parsed.Params {
			params[i] = resolver.SVCParam{Key: param.Key, Value: append([]byte(nil), param.Value...)}
		}
		return parsed.Priority, parsed.Target.String(), params, true
	}

	priority = binary.BigEndian.Uint16(raw)
	var offset int
	target, offset, ok = unpackDNSName(raw, 2)
	if !ok {
		return priority, "", nil, false
	}
	for offset < len(raw) {
		if len(raw)-offset < 4 {
			return priority, target, params, false
		}
		key := binary.BigEndian.Uint16(raw[offset:])
		length := int(binary.BigEndian.Uint16(raw[offset+2:]))
		offset += 4
		if length > len(raw)-offset {
			return priority, target, params, false
		}
		params = append(params, resolver.SVCParam{Key: key, Value: append([]byte(nil), raw[offset:offset+length]...)})
		offset += length
	}
	// Reaching this point means strict semantic validation failed. Keep the
	// recovered fields for display, but make the caller retain the raw value.
	return priority, target, params, false
}

func formatSVCParam(param dnsmessage.SVCParam) string {
	switch param.Key {
	case dnsmessage.SVCParamALPN:
		var alpns []string
		for i := 0; i < len(param.Value); {
			ln := int(param.Value[i])
			i++
			if i+ln > len(param.Value) {
				return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
			}
			alpns = append(alpns, safeRecordText(string(param.Value[i:i+ln])))
			i += ln
		}
		return param.Key.String() + "=" + strings.Join(alpns, ",")
	case dnsmessage.SVCParamNoDefaultALPN:
		return param.Key.String()
	case dnsmessage.SVCParamECH:
		return "ECH=" + base64.StdEncoding.EncodeToString(param.Value)
	case dnsmessage.SVCParamPort:
		if len(param.Value) != 2 {
			return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
		}
		port := uint16(param.Value[0])<<8 | uint16(param.Value[1])
		return fmt.Sprintf("%s=%d", param.Key.String(), port)
	case dnsmessage.SVCParamIPv4Hint:
		if len(param.Value)%4 != 0 {
			return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
		}
		var ips []string
		for i := 0; i < len(param.Value); i += 4 {
			ips = append(ips, net.IP(param.Value[i:i+4]).String())
		}
		return param.Key.String() + "=" + strings.Join(ips, ",")
	case dnsmessage.SVCParamIPv6Hint:
		if len(param.Value)%16 != 0 {
			return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
		}
		var ips []string
		for i := 0; i < len(param.Value); i += 16 {
			ips = append(ips, net.IP(param.Value[i:i+16]).String())
		}
		return param.Key.String() + "=" + strings.Join(ips, ",")
	case dnsmessage.SVCParamDOHPath:
		return param.Key.String() + "=" + strconv.Quote(string(param.Value))
	default:
		return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
	}
}

func normalizeDOHValue(typ dnsmessage.Type, value string) string {
	raw, ok := parseGenericRDATA(value)
	if !ok {
		return value
	}

	switch typ {
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		if text, ok := parseSVCBRDATA(raw); ok {
			return text
		}
	case dnsTypeCAA:
		return formatCAA(raw)
	}
	return "0x" + hex.EncodeToString(raw)
}

func parseGenericRDATA(value string) ([]byte, bool) {
	fields := strings.Fields(value)
	if len(fields) < 3 || fields[0] != "\\#" {
		return nil, false
	}
	wantLen, err := strconv.Atoi(fields[1])
	if err != nil || wantLen < 0 {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.Join(fields[2:], ""))
	if err != nil || len(raw) != wantLen {
		return nil, false
	}
	return raw, true
}

func parseSVCBRDATA(raw []byte) (string, bool) {
	if len(raw) < 3 {
		return "", false
	}
	priority := uint16(raw[0])<<8 | uint16(raw[1])
	target, off, ok := unpackDNSName(raw, 2)
	if !ok {
		return "", false
	}

	var params []dnsmessage.SVCParam
	for off < len(raw) {
		if off+4 > len(raw) {
			return "", false
		}
		key := uint16(raw[off])<<8 | uint16(raw[off+1])
		ln := int(raw[off+2])<<8 | int(raw[off+3])
		off += 4
		if off+ln > len(raw) {
			return "", false
		}
		value := append([]byte(nil), raw[off:off+ln]...)
		params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamKey(key), Value: value})
		off += ln
	}
	return formatSVCBValue(priority, target, params), true
}

func unpackDNSName(raw []byte, off int) (string, int, bool) {
	var labels []string
	wireSize := 1
	for {
		if off >= len(raw) {
			return "", 0, false
		}
		ln := int(raw[off])
		off++
		if ln == 0 {
			if len(labels) == 0 {
				return ".", off, true
			}
			return strings.Join(labels, ".") + ".", off, true
		}
		if ln&0xc0 != 0 || ln > 63 || off+ln > len(raw) {
			return "", 0, false
		}
		wireSize += 1 + ln
		if wireSize > 255 {
			return "", 0, false
		}
		labels = append(labels, dnsLabelPresentation(raw[off:off+ln]))
		off += ln
	}
}

func dnsLabelPresentation(label []byte) string {
	var b strings.Builder
	for _, value := range label {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' || value >= 0x21 && value <= 0x7e && value != '.' && value != '\\' {
			b.WriteByte(value)
			continue
		}
		fmt.Fprintf(&b, "\\%03d", value)
	}
	return b.String()
}
