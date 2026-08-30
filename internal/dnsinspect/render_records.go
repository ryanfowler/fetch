package dnsinspect

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
)

// renderValue is the only place that turns semantic record data into terminal
// presentation. DoH JSON text is used only when that protocol did not provide
// parsed fields or generic wire-format RDATA.
func (rec record) renderValue() string {
	fallback := func() string {
		if rec.presentation != "" {
			return safeRecordText(normalizeDOHValue(rec.typ, rec.presentation))
		}
		return "0x" + hex.EncodeToString(rec.rawRData)
	}

	switch rec.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if len(rec.address) > 0 {
			return (&net.IPAddr{IP: rec.address, Zone: rec.zone}).String()
		}
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		if rec.target != "" {
			return rec.target
		}
	case dnsmessage.TypeTXT:
		if len(rec.txt) == 1 {
			return formatTXTChunk(rec.txt[0])
		}
	case dnsmessage.TypeMX:
		if rec.target != "" {
			return fmt.Sprintf("%d %s", rec.preference, rec.target)
		}
	case dnsmessage.TypeSOA:
		if rec.target != "" && rec.target2 != "" {
			return fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d minttl=%d", rec.target, rec.target2, rec.soa[0], rec.soa[1], rec.soa[2], rec.soa[3], rec.soa[4])
		}
	case dnsmessage.TypeSRV:
		if rec.target != "" {
			return fmt.Sprintf("%d %d %d %s", rec.priority, rec.weight, rec.port, rec.target)
		}
	case dnsTypeCAA:
		if len(rec.rawRData) > 0 {
			return formatCAA(rec.rawRData)
		}
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		if rec.target != "" {
			params := make([]dnsmessage.SVCParam, 0, len(rec.params))
			for _, param := range rec.params {
				params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamKey(param.Key), Value: param.Value})
			}
			return formatSVCBValue(rec.priority, rec.target, params)
		}
	}
	return fallback()
}

func countPhrase(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func queryCountPhrase(count int, label string) string {
	return fmt.Sprintf("%d %s", count, label)
}

func recordTypeCount(res *result) int {
	count := 0
	for _, records := range res.records {
		if len(records) > 0 {
			count++
		}
	}
	return count
}

func renderOtherSections(p *core.Printer, records map[string][]record) {
	known := make(map[string]bool, len(inspectTypes))
	for _, qt := range inspectTypes {
		known[qt.label] = true
	}
	var types []string
	for typ := range records {
		if known[typ] {
			continue
		}
		types = append(types, typ)
	}
	slices.SortFunc(types, func(a, b string) int {
		aRecords, bRecords := records[a], records[b]
		if len(aRecords) > 0 && len(bRecords) > 0 {
			if order := cmp.Compare(aRecords[0].typ, bRecords[0].typ); order != 0 {
				return order
			}
		}
		return strings.Compare(a, b)
	})
	for _, typ := range types {
		renderSection(p, typ, records[typ])
	}
}

func compareRecords(a, b record) int {
	text := func(left, right string) int {
		return strings.Compare(strings.ToLower(left), strings.ToLower(right))
	}
	if a.typ != b.typ {
		return cmp.Compare(a.typ, b.typ)
	}

	switch a.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if order := bytes.Compare(canonicalAddressBytes(a), canonicalAddressBytes(b)); order != 0 {
			return order
		}
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		if order := text(a.target, b.target); order != 0 {
			return order
		}
	case dnsmessage.TypeTXT:
		for i := 0; i < min(len(a.txt), len(b.txt)); i++ {
			if order := bytes.Compare(a.txt[i], b.txt[i]); order != 0 {
				return order
			}
		}
		if order := cmp.Compare(len(a.txt), len(b.txt)); order != 0 {
			return order
		}
	case dnsmessage.TypeMX:
		if order := cmp.Compare(a.preference, b.preference); order != 0 {
			return order
		}
		if order := text(a.target, b.target); order != 0 {
			return order
		}
	case dnsmessage.TypeSOA:
		if order := text(a.owner, b.owner); order != 0 {
			return order
		}
	case dnsmessage.TypeSRV:
		for _, order := range []int{
			cmp.Compare(a.priority, b.priority),
			cmp.Compare(a.weight, b.weight),
			cmp.Compare(a.port, b.port),
			text(a.target, b.target),
		} {
			if order != 0 {
				return order
			}
		}
	case dnsTypeCAA:
		aFlags, aTag, aValue := caaSortFields(a.rawRData)
		bFlags, bTag, bValue := caaSortFields(b.rawRData)
		for _, order := range []int{text(aTag, bTag), cmp.Compare(aFlags, bFlags), bytes.Compare(aValue, bValue)} {
			if order != 0 {
				return order
			}
		}
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		if order := cmp.Compare(a.priority, b.priority); order != 0 {
			return order
		}
		if order := text(a.target, b.target); order != 0 {
			return order
		}
	default:
		if order := bytes.Compare(a.rawRData, b.rawRData); order != 0 {
			return order
		}
	}
	for _, order := range []int{
		strings.Compare(a.semanticKey(), b.semanticKey()),
		text(a.owner, b.owner),
		cmp.Compare(a.source, b.source),
		compareBool(a.hasTTL, b.hasTTL),
		cmp.Compare(a.ttl, b.ttl),
		strings.Compare(a.presentation, b.presentation),
	} {
		if order != 0 {
			return order
		}
	}
	return 0
}

func compareBool(a, b bool) int {
	if a == b {
		return 0
	}
	if !a {
		return -1
	}
	return 1
}

func canonicalAddressBytes(rec record) []byte {
	ip := net.IP(rec.address)
	if rec.typ == dnsmessage.TypeA {
		return ip.To4()
	}
	return ip.To16()
}

func caaSortFields(raw []byte) (uint8, string, []byte) {
	if len(raw) < 2 || int(raw[1]) > len(raw)-2 {
		return 0, "", raw
	}
	tagEnd := 2 + int(raw[1])
	return raw[0], string(raw[2:tagEnd]), raw[tagEnd:]
}

func renderSection(p *core.Printer, name string, records []record) {
	if len(records) == 0 {
		return
	}
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b record) int {
		if order := compareRecords(a, b); order != 0 {
			return order
		}
		if a.ttl < b.ttl {
			return -1
		}
		if a.ttl > b.ttl {
			return 1
		}
		return 0
	})

	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString("  " + name)
	p.Reset()
	p.WriteString("\n")

	for i, rec := range records {
		last := i == len(records)-1
		switch {
		case rec.typ == dnsmessage.TypeTXT && len(rec.txt) > 1:
			renderTXTRecord(p, rec, last)
		case rec.hasComplexRendering():
			renderComplexRecord(p, rec, last)
		default:
			renderRecordLine(p, rec, last)
		}
	}

	p.WriteInfoPrefix()
	p.WriteString("\n")
}

func (rec record) hasComplexRendering() bool {
	switch rec.typ {
	case dnsmessage.TypeMX:
		return rec.target != ""
	case dnsmessage.TypeSRV:
		return rec.target != ""
	case dnsmessage.TypeSOA:
		return rec.target != "" && rec.target2 != ""
	case dnsTypeCAA:
		_, _, _, ok := caaFields(rec.rawRData)
		return ok
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		return rec.target != ""
	default:
		return false
	}
}

// renderComplexRecord keeps the structured fields of complex resource records
// visible. The first line identifies the owner and target (when one exists),
// while the indented fields explain the numeric and type-specific values.
func renderComplexRecord(p *core.Printer, rec record, last bool) {
	writeRecordPrefix(p, last)
	p.Set(core.Green)
	if rec.owner != "" {
		p.WriteString(core.TerminalSafeText(rec.owner))
		if rec.typ == dnsmessage.TypeSVCB || rec.typ == dnsmessage.TypeHTTPS {
			p.WriteString(" ")
		} else if rec.typ != dnsmessage.TypeSOA && rec.typ != dnsTypeCAA {
			p.WriteString(" → ")
		}
	}
	switch rec.typ {
	case dnsmessage.TypeMX:
		p.WriteString(core.TerminalSafeText(rec.target))
	case dnsmessage.TypeSRV:
		p.WriteString(core.TerminalSafeText(rec.target))
		p.WriteString(fmt.Sprintf(":%d", rec.port))
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		p.WriteString(fmt.Sprintf("priority %d → ", rec.priority))
		p.WriteString(core.TerminalSafeText(safeRecordText(rec.target)))
	case dnsmessage.TypeSOA, dnsTypeCAA:
		// These records list their semantic values on indented lines below.
	}
	p.Reset()
	p.WriteString("\n")

	continued := !last
	switch rec.typ {
	case dnsmessage.TypeMX:
		writeRecordDetail(p, "Priority", strconv.FormatUint(uint64(rec.preference), 10), continued)
	case dnsmessage.TypeSRV:
		writeRecordDetail(p, "Priority", strconv.FormatUint(uint64(rec.priority), 10), continued)
		writeRecordDetail(p, "Weight", strconv.FormatUint(uint64(rec.weight), 10), continued)
	case dnsmessage.TypeSOA:
		writeRecordDetail(p, "Primary NS", rec.target, continued)
		writeRecordDetail(p, "Responsible", rec.target2, continued)
		writeRecordDetail(p, "Serial", strconv.FormatUint(uint64(rec.soa[0]), 10), continued)
		writeRecordDetail(p, "Refresh", formatTTL(rec.soa[1]), continued)
		writeRecordDetail(p, "Retry", formatTTL(rec.soa[2]), continued)
		writeRecordDetail(p, "Expire", formatTTL(rec.soa[3]), continued)
		writeRecordDetail(p, "Minimum TTL", formatTTL(rec.soa[4]), continued)
	case dnsTypeCAA:
		flags, tag, value, ok := caaFields(rec.rawRData)
		if !ok {
			renderRecordLine(p, rec, last)
			return
		}
		writeRecordDetail(p, "Flags", strconv.Itoa(int(flags)), continued)
		writeRecordDetail(p, "Tag", tag, continued)
		writeRecordDetail(p, "Value", value, continued)
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		renderServiceBindingDetails(p, rec, continued)
		return
	}
	writeRecordSourceAndTTL(p, rec, continued)
}

// renderServiceBindingDetails expands HTTPS/SVCB parameters into stable,
// human-readable fields. Parameter values stay bytes until this point so the
// renderer can distinguish valid values from malformed or unknown ones.
func renderServiceBindingDetails(p *core.Printer, rec record, continued bool) {
	if rec.priority == 0 {
		writeRecordDetail(p, "Mode", "AliasMode", continued)
	}

	params := slices.Clone(rec.params)
	slices.SortStableFunc(params, func(a, b resolver.SVCParam) int {
		if order := cmp.Compare(svcParamRenderOrder(a.Key), svcParamRenderOrder(b.Key)); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Key, b.Key); order != 0 {
			return order
		}
		return bytes.Compare(a.Value, b.Value)
	})
	for _, param := range params {
		label, value := formatStructuredSVCParam(param)
		writeRecordDetail(p, label, value, continued)
	}

	// A malformed generic RDATA must remain inspectable. Valid responses have
	// already been decoded into Params, but a generic fixture or an unusual
	// provider can still leave only raw bytes available.
	if len(rec.rawRData) > 0 {
		_, _, _, valid := parseRawSVCB(rec.rawRData)
		if !valid {
			writeRecordDetail(p, "Raw RDATA", "0x"+hex.EncodeToString(rec.rawRData), continued)
		}
	}
	writeRecordSourceAndTTL(p, rec, continued)
}

func writeRecordDetail(p *core.Printer, label, value string, continued bool) {
	writeRecordContinuationPrefix(p, continued)
	p.WriteString(label)
	p.WriteString(": ")
	p.WriteString(core.TerminalSafeText(safeRecordText(value)))
	p.WriteString("\n")
}

// writeRecordContinuationPrefix keeps detail lines connected to the record
// branch. Without the vertical continuation, the indentation looks like a
// large gap between the tree marker and the field text.
func writeRecordContinuationPrefix(p *core.Printer, continued bool) {
	p.WriteInfoPrefix()
	if continued {
		p.WriteString("  \u2502  ")
		return
	}
	p.WriteString("     ")
}

func writeRecordSourceAndTTL(p *core.Printer, rec record, continued bool) {
	if rec.source == recordSourcePlatform {
		writeRecordDetail(p, "Source", "platform resolver", continued)
	}
	if rec.hasTTL {
		writeRecordDetail(p, "TTL", formatTTL(rec.ttl), continued)
	} else {
		writeRecordDetail(p, "TTL", "unavailable", continued)
	}
}

func caaFields(raw []byte) (flags uint8, tag, value string, ok bool) {
	if len(raw) < 2 {
		return 0, "", "", false
	}
	tagLen := int(raw[1])
	if tagLen > len(raw)-2 {
		return 0, "", "", false
	}
	return raw[0], string(raw[2 : 2+tagLen]), string(raw[2+tagLen:]), true
}

func formatTXTChunk(chunk []byte) string {
	// strconv.Quote escapes controls, invalid UTF-8, and quotes, so TXT data
	// cannot inject terminal control sequences or output lines.
	return strconv.Quote(string(chunk))
}

// renderTXTRecord renders each TXT character-string on its own line. This
// avoids making adjacent DNS character-strings look like one string with a
// synthetic space between their contents.
func renderTXTRecord(p *core.Printer, rec record, last bool) {
	writeRecordPrefix(p, last)
	p.Set(core.Green)
	if rec.owner != "" {
		p.WriteString(core.TerminalSafeText(rec.owner))
	}
	p.Reset()
	p.WriteString("\n")

	for _, chunk := range rec.txt {
		writeRecordContinuationPrefix(p, !last)
		p.Set(core.Green)
		p.WriteString(formatTXTChunk(chunk))
		p.Reset()
		p.WriteString("\n")
	}

	writeRecordContinuationPrefix(p, !last)
	p.Set(core.Dim)
	if rec.source == recordSourcePlatform {
		p.WriteString("Source: platform resolver; ")
	}
	if rec.hasTTL {
		p.WriteString("TTL: ")
		p.WriteString(formatTTL(rec.ttl))
	} else {
		p.WriteString("TTL: unavailable")
	}
	p.Reset()
	p.WriteString("\n")
}

func renderRecordLine(p *core.Printer, rec record, last bool) {
	writeRecordPrefix(p, last)
	p.Set(core.Green)
	if rec.owner != "" {
		p.WriteString(core.TerminalSafeText(rec.owner))
		p.WriteString(" → ")
	}
	p.WriteString(core.TerminalSafeText(rec.renderValue()))
	p.Reset()
	p.WriteString(" ")
	writeRecordMetadata(p, rec)
	p.WriteString("\n")
}

func writeRecordPrefix(p *core.Printer, last bool) {
	p.WriteInfoPrefix()
	if last {
		p.WriteString("  \u2514\u2500 ")
	} else {
		p.WriteString("  \u251c\u2500 ")
	}
}

func writeRecordMetadata(p *core.Printer, rec record) {
	p.Set(core.Dim)
	p.WriteString("(")
	if rec.source == recordSourcePlatform {
		p.WriteString("platform resolver; ")
	}
	if rec.hasTTL {
		p.WriteString("TTL ")
		p.WriteString(formatTTL(rec.ttl))
	} else {
		p.WriteString("TTL unavailable")
	}
	p.WriteString(")")
	p.Reset()
}

func recordCount(res *result) int {
	var count int
	for _, records := range res.records {
		count += len(records)
	}
	return count
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(100 * time.Microsecond).String()
}

func formatTTL(ttl uint32) string {
	if ttl == 0 {
		return "0s"
	}

	// DNS TTLs are seconds. Use compact whole-unit components so SOA
	// durations such as expire=604800 are readable as 1w instead of 168h.
	remaining := uint64(ttl)
	units := []struct {
		seconds uint64
		suffix  string
	}{
		{7 * 24 * 60 * 60, "w"},
		{24 * 60 * 60, "d"},
		{60 * 60, "h"},
		{60, "m"},
		{1, "s"},
	}
	var b strings.Builder
	for _, unit := range units {
		if remaining < unit.seconds {
			continue
		}
		count := remaining / unit.seconds
		remaining %= unit.seconds
		fmt.Fprintf(&b, "%d%s", count, unit.suffix)
	}
	return b.String()
}
