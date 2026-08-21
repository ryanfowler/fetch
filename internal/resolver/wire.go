package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// DNS wire limits are deliberately small enough to make malformed packets
// cheap to reject. A DNS message itself cannot exceed 65535 bytes.
const (
	maxDNSNameBytes    = 255
	maxDNSLabelBytes   = 63
	maxDNSLabels       = 127
	maxDNSRecords      = 1024
	maxDNSPointerJumps = 16
	maxDNSRDataBytes   = 65535
	maxDNSUDPPayload   = 1232
)

var errDNSNoData = errors.New("DNS response: NODATA")

const (
	dnsTypeNS    uint16 = 2
	dnsTypeCNAME uint16 = 5
	dnsTypeSOA   uint16 = 6
	dnsTypeMX    uint16 = 15
	dnsTypeTXT   uint16 = 16
	dnsTypeSRV   uint16 = 33
	dnsTypeCAA   uint16 = 257
	dnsTypeRRSIG uint16 = 46
	dnsTypeSVCB  uint16 = 64
	dnsTypeHTTPS uint16 = 65
	dnsTypeOPT   uint16 = 41
)

// Header contains the fields that are relevant to query correlation and
// response authorization. RCode includes the EDNS extended RCODE when an OPT
// record is present.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	RCode              uint16
}

// Name is a DNS name in canonical wire-label form. Labels are opaque octets;
// comparison folds ASCII letters only, as required by DNS name comparison.
type Name struct {
	labels [][]byte
}

// ParseName parses a presentation-format DNS name. A trailing dot is optional.
// Backslash escapes may quote one octet or use the RFC 4343 three-digit form.
func ParseName(value string) (Name, error) { return parsePresentationName(value) }

// ParseDNSName is an explicit alias for callers that prefer the protocol name.
func ParseDNSName(value string) (Name, error) { return ParseName(value) }

func parsePresentationName(value string) (Name, error) {
	if value == "." {
		return Name{}, nil
	}
	if value == "" {
		return Name{}, errors.New("DNS name is empty")
	}
	if hasUnescapedTrailingDot(value) {
		value = value[:len(value)-1]
	}
	if value == "" {
		return Name{}, errors.New("DNS name is empty")
	}

	labels := make([][]byte, 0, 4)
	label := make([]byte, 0, 16)
	wireSize := 1 // terminating root label
	for i := 0; i < len(value); {
		switch value[i] {
		case '.':
			if len(label) == 0 {
				return Name{}, errors.New("DNS name contains an empty label")
			}
			if len(labels) >= maxDNSLabels || wireSize+1+len(label) > maxDNSNameBytes {
				return Name{}, fmt.Errorf("DNS name exceeds %d octets", maxDNSNameBytes)
			}
			labels = append(labels, append([]byte(nil), label...))
			wireSize += 1 + len(label)
			label = label[:0]
			i++
		case '\\':
			i++
			if i >= len(value) {
				return Name{}, errors.New("DNS name has an incomplete escape")
			}
			if i+3 <= len(value) && value[i] >= '0' && value[i] <= '9' && value[i+1] >= '0' && value[i+1] <= '9' && value[i+2] >= '0' && value[i+2] <= '9' {
				n := int(value[i]-'0')*100 + int(value[i+1]-'0')*10 + int(value[i+2]-'0')
				if n > 255 {
					return Name{}, errors.New("DNS name escape is outside the octet range")
				}
				label = append(label, byte(n))
				i += 3
			} else {
				label = append(label, value[i])
				i++
			}
		default:
			label = append(label, value[i])
			i++
		}
		if len(label) > maxDNSLabelBytes {
			return Name{}, fmt.Errorf("DNS label exceeds %d octets", maxDNSLabelBytes)
		}
	}
	if len(label) == 0 {
		return Name{}, errors.New("DNS name contains an empty label")
	}
	if len(labels) >= maxDNSLabels || wireSize+1+len(label) > maxDNSNameBytes {
		return Name{}, fmt.Errorf("DNS name exceeds %d octets", maxDNSNameBytes)
	}
	labels = append(labels, label)
	name := Name{labels: labels}
	if err := name.validate(); err != nil {
		return Name{}, err
	}
	return name, nil
}

func hasUnescapedTrailingDot(value string) bool {
	if !strings.HasSuffix(value, ".") {
		return false
	}
	backslashes := 0
	for i := len(value) - 2; i >= 0 && value[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func (n Name) validate() error {
	if len(n.labels) > maxDNSLabels {
		return fmt.Errorf("DNS name contains too many labels")
	}
	size := 1
	for _, label := range n.labels {
		if len(label) == 0 || len(label) > maxDNSLabelBytes {
			return errors.New("DNS name contains an invalid label")
		}
		size += 1 + len(label)
	}
	if size > maxDNSNameBytes {
		return fmt.Errorf("DNS name exceeds %d octets", maxDNSNameBytes)
	}
	return nil
}

// Wire returns the uncompressed wire representation of the name.
func (n Name) Wire() ([]byte, error) {
	if err := n.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, maxDNSNameBytes)
	for _, label := range n.labels {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// String returns an escaped presentation name that round-trips to the same
// wire labels. The root name is ".".
func (n Name) String() string {
	if len(n.labels) == 0 {
		return "."
	}
	var b strings.Builder
	for i, label := range n.labels {
		if i != 0 {
			b.WriteByte('.')
		}
		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || (c >= 0x21 && c <= 0x7e && c != '.' && c != '\\') {
				b.WriteByte(c)
			} else {
				b.WriteByte('\\')
				b.WriteString(fmt.Sprintf("%03d", c))
			}
		}
	}
	return b.String() + "."
}

// Equal compares names using DNS ASCII case-insensitive semantics.
func (n Name) Equal(other Name) bool { return nameKey(n) == nameKey(other) }

func nameKey(n Name) string {
	var b strings.Builder
	for _, label := range n.labels {
		b.WriteByte(byte(len(label)))
		for _, c := range label {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Question identifies the question to which a response belongs.
type Question struct {
	Name  Name
	Type  uint16
	Class uint16
}

// SVCParam retains an SVCB/HTTPS parameter without interpreting unknown keys.
type SVCParam struct {
	Key   uint16
	Value []byte
}

// Record is a bounded DNS resource record. RData is always a copy limited to
// the record's declared length. Target is populated for records whose RDATA
// contains a DNS name.
type Record struct {
	Owner      Name
	Type       uint16
	Class      uint16
	TTL        uint32
	TTLPresent bool
	RData      []byte
	Target     *Name
	Target2    *Name
	Preference uint16
	Priority   uint16
	Weight     uint16
	Port       uint16
	SOAValues  [5]uint32
	TXT        [][]byte
	Params     []SVCParam
}

// Message is a decoded DNS message. Unknown record types remain opaque in
// Record.RData, but their owner, class, TTL, and bounds are still validated.
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

// DecodeMessage strictly decodes one DNS message.
func DecodeMessage(packet []byte) (*Message, error) {
	if len(packet) < 12 {
		return nil, errors.New("DNS packet is shorter than its header")
	}
	if len(packet) > 65535 {
		return nil, errors.New("DNS packet exceeds the 65535-byte wire limit")
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	counts := [4]uint16{
		binary.BigEndian.Uint16(packet[4:6]),
		binary.BigEndian.Uint16(packet[6:8]),
		binary.BigEndian.Uint16(packet[8:10]),
		binary.BigEndian.Uint16(packet[10:12]),
	}
	total := 0
	for _, count := range counts {
		if int(count) > maxDNSRecords-total {
			return nil, fmt.Errorf("DNS message has too many records")
		}
		total += int(count)
	}
	m := &Message{Header: Header{
		ID:                 binary.BigEndian.Uint16(packet[0:2]),
		Response:           flags&0x8000 != 0,
		Opcode:             uint8((flags >> 11) & 0x0f),
		Authoritative:      flags&0x0400 != 0,
		Truncated:          flags&0x0200 != 0,
		RecursionDesired:   flags&0x0100 != 0,
		RecursionAvailable: flags&0x0080 != 0,
		RCode:              uint16(flags & 0x000f),
	}}
	m.Questions = make([]Question, 0, counts[0])
	m.Answers = make([]Record, 0, counts[1])
	m.Authorities = make([]Record, 0, counts[2])
	m.Additionals = make([]Record, 0, counts[3])
	off := 12
	boundaries := make(map[int]struct{}, total)
	for i := 0; i < int(counts[0]); i++ {
		name, next, err := decodeNameWithBoundaries(packet, off, boundaries)
		if err != nil {
			return nil, fmt.Errorf("question %d name: %w", i, err)
		}
		off = next
		if off+4 > len(packet) {
			return nil, errors.New("truncated DNS question")
		}
		m.Questions = append(m.Questions, Question{Name: name, Type: binary.BigEndian.Uint16(packet[off:]), Class: binary.BigEndian.Uint16(packet[off+2:])})
		off += 4
	}
	sections := []struct {
		count uint16
		dst   *[]Record
	}{
		{counts[1], &m.Answers}, {counts[2], &m.Authorities}, {counts[3], &m.Additionals},
	}
	for si, section := range sections {
		for i := 0; i < int(section.count); i++ {
			record, next, err := decodeRecord(packet, off, boundaries)
			if err == nil && record.Type == dnsTypeOPT {
				if si != 2 {
					err = errors.New("OPT record is not in the additional section")
				} else if !record.Owner.Equal(Name{}) {
					err = errors.New("OPT record owner is not the root name")
				}
			}
			if err != nil {
				return nil, fmt.Errorf("DNS section %d record %d: %w", si, i, err)
			}
			off = next
			*section.dst = append(*section.dst, record)
		}
	}
	if off != len(packet) {
		return nil, errors.New("trailing bytes after DNS message")
	}
	optSeen := false
	for _, record := range m.Additionals {
		if record.Type != dnsTypeOPT {
			continue
		}
		if optSeen {
			return nil, errors.New("DNS message contains multiple OPT records")
		}
		optSeen = true
		if len(record.RData) > maxDNSRDataBytes {
			return nil, errors.New("OPT RDATA is too large")
		}
		extended := uint16(record.TTL >> 24)
		m.Header.RCode |= extended << 4
	}
	return m, nil
}

func decodeRecord(packet []byte, off int, boundaries map[int]struct{}) (Record, int, error) {
	name, next, err := decodeNameWithBoundaries(packet, off, boundaries)
	if err != nil {
		return Record{}, 0, fmt.Errorf("owner name: %w", err)
	}
	off = next
	if off+10 > len(packet) {
		return Record{}, 0, errors.New("truncated DNS record header")
	}
	record := Record{Owner: name, Type: binary.BigEndian.Uint16(packet[off:]), Class: binary.BigEndian.Uint16(packet[off+2:]), TTL: binary.BigEndian.Uint32(packet[off+4:]), TTLPresent: true}
	rdlen := int(binary.BigEndian.Uint16(packet[off+8:]))
	off += 10
	if rdlen > maxDNSRDataBytes || rdlen > len(packet)-off {
		return Record{}, 0, errors.New("DNS record RDATA exceeds packet bounds")
	}
	end := off + rdlen
	record.RData = append([]byte(nil), packet[off:end]...)
	if err := decodeKnownRData(&record, packet, off, end, boundaries); err != nil {
		return Record{}, 0, err
	}
	return record, end, nil
}

func decodeKnownRData(record *Record, packet []byte, start, end int, boundaries map[int]struct{}) error {
	name := func(at int) (*Name, int, error) {
		n, next, err := decodeNameWithBoundaries(packet, at, boundaries)
		if err != nil {
			return nil, 0, err
		}
		if next > end {
			return nil, 0, errors.New("DNS name escapes RDATA bounds")
		}
		return &n, next, nil
	}
	switch record.Type {
	case dnsTypeA:
		if end-start != 4 {
			return errors.New("a record has invalid RDATA length")
		}
	case dnsTypeAAAA:
		if end-start != 16 {
			return errors.New("AAAA record has invalid RDATA length")
		}
	case dnsTypeCNAME, dnsTypeNS:
		target, next, err := name(start)
		if err != nil {
			return fmt.Errorf("record target: %w", err)
		}
		if next != end {
			return errors.New("record target has trailing RDATA")
		}
		record.Target = target
	case dnsTypeMX:
		if end-start < 3 {
			return errors.New("MX record is truncated")
		}
		record.Preference = binary.BigEndian.Uint16(packet[start:])
		target, next, err := name(start + 2)
		if err != nil {
			return fmt.Errorf("MX target: %w", err)
		}
		if next != end {
			return errors.New("MX target has trailing RDATA")
		}
		record.Target = target
	case dnsTypeSOA:
		first, next, err := name(start)
		if err != nil {
			return fmt.Errorf("SOA primary name: %w", err)
		}
		second, next2, err := name(next)
		if err != nil {
			return fmt.Errorf("SOA mailbox name: %w", err)
		}
		if end-next2 != 20 {
			return errors.New("SOA record has invalid RDATA length")
		}
		record.Target, record.Target2 = first, second
		for i := range record.SOAValues {
			record.SOAValues[i] = binary.BigEndian.Uint32(packet[next2+i*4:])
		}
	case dnsTypeTXT:
		for at := start; at < end; {
			ln := int(packet[at])
			at++
			if ln > end-at {
				return errors.New("TXT record is truncated")
			}
			record.TXT = append(record.TXT, append([]byte(nil), packet[at:at+ln]...))
			at += ln
		}
	case dnsTypeSRV:
		if end-start < 7 {
			return errors.New("SRV record is truncated")
		}
		record.Priority = binary.BigEndian.Uint16(packet[start:])
		record.Weight = binary.BigEndian.Uint16(packet[start+2:])
		record.Port = binary.BigEndian.Uint16(packet[start+4:])
		target, next, err := name(start + 6)
		if err != nil {
			return fmt.Errorf("SRV target: %w", err)
		}
		if next != end {
			return errors.New("SRV target has trailing RDATA")
		}
		record.Target = target
	case dnsTypeCAA:
		if end-start < 2 {
			return errors.New("CAA record has an invalid tag length")
		}
		tagLen := int(packet[start+1])
		if tagLen == 0 || tagLen > 15 || tagLen > end-start-2 {
			return errors.New("CAA record has an invalid tag length")
		}
	case dnsTypeOPT:
		for at := start; at < end; {
			if end-at < 4 {
				return errors.New("EDNS option is truncated")
			}
			length := int(binary.BigEndian.Uint16(packet[at+2:]))
			at += 4
			if length > end-at {
				return errors.New("EDNS option exceeds RDATA bounds")
			}
			at += length
		}
	case dnsTypeSVCB, dnsTypeHTTPS:
		if end-start < 3 {
			return errors.New("SVCB record is truncated")
		}
		record.Priority = binary.BigEndian.Uint16(packet[start:])
		if err := validateSVCBTargetEncoding(packet, start+2, end); err != nil {
			return err
		}
		target, next, err := name(start + 2)
		if err != nil {
			return fmt.Errorf("SVCB target: %w", err)
		}
		record.Target = target
		lastKey := uint16(0)
		haveKey := false
		for at := next; at < end; {
			if end-at < 4 {
				return errors.New("SVCB parameter is truncated")
			}
			key := binary.BigEndian.Uint16(packet[at:])
			if key == ^uint16(0) {
				return errors.New("SVCB parameter key 65535 is reserved")
			}
			ln := int(binary.BigEndian.Uint16(packet[at+2:]))
			at += 4
			if ln > end-at {
				return errors.New("SVCB parameter exceeds RDATA bounds")
			}
			if haveKey && key <= lastKey {
				return errors.New("SVCB parameters are not strictly ordered")
			}
			lastKey, haveKey = key, true
			record.Params = append(record.Params, SVCParam{Key: key, Value: append([]byte(nil), packet[at:at+ln]...)})
			at += ln
		}
		if _, err := buildSVCBRecord(record.Priority, *record.Target, record.Params); err != nil {
			return err
		}
	}
	return nil
}

func decodeName(packet []byte, off int) (Name, int, error) {
	return decodeNameWithBoundaries(packet, off, nil)
}

func decodeNameWithBoundaries(packet []byte, off int, boundaries map[int]struct{}) (Name, int, error) {
	if off < 0 || off >= len(packet) {
		return Name{}, 0, errors.New("DNS name offset is outside packet")
	}
	if boundaries != nil {
		boundaries[off] = struct{}{}
	}
	labels := make([][]byte, 0, 4)
	cursor, next, jumps, wireSize := off, off, 0, 1
	jumped := false
	seen := make(map[int]struct{}, maxDNSPointerJumps)
	for {
		if cursor >= len(packet) {
			return Name{}, 0, errors.New("truncated DNS name")
		}
		ln := packet[cursor]
		switch {
		case ln == 0:
			if boundaries != nil {
				boundaries[cursor] = struct{}{}
			}
			if !jumped {
				next = cursor + 1
			}
			name := Name{labels: labels}
			if err := name.validate(); err != nil {
				return Name{}, 0, err
			}
			return name, next, nil
		case ln&0xc0 == 0xc0:
			if cursor+1 >= len(packet) {
				return Name{}, 0, errors.New("truncated DNS compression pointer")
			}
			target := int(ln&0x3f)<<8 | int(packet[cursor+1])
			if target >= cursor {
				return Name{}, 0, errors.New("DNS compression pointer points forward")
			}
			if boundaries != nil {
				if _, ok := boundaries[target]; !ok {
					return Name{}, 0, errors.New("DNS compression pointer targets a non-label boundary")
				}
			}
			if _, ok := seen[target]; ok {
				return Name{}, 0, errors.New("DNS compression pointer loop")
			}
			seen[target] = struct{}{}
			jumps++
			if jumps > maxDNSPointerJumps {
				return Name{}, 0, errors.New("DNS compression pointer depth exceeded")
			}
			if !jumped {
				next = cursor + 2
				jumped = true
			}
			cursor = target
		case ln&0xc0 != 0:
			return Name{}, 0, errors.New("DNS name uses an invalid label type")
		default:
			if boundaries != nil {
				boundaries[cursor] = struct{}{}
			}
			if ln > maxDNSLabelBytes || cursor+1+int(ln) > len(packet) {
				return Name{}, 0, errors.New("DNS label exceeds packet bounds")
			}
			wireSize += 1 + int(ln)
			if wireSize > maxDNSNameBytes {
				return Name{}, 0, errors.New("DNS name exceeds 255 octets")
			}
			labels = append(labels, append([]byte(nil), packet[cursor+1:cursor+1+int(ln)]...))
			if len(labels) > maxDNSLabels {
				return Name{}, 0, errors.New("DNS name contains too many labels")
			}
			cursor += 1 + int(ln)
		}
	}
}

const (
	// DNS retransmission is deliberately short enough to recover from a lost
	// packet without making a normal lookup unnecessarily slow. A finite
	// parent context can shorten it further.
	dnsRetransmissionInterval = time.Second
	dnsTransactionAttempts    = 2
	maxDNSWirePacket          = 65535
	maxDNSTCPFrames           = 8
	maxDNSTCPBytes            = 256 * 1024
)

func lookupWireIPs(ctx context.Context, serverAddr, host string) ([]net.IPAddr, error) {
	return resolveAddressFamilies(ctx, func(ctx context.Context, typ uint16) ([]net.IPAddr, error) {
		return lookupWireType(ctx, serverAddr, host, typ)
	})
}

// LookupUDPMessage performs one UDP DNS transaction and, when the matching
// response is truncated, retries the same query over TCP. The boolean reports
// whether TCP fallback was used so diagnostic callers can explain the result.
func LookupUDPMessage(ctx context.Context, serverAddr, host string, typ uint16) (*Message, bool, error) {
	return lookupUDPMessage(ctx, serverAddr, host, typ, dnsTransactionAttempts)
}

func lookupUDPMessage(ctx context.Context, serverAddr, host string, typ uint16, attempts int) (*Message, bool, error) {
	if attempts < 1 {
		attempts = 1
	}
	transactionDeadline := dnsTransactionDeadline(ctx)
	raw, id, err := EncodeQuery(host, typ)
	if err != nil {
		return nil, false, err
	}
	name, err := ParseName(host)
	if err != nil {
		return nil, false, err
	}
	question := Question{Name: name, Type: typ, Class: 1}

	// DialContext covers resolver-address lookup and socket creation. The
	// resulting connected UDP socket also gives us the exact peer to check on
	// every received datagram.
	dialContext, cancelDial := context.WithDeadline(ctx, transactionDeadline)
	defer cancelDial()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialContext, "udp", serverAddr)
	if err != nil {
		return nil, false, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, false, errors.New("DNS UDP dial did not return a UDP connection")
	}
	defer udpConn.Close()

	message, err := transactUDP(ctx, udpConn, raw, id, question, transactionDeadline, attempts)
	if err != nil {
		return nil, false, err
	}
	if !message.Header.Truncated {
		return message, false, nil
	}

	tcpAddress := serverAddr
	if peer := udpConn.RemoteAddr(); peer != nil {
		tcpAddress = peer.String()
	}
	message, err = transactTCP(ctx, tcpAddress, raw, id, question, transactionDeadline)
	if err != nil {
		return nil, false, fmt.Errorf("DNS TCP fallback: %w", err)
	}
	return message, true, nil
}

func lookupWireType(ctx context.Context, serverAddr, host string, typ uint16) ([]net.IPAddr, error) {
	message, _, err := LookupUDPMessage(ctx, serverAddr, host, typ)
	if err != nil {
		return nil, err
	}
	questionName, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	return addressAnswers(message, Question{Name: questionName, Type: typ, Class: 1}, typ)
}

// transactUDP sends one query, retransmitting it at most once. Invalid or
// unrelated datagrams are not transaction failures: UDP is a datagram service
// and stale packets can remain in a socket after a prior query or be injected
// by an off-path sender.
func transactUDP(ctx context.Context, conn *net.UDPConn, query []byte, id uint16, question Question, transactionDeadline time.Time, attempts int) (*Message, error) {
	stopClosing := closeOnContext(ctx, conn)
	defer stopClosing()

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if time.Now().After(transactionDeadline) {
			return nil, errors.New("DNS transaction budget exhausted")
		}
		if err := conn.SetWriteDeadline(transactionDeadline); err != nil {
			return nil, err
		}
		if err := writeAll(conn, query); err != nil {
			return nil, err
		}

		deadline, err := receiveDeadline(ctx, attempt, transactionDeadline, attempts)
		if err != nil {
			return nil, err
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		packet := make([]byte, maxDNSWirePacket+1)
		for {
			n, source, readErr := conn.ReadFromUDP(packet)
			if readErr != nil {
				if isTimeout(readErr) {
					lastErr = readErr
					break
				}
				if err := contextError(ctx); err != nil {
					return nil, err
				}
				return nil, readErr
			}
			if n > maxDNSWirePacket {
				// The packet was larger than the DNS wire limit. Do not attempt
				// to decode a truncated prefix.
				continue
			}
			if !sameUDPAddr(source, conn.RemoteAddr()) {
				continue
			}
			message, matched, decodeErr := decodeTransactionPacket(packet[:n], id, question)
			if decodeErr != nil {
				return nil, decodeErr
			}
			if !matched {
				continue
			}
			return message, nil
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("DNS UDP transaction timed out after %d attempts: %w", attempts, lastErr)
	}
	return nil, errors.New("DNS UDP transaction failed")
}

func transactTCP(ctx context.Context, serverAddr string, query []byte, id uint16, question Question, transactionDeadline time.Time) (*Message, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	dialContext, cancelDial := context.WithDeadline(ctx, transactionDeadline)
	defer cancelDial()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialContext, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stopClosing := closeOnContext(ctx, conn)
	defer stopClosing()
	if err := conn.SetDeadline(transactionDeadline); err != nil {
		return nil, err
	}
	if len(query) > 65535 {
		return nil, errors.New("DNS query exceeds the TCP frame limit")
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(query)))
	if err := writeAll(conn, length[:]); err != nil {
		return nil, err
	}
	if err := writeAll(conn, query); err != nil {
		return nil, err
	}

	var frameLength [2]byte
	packet := make([]byte, maxDNSWirePacket)
	totalBytes := 0
	for frame := 0; ; frame++ {
		if frame >= maxDNSTCPFrames {
			return nil, errors.New("DNS TCP response has too many frames")
		}
		if _, err := io.ReadFull(conn, frameLength[:]); err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(frameLength[:]))
		if n == 0 {
			return nil, errors.New("DNS TCP response has an empty frame")
		}
		if n > len(packet) || totalBytes > maxDNSTCPBytes-n {
			return nil, errors.New("DNS TCP response exceeds the transaction limit")
		}
		totalBytes += n
		framePacket := packet[:n]
		if _, err := io.ReadFull(conn, framePacket); err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, err
		}
		message, matched, decodeErr := decodeTransactionPacket(framePacket, id, question)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if matched {
			return message, nil
		}
	}
}

func addressAnswers(message *Message, question Question, typ uint16) ([]net.IPAddr, error) {
	if message.Header.RCode != 0 {
		return nil, fmt.Errorf("DNS response: %s", RCodeName(message.Header.RCode))
	}
	answers, err := AuthorizeAddressAnswers(message, question)
	if err != nil {
		return nil, err
	}
	out := make([]net.IPAddr, 0, len(answers))
	for _, answer := range answers {
		if answer.Type != typ {
			continue
		}
		if ip := RecordAddress(answer); ip != nil {
			out = append(out, net.IPAddr{IP: ip})
		}
	}
	if len(out) == 0 {
		return nil, errDNSNoData
	}
	return out, nil
}

func decodeTransactionPacket(packet []byte, id uint16, question Question) (*Message, bool, error) {
	// Filter the cheap correlation fields before strict decoding. A stale
	// query packet or response for another opcode must not be able to abort
	// this transaction merely because its remaining bytes are malformed.
	matches, err := transactionQuestionMatches(packet, id, question)
	if err != nil || !matches {
		return nil, false, err
	}
	message, err := DecodeMessage(packet)
	if err != nil {
		return nil, false, err
	}
	if err := message.ValidateResponse(id, question); err != nil {
		// Correlation mismatches are expected noise on UDP. They must not abort
		// the transaction or make a stale response look authoritative.
		return nil, false, nil
	}
	return message, true, nil
}

func transactionQuestionMatches(packet []byte, id uint16, question Question) (bool, error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[:2]) != id {
		return false, nil
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	if flags&0x8000 == 0 || (flags>>11)&0x0f != 0 {
		return false, nil
	}
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return false, nil
	}
	name, next, err := decodeName(packet, 12)
	if err != nil {
		return false, err
	}
	if next+4 > len(packet) {
		return false, errors.New("truncated DNS response question")
	}
	got := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(packet[next:]),
		Class: binary.BigEndian.Uint16(packet[next+2:]),
	}
	return got.Name.Equal(question.Name) && got.Type == question.Type && got.Class == question.Class, nil
}

func sameUDPAddr(got *net.UDPAddr, expected net.Addr) bool {
	want, ok := expected.(*net.UDPAddr)
	if !ok || got == nil || want == nil {
		return false
	}
	return got.Port == want.Port && got.IP.Equal(want.IP) && got.Zone == want.Zone
}

func dnsTransactionDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	// An absent request deadline still needs a finite DNS retransmission
	// window. This same absolute deadline is passed to TCP fallback, so a
	// truncated response cannot turn a bounded UDP transaction into an
	// unbounded stream read.
	return time.Now().Add(dnsRetransmissionInterval * dnsTransactionAttempts)
}

func receiveDeadline(ctx context.Context, attempt int, transactionDeadline time.Time, attempts int) (time.Time, error) {
	if err := contextError(ctx); err != nil {
		return time.Time{}, err
	}
	remaining := time.Until(transactionDeadline)
	if remaining <= 0 {
		if err := contextError(ctx); err != nil {
			return time.Time{}, err
		}
		return time.Time{}, fmt.Errorf("DNS transaction budget exhausted")
	}
	deadline := time.Now().Add(dnsRetransmissionInterval)
	// Divide the remaining budget between this and the final possible
	// transmission. This keeps retransmission inside the parent deadline.
	transmissionsLeft := attempts - attempt
	if transmissionsLeft > 1 {
		share := remaining / time.Duration(transmissionsLeft)
		if share < dnsRetransmissionInterval {
			deadline = time.Now().Add(share)
		}
	}
	if transactionDeadline.Before(deadline) {
		deadline = transactionDeadline
	}
	return deadline, nil
}

func closeOnContext(ctx context.Context, conn net.Conn) func() {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	return func() { close(stop) }
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return errors.New("short DNS stream write")
		}
		data = data[n:]
	}
	return nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return ctx.Err()
	default:
		return nil
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// EncodeQuery creates a recursive query with a cryptographically random ID
// and an EDNS(0) OPT record sized for the usual DNS UDP payload.
func EncodeQuery(name string, typ uint16) ([]byte, uint16, error) {
	var rawID [2]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return nil, 0, fmt.Errorf("generate DNS transaction ID: %w", err)
	}
	return EncodeQueryWithID(binary.BigEndian.Uint16(rawID[:]), name, typ)
}

// EncodeQueryWithID is deterministic for tests and for transports that need
// to correlate a caller-selected transaction ID.
func EncodeQueryWithID(id uint16, name string, typ uint16) ([]byte, uint16, error) {
	qname, err := ParseName(name)
	if err != nil {
		return nil, 0, err
	}
	wireName, err := qname.Wire()
	if err != nil {
		return nil, 0, err
	}
	packet := make([]byte, 12+len(wireName)+4+11)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], 1)
	off := 12
	copy(packet[off:], wireName)
	off += len(wireName)
	binary.BigEndian.PutUint16(packet[off:], typ)
	binary.BigEndian.PutUint16(packet[off+2:], 1)
	off += 4
	// root owner, OPT, UDP payload size, ext-RCODE/version/flags, empty RDATA
	packet[off] = 0
	binary.BigEndian.PutUint16(packet[off+1:], dnsTypeOPT)
	binary.BigEndian.PutUint16(packet[off+3:], maxDNSUDPPayload)
	return packet, id, nil
}

// ValidateResponse checks the transaction, response flags, and exact question.
func (m *Message) ValidateResponse(id uint16, question Question) error {
	if m == nil {
		return errors.New("nil DNS response")
	}
	if !m.Header.Response {
		return errors.New("DNS packet is not a response")
	}
	if m.Header.ID != id {
		return errors.New("mismatched DNS response ID")
	}
	if m.Header.Opcode != 0 {
		return fmt.Errorf("unexpected DNS opcode %d", m.Header.Opcode)
	}
	if len(m.Questions) != 1 {
		return errors.New("DNS response has an unexpected question count")
	}
	got := m.Questions[0]
	if !got.Name.Equal(question.Name) || got.Type != question.Type || got.Class != question.Class {
		return errors.New("mismatched DNS response question")
	}
	return nil
}

// DecodeResponse decodes and validates a response for one query.
func DecodeResponse(packet []byte, id uint16, question Question) (*Message, error) {
	m, err := DecodeMessage(packet)
	if err != nil {
		return nil, err
	}
	if err := m.ValidateResponse(id, question); err != nil {
		return nil, err
	}
	return m, nil
}

// AuthorizeAnswers returns answer records whose owners are the queried name
// or a bounded, validated CNAME successor. Unrelated answer and glue records
// are excluded. A reachable CNAME owner cannot also contain other answer data,
// and all CNAME records for one owner must agree on one target.
func AuthorizeAnswers(m *Message, question Question) ([]Record, error) {
	if m == nil {
		return nil, errors.New("nil DNS message")
	}
	if err := question.Name.validate(); err != nil {
		return nil, err
	}
	if len(m.Answers) > maxDNSRecords {
		return nil, errors.New("DNS response has too many answer records")
	}

	// Validate every service-binding RRset before selecting authorized answers.
	// This keeps a malformed record from being hidden by a valid record in the
	// same authenticated response.
	type serviceSetKey struct {
		owner string
		typ   uint16
	}
	serviceSets := make(map[serviceSetKey][]Record)
	for _, record := range m.Answers {
		if record.Class != question.Class || (record.Type != dnsTypeSVCB && record.Type != dnsTypeHTTPS) {
			continue
		}
		key := serviceSetKey{owner: nameKey(record.Owner), typ: record.Type}
		serviceSets[key] = append(serviceSets[key], record)
	}
	for _, records := range serviceSets {
		if err := ValidateSVCBRRSet(records); err != nil {
			return nil, err
		}
	}

	// DNS CNAMEs form a chain, not a general graph. Index the complete answer
	// section first so reverse-ordered answers receive the same authorization as
	// forward-ordered answers, without scanning the section at every hop.
	type cnameOwner struct {
		targets  []Name
		hasCNAME bool
		hasOther bool
	}
	owners := make(map[string]*cnameOwner, len(m.Answers))
	for _, record := range m.Answers {
		if record.Class != question.Class {
			continue
		}
		key := nameKey(record.Owner)
		entry := owners[key]
		if entry == nil {
			entry = &cnameOwner{}
			owners[key] = entry
		}
		switch record.Type {
		case dnsTypeCNAME:
			if record.Target == nil {
				return nil, errors.New("DNS CNAME record has no valid target")
			}
			entry.targets = append(entry.targets, *record.Target)
			entry.hasCNAME = true
		case dnsTypeRRSIG:
			// Signatures may accompany a CNAME without violating the CNAME
			// exclusivity rule. They are still returned when their owner is
			// authorized.
		default:
			entry.hasOther = true
		}
	}

	const maxCNAMEChainDepth = 16
	allowed := make(map[string]struct{}, maxCNAMEChainDepth+1)
	current := question.Name
	allowed[nameKey(current)] = struct{}{}
	seen := map[string]struct{}{nameKey(current): {}}
	for depth := 0; ; depth++ {
		entry := owners[nameKey(current)]
		if entry == nil || !entry.hasCNAME {
			break
		}
		if entry.hasOther {
			return nil, errors.New("DNS CNAME owner has conflicting answer data")
		}
		if depth >= maxCNAMEChainDepth {
			return nil, errors.New("DNS CNAME chain exceeds depth limit")
		}
		target := entry.targets[0]
		for _, candidate := range entry.targets[1:] {
			if !candidate.Equal(target) {
				return nil, errors.New("DNS CNAME owner has conflicting targets")
			}
		}
		targetKey := nameKey(target)
		if _, ok := seen[targetKey]; ok {
			return nil, errors.New("DNS CNAME loop (chain contains a cycle)")
		}
		seen[targetKey] = struct{}{}
		allowed[targetKey] = struct{}{}
		current = target
	}

	out := make([]Record, 0, len(m.Answers))
	for _, record := range m.Answers {
		if record.Class != question.Class {
			continue
		}
		if _, ok := allowed[nameKey(record.Owner)]; ok {
			out = append(out, record)
		}
	}
	return out, nil
}

// AuthorizeAddressAnswers filters AuthorizeAnswers to records that can supply
// an address or service candidate.
func AuthorizeAddressAnswers(m *Message, question Question) ([]Record, error) {
	records, err := AuthorizeAnswers(m, question)
	if err != nil {
		return nil, err
	}
	out := records[:0]
	for _, record := range records {
		switch record.Type {
		case dnsTypeA, dnsTypeAAAA, dnsTypeSVCB, dnsTypeHTTPS:
			out = append(out, record)
		}
	}
	return out, nil
}

// RCodeName returns a stable name for ordinary and EDNS extended response
// codes. Unknown values are retained as a numeric name.
func RCodeName(code uint16) string {
	names := map[uint16]string{0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain", 4: "NotImp", 5: "Refused", 6: "YXDomain", 7: "YXRRSet", 8: "NXRRSet", 9: "NotAuth", 10: "NotZone", 11: "DSOTYPENI", 16: "BADSIG", 17: "BADKEY", 18: "BADTIME", 19: "BADMODE", 20: "BADNAME", 21: "BADALG", 22: "BADTRUNC", 23: "BADCOOKIE"}
	if name, ok := names[code]; ok {
		return name
	}
	return "RCODE" + strconv.Itoa(int(code))
}

// ValidateRData applies the same strict per-type RDATA checks used by the
// message decoder to an independently obtained RDATA slice.
func ValidateRData(typ uint16, rdata []byte) error {
	record := Record{Type: typ, RData: append([]byte(nil), rdata...)}
	return decodeKnownRData(&record, rdata, 0, len(rdata), nil)
}

// RecordAddress returns an address from an A or AAAA record.
func RecordAddress(record Record) net.IP {
	switch record.Type {
	case dnsTypeA, dnsTypeAAAA:
		return append(net.IP(nil), record.RData...)
	}
	return nil
}
