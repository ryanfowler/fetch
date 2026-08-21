package resolver

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func TestNameEscapesRoundTrip(t *testing.T) {
	for _, input := range []string{"Example.COM", `a\\.b.example.`, `a\\046b.example`, "."} {
		name, err := ParseName(input)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", input, err)
		}
		wire, err := name.Wire()
		if err != nil {
			t.Fatal(err)
		}
		packet := append(make([]byte, 12), wire...)
		decoded, next, err := decodeName(packet, 12)
		if err != nil {
			t.Fatalf("decodeName(%q): %v", input, err)
		}
		if next != len(packet) || !name.Equal(decoded) {
			t.Fatalf("name %q did not round-trip: %q, next=%d", input, decoded.String(), next)
		}
	}
}

func TestEncodeQueryIncludesRandomIDAndEDNS(t *testing.T) {
	first, firstID, err := EncodeQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	second, secondID, err := EncodeQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 12 || len(second) < 12 {
		t.Fatal("encoded query is shorter than a DNS header")
	}
	if firstID == secondID && string(first) == string(second) {
		t.Fatal("two encoded queries were identical")
	}
	message, err := DecodeMessage(first)
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.Response || len(message.Questions) != 1 || len(message.Additionals) != 1 {
		t.Fatalf("unexpected query: %#v", message)
	}
	if message.Additionals[0].Type != dnsTypeOPT || len(message.Additionals[0].RData) != 0 {
		t.Fatalf("unexpected OPT record: %#v", message.Additionals[0])
	}
}

func TestDecodeMessageRejectsMalformedWire(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{"short header", []byte{1, 2, 3}},
		{"forward pointer", questionPacket([]byte{0xc0, 0x0c})},
		{"pointer loop", questionPacket([]byte{1, 'a', 0xc0, 0x0c})},
		{"truncated rdata", recordPacket([]byte{0}, dnsTypeA, []byte{192, 0, 2})},
		{"rdata length beyond packet", recordLengthPacket(dnsTypeA, 4, []byte{192, 0, 2})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeMessage(test.packet); err == nil {
				t.Fatal("DecodeMessage accepted malformed packet")
			}
		})
	}
}

func TestDecodeResponseValidatesTransactionAndQuestion(t *testing.T) {
	query, id, err := EncodeQueryWithID(0x1234, "Example.COM", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	questionName, err := ParseName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	question := Question{Name: questionName, Type: dnsTypeA, Class: 1}
	response := responsePacket(query, id, question, nil)
	if _, err := DecodeResponse(response, id, question); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if _, err := DecodeResponse(response, id+1, question); err == nil || !strings.Contains(err.Error(), "ID") {
		t.Fatalf("wrong ID error = %v", err)
	}
	wrong := question
	wrong.Type = dnsTypeAAAA
	if _, err := DecodeResponse(response, id, wrong); err == nil || !strings.Contains(err.Error(), "question") {
		t.Fatalf("wrong question error = %v", err)
	}
}

func TestDecodeExtendedRCode(t *testing.T) {
	query, id, err := EncodeQueryWithID(7, "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := ParseName("example.com")
	q := Question{Name: name, Type: dnsTypeA, Class: 1}
	response := responsePacket(query, id, q, nil)
	// Replace the query's EDNS OPT with an answer-side OPT carrying extended
	// RCODE 1 (BADVERS), while retaining the ordinary response header.
	binary.BigEndian.PutUint16(response[10:12], 1)
	// root, type=OPT, UDP payload size, extended RCODE=1, version/flags,
	// empty options.
	response = append(response, 0, 0, 41, 0x04, 0xd0, 1, 0, 0, 0, 0, 0)
	message, err := DecodeMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.RCode != 16 {
		t.Fatalf("RCode = %d, want 16", message.Header.RCode)
	}
}

func TestAddressAnswersReportsNODATA(t *testing.T) {
	query, id, err := EncodeQueryWithID(0x54, "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	name, err := ParseName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	question := Question{Name: name, Type: dnsTypeA, Class: 1}
	message, err := DecodeResponse(responsePacket(query, id, question, nil), id, question)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := addressAnswers(message, question, dnsTypeA); err == nil || !strings.Contains(err.Error(), "NODATA") {
		t.Fatalf("err = %v, want NODATA", err)
	}
}

func TestAuthorizeAnswersFollowsOnlyValidatedCNAMEChain(t *testing.T) {
	query, id, err := EncodeQueryWithID(0x55, "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := ParseName("example.com")
	question := Question{Name: name, Type: dnsTypeA, Class: 1}
	alias, _ := ParseName("alias.example")
	cname := makeRecord(name, dnsTypeCNAME, mustWireName(t, alias))
	address := makeRecord(alias, dnsTypeA, []byte{192, 0, 2, 10})
	unrelatedName, _ := ParseName("unrelated.example")
	unrelated := makeRecord(unrelatedName, dnsTypeA, []byte{192, 0, 2, 99})
	response := responsePacket(query, id, question, []Record{cname, address, unrelated})
	message, err := DecodeResponse(response, id, question)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := AuthorizeAddressAnswers(message, question)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 1 || !authorized[0].Owner.Equal(alias) || string(authorized[0].RData) != string(address.RData) {
		t.Fatalf("authorized answers = %#v", authorized)
	}
}

func TestAuthorizeAnswersRejectsReachableCNAMECycle(t *testing.T) {
	query, id, _ := EncodeQueryWithID(0x77, "a.example", dnsTypeA)
	name, _ := ParseName("a.example")
	b, _ := ParseName("b.example")
	question := Question{Name: name, Type: dnsTypeA, Class: 1}
	response := responsePacket(query, id, question, []Record{
		makeRecord(name, dnsTypeCNAME, mustWireName(t, b)),
		makeRecord(b, dnsTypeCNAME, mustWireName(t, name)),
	})
	message, err := DecodeResponse(response, id, question)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeAnswers(message, question); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestAuthorizeAnswersRejectsConflictingCNAMEData(t *testing.T) {
	query, id, _ := EncodeQueryWithID(0x78, "example.com", dnsTypeA)
	name, _ := ParseName("example.com")
	alias, _ := ParseName("alias.example")
	question := Question{Name: name, Type: dnsTypeA, Class: 1}
	response := responsePacket(query, id, question, []Record{
		makeRecord(name, dnsTypeCNAME, mustWireName(t, alias)),
		makeRecord(name, dnsTypeA, []byte{192, 0, 2, 1}),
	})
	message, err := DecodeResponse(response, id, question)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeAnswers(message, question); err == nil || !strings.Contains(err.Error(), "conflicting answer data") {
		t.Fatalf("conflicting data error = %v", err)
	}
}

func TestAuthorizeAnswersRejectsConflictingCNAMETargets(t *testing.T) {
	query, id, _ := EncodeQueryWithID(0x79, "example.com", dnsTypeA)
	name, _ := ParseName("example.com")
	one, _ := ParseName("one.example")
	two, _ := ParseName("two.example")
	question := Question{Name: name, Type: dnsTypeA, Class: 1}
	response := responsePacket(query, id, question, []Record{
		makeRecord(name, dnsTypeCNAME, mustWireName(t, one)),
		makeRecord(name, dnsTypeCNAME, mustWireName(t, two)),
	})
	message, err := DecodeResponse(response, id, question)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeAnswers(message, question); err == nil || !strings.Contains(err.Error(), "conflicting targets") {
		t.Fatalf("conflicting target error = %v", err)
	}
}

func TestAuthorizeAnswersBoundsReverseOrderedCNAMEChain(t *testing.T) {
	query, id, _ := EncodeQueryWithID(0x7a, "example.com", dnsTypeA)
	questionName, _ := ParseName("example.com")
	question := Question{Name: questionName, Type: dnsTypeA, Class: 1}
	answers := make([]Record, 0, 17)
	previous := questionName
	for i := 0; i < 16; i++ {
		next, err := ParseName("n" + strconv.Itoa(i) + ".example")
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, makeRecord(previous, dnsTypeCNAME, mustWireName(t, next)))
		previous = next
	}
	answers = append(answers, makeRecord(previous, dnsTypeA, []byte{192, 0, 2, 1}))
	for i, j := 0, len(answers)-1; i < j; i, j = i+1, j-1 {
		answers[i], answers[j] = answers[j], answers[i]
	}
	response := responsePacket(query, id, question, answers)
	message, err := DecodeResponse(response, id, question)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := AuthorizeAddressAnswers(message, question)
	if err != nil || len(authorized) != 1 {
		t.Fatalf("authorized reverse chain = %#v, err = %v", authorized, err)
	}
}

func mustWireName(t *testing.T, name Name) []byte {
	t.Helper()
	wire, err := name.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func makeRecord(owner Name, typ uint16, data []byte) Record {
	return Record{Owner: owner, Type: typ, Class: 1, TTL: 60, RData: data}
}

func responsePacket(query []byte, id uint16, question Question, answers []Record) []byte {
	qwire, _ := question.Name.Wire()
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x8180)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[6:8], uint16(len(answers)))
	packet = append(packet, qwire...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], question.Type)
	binary.BigEndian.PutUint16(tail[2:4], question.Class)
	packet = append(packet, tail[:]...)
	for _, answer := range answers {
		owner, _ := answer.Owner.Wire()
		packet = append(packet, owner...)
		var header [10]byte
		binary.BigEndian.PutUint16(header[0:2], answer.Type)
		binary.BigEndian.PutUint16(header[2:4], answer.Class)
		binary.BigEndian.PutUint32(header[4:8], answer.TTL)
		binary.BigEndian.PutUint16(header[8:10], uint16(len(answer.RData)))
		packet = append(packet, header[:]...)
		packet = append(packet, answer.RData...)
	}
	_ = query
	return packet
}

func questionPacket(name []byte) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, name...)
	packet = append(packet, 0, 1, 0, 1)
	return packet
}

func recordPacket(owner []byte, typ uint16, data []byte) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	packet = append(packet, owner...)
	var header [10]byte
	binary.BigEndian.PutUint16(header[0:2], typ)
	binary.BigEndian.PutUint16(header[2:4], 1)
	binary.BigEndian.PutUint32(header[4:8], 1)
	binary.BigEndian.PutUint16(header[8:10], uint16(len(data)))
	packet = append(packet, header[:]...)
	packet = append(packet, data...)
	return packet
}

func recordLengthPacket(typ uint16, length uint16, data []byte) []byte {
	packet := recordPacket([]byte{0}, typ, data)
	binary.BigEndian.PutUint16(packet[12+1+8:12+1+10], length)
	return packet
}
