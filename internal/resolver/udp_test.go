package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLookupWireTypeDiscardsMismatchedDatagrams(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		question := message.Questions[0]

		// A valid query packet, a different transaction, a different opcode,
		// and a different question must all be ignored.
		server.udp.WriteToUDP(query, client)
		wrongID := responsePacket(query, message.Header.ID+1, question, nil)
		server.udp.WriteToUDP(wrongID, client)
		wrongOpcode := responsePacket(query, message.Header.ID, question, nil)
		binary.BigEndian.PutUint16(wrongOpcode[2:4], binary.BigEndian.Uint16(wrongOpcode[2:4])|0x0800)
		server.udp.WriteToUDP(wrongOpcode, client)
		wrongQuestion := question
		wrongQuestion.Type = dnsTypeAAAA
		malformedWrongQuestion := append(responsePacket(query, message.Header.ID, wrongQuestion, nil), 0xff)
		server.udp.WriteToUDP(malformedWrongQuestion, client)

		answer := makeRecord(question.Name, dnsTypeA, net.IPv4(192, 0, 2, 10).To4())
		_, err = server.udp.WriteToUDP(responsePacket(query, message.Header.ID, question, []Record{answer}), client)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || !addrs[0].IP.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Fatalf("addresses = %v", addrs)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLookupWireTypeRejectsDatagramsFromWrongSource(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()
	spoof, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer spoof.Close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		question := message.Questions[0]
		answer := makeRecord(question.Name, dnsTypeA, net.IPv4(192, 0, 2, 11).To4())
		packet := responsePacket(query, message.Header.ID, question, []Record{answer})
		if _, err := spoof.WriteToUDP(packet, client); err != nil {
			done <- err
			return
		}
		_, err = server.udp.WriteToUDP(packet, client)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || !addrs[0].IP.Equal(net.IPv4(192, 0, 2, 11)) {
		t.Fatalf("addresses = %v", addrs)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLookupWireTypeRetransmitsDroppedUDPQuery(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		query2, client2, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		if string(query) != string(query2) || !client.IP.Equal(client2.IP) || client.Port != client2.Port {
			done <- errors.New("retransmission changed the query or client")
			return
		}
		question := message.Questions[0]
		answer := makeRecord(question.Name, dnsTypeA, net.IPv4(192, 0, 2, 12).To4())
		_, err = server.udp.WriteToUDP(responsePacket(query2, message.Header.ID, question, []Record{answer}), client2)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || !addrs[0].IP.Equal(net.IPv4(192, 0, 2, 12)) {
		t.Fatalf("addresses = %v", addrs)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLookupWireTypeRetransmitsAfterMalformedMatchingResponse(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		question := message.Questions[0]
		malformed := append(responsePacket(query, message.Header.ID, question, nil), 0xff)
		if _, err := server.udp.WriteToUDP(malformed, client); err != nil {
			done <- err
			return
		}

		query2, client2, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		if string(query) != string(query2) || !client.IP.Equal(client2.IP) || client.Port != client2.Port {
			done <- errors.New("retransmission changed the query or client")
			return
		}
		answer := makeRecord(question.Name, dnsTypeA, net.IPv4(192, 0, 2, 14).To4())
		_, err = server.udp.WriteToUDP(responsePacket(query2, message.Header.ID, question, []Record{answer}), client2)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || !addrs[0].IP.Equal(net.IPv4(192, 0, 2, 14)) {
		t.Fatalf("addresses = %v", addrs)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLookupWireTypeAcceptsResponseAfterMalformedMatchingBurst(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		question := message.Questions[0]
		malformed := append(responsePacket(query, message.Header.ID, question, nil), 0xff)
		for range maxDNSMalformedUDPPackets {
			if _, err := server.udp.WriteToUDP(malformed, client); err != nil {
				done <- err
				return
			}
		}
		answer := makeRecord(question.Name, dnsTypeA, net.IPv4(192, 0, 2, 15).To4())
		_, err = server.udp.WriteToUDP(responsePacket(query, message.Header.ID, question, []Record{answer}), client)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || !addrs[0].IP.Equal(net.IPv4(192, 0, 2, 15)) {
		t.Fatalf("addresses = %v", addrs)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLookupWireTypeFallsBackToTCPWhenUDPIsTruncated(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: server.port()})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		truncated := responsePacket(query, message.Header.ID, message.Questions[0], nil)
		binary.BigEndian.PutUint16(truncated[2:4], binary.BigEndian.Uint16(truncated[2:4])|0x0200)
		if _, err := server.udp.WriteToUDP(truncated, client); err != nil {
			done <- err
			return
		}

		connection, err := tcp.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			done <- err
			return
		}
		tcpQuery := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(connection, tcpQuery); err != nil {
			done <- err
			return
		}
		tcpMessage, err := DecodeMessage(tcpQuery)
		if err != nil {
			done <- err
			return
		}
		if tcpMessage.Header.ID != message.Header.ID {
			done <- errors.New("TCP fallback changed transaction ID")
			return
		}
		answer := makeRecord(tcpMessage.Questions[0].Name, dnsTypeA, net.IPv4(192, 0, 2, 13).To4())
		response := responsePacket(tcpQuery, tcpMessage.Header.ID, tcpMessage.Questions[0], []Record{answer})
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if _, err := connection.Write(length[:]); err != nil {
			done <- err
			return
		}
		_, err = connection.Write(response)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || !addrs[0].IP.Equal(net.IPv4(192, 0, 2, 13)) {
		t.Fatalf("addresses = %v", addrs)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLookupWireTypePreservesMatchingSERVFAIL(t *testing.T) {
	server := newUDPTestServer(t)
	defer server.close()
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			return
		}
		response := responsePacket(query, message.Header.ID, message.Questions[0], nil)
		flags := binary.BigEndian.Uint16(response[2:4])
		binary.BigEndian.PutUint16(response[2:4], (flags&0xfff0)|2)
		_, _ = server.udp.WriteToUDP(response, client)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := lookupWireType(ctx, server.addr(), "example.com", dnsTypeA)
	if err == nil || !strings.Contains(err.Error(), "ServFail") {
		t.Fatalf("error = %v, want ServFail", err)
	}
}

type udpTestServer struct {
	udp *net.UDPConn
}

func newUDPTestServer(t *testing.T) *udpTestServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	return &udpTestServer{udp: conn}
}

func (s *udpTestServer) addr() string { return s.udp.LocalAddr().String() }
func (s *udpTestServer) port() int    { return s.udp.LocalAddr().(*net.UDPAddr).Port }

func (s *udpTestServer) readQuery() ([]byte, *net.UDPAddr, error) {
	if err := s.udp.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, nil, err
	}
	packet := make([]byte, maxDNSWirePacket+1)
	n, client, err := s.udp.ReadFromUDP(packet)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), packet[:n]...), client, nil
}

func (s *udpTestServer) close() { _ = s.udp.Close() }
