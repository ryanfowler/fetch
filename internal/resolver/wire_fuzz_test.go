package resolver

import "testing"

func FuzzDecodeDNSWire(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 1, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff})
	// Keep the largest accepted wire packet in the normal-input corpus.
	f.Add(make([]byte, maxDNSWirePacket))
	// Keep a seed beyond the DNS wire limit so the rejection path is exercised.
	f.Add(make([]byte, maxDNSWirePacket+1))

	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxDNSWirePacket {
			if _, err := DecodeMessage(packet); err == nil {
				t.Fatalf("DecodeMessage accepted %d-byte packet", len(packet))
			}
			return
		}
		_, _ = DecodeMessage(packet)
	})
}
