package grpc

import "testing"

func FuzzUnframe(f *testing.F) {
	f.Add(Frame([]byte("hello"), false))
	f.Add(Frame([]byte("compressed"), true))
	f.Add([]byte{0x02, 0, 0, 0, 0})
	f.Add([]byte{0, 0x10, 0, 0, 0})

	f.Fuzz(func(t *testing.T, frame []byte) {
		const maxFuzzInput = 1 << 20
		if len(frame) > maxFuzzInput {
			frame = frame[:maxFuzzInput]
		}
		_, _, _ = Unframe(frame)
	})
}
