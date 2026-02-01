package fetch

import (
	"io"
	"strings"
	"testing"
)

func TestLimitedBuffer(t *testing.T) {
	t.Run("under limit", func(t *testing.T) {
		lb := &limitedBuffer{max: 10}
		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if lb.overflow {
			t.Fatal("overflow should be false")
		}
		if lb.buf.String() != "hello" {
			t.Fatalf("expected %q, got %q", "hello", lb.buf.String())
		}
	})

	t.Run("at limit", func(t *testing.T) {
		lb := &limitedBuffer{max: 5}
		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if lb.overflow {
			t.Fatal("overflow should be false at exact limit")
		}
		if lb.buf.String() != "hello" {
			t.Fatalf("expected %q, got %q", "hello", lb.buf.String())
		}
	})

	t.Run("over limit single write", func(t *testing.T) {
		lb := &limitedBuffer{max: 3}
		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}
		if lb.buf.String() != "hel" {
			t.Fatalf("expected %q, got %q", "hel", lb.buf.String())
		}
	})

	t.Run("multiple writes crossing limit", func(t *testing.T) {
		lb := &limitedBuffer{max: 7}

		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if lb.overflow {
			t.Fatal("overflow should be false after first write")
		}

		n, err = lb.Write([]byte("world"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true after second write")
		}
		if lb.buf.String() != "hellowo" {
			t.Fatalf("expected %q, got %q", "hellowo", lb.buf.String())
		}
	})

	t.Run("writes after overflow are discarded", func(t *testing.T) {
		lb := &limitedBuffer{max: 3}
		lb.Write([]byte("hello"))
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}

		n, err := lb.Write([]byte("more"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 4 {
			t.Fatalf("expected n=4, got %d", n)
		}
		if lb.buf.String() != "hel" {
			t.Fatalf("expected %q, got %q", "hel", lb.buf.String())
		}
	})

	t.Run("zero max", func(t *testing.T) {
		lb := &limitedBuffer{max: 0}
		n, err := lb.Write([]byte("a"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 1 {
			t.Fatalf("expected n=1, got %d", n)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}
		if lb.buf.Len() != 0 {
			t.Fatalf("expected empty buffer, got %d bytes", lb.buf.Len())
		}
	})

	t.Run("tee reader not affected by overflow", func(t *testing.T) {
		lb := &limitedBuffer{max: 5}
		data := "hello world, this is a longer string"
		r := io.TeeReader(strings.NewReader(data), lb)

		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != data {
			t.Fatalf("TeeReader should return all data; got %q", got)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}
		if lb.buf.String() != "hello" {
			t.Fatalf("expected %q in buffer, got %q", "hello", lb.buf.String())
		}
	})
}
