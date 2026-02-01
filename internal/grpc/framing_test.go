package grpc

import (
	"bytes"
	"io"
	"testing"
)

func TestFrame(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		compressed bool
		want       []byte
	}{
		{
			name:       "empty uncompressed",
			data:       []byte{},
			compressed: false,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:       "simple uncompressed",
			data:       []byte{0x01, 0x02, 0x03},
			compressed: false,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			name:       "simple compressed",
			data:       []byte{0x01, 0x02, 0x03},
			compressed: true,
			want:       []byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			name:       "larger message",
			data:       bytes.Repeat([]byte{0xAB}, 256),
			compressed: false,
			want:       append([]byte{0x00, 0x00, 0x00, 0x01, 0x00}, bytes.Repeat([]byte{0xAB}, 256)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Frame(tt.data, tt.compressed)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Frame() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnframe(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantData       []byte
		wantCompressed bool
		wantErr        bool
	}{
		{
			name:           "empty message",
			input:          []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantData:       []byte{},
			wantCompressed: false,
			wantErr:        false,
		},
		{
			name:           "simple uncompressed",
			input:          []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			wantData:       []byte{0x01, 0x02, 0x03},
			wantCompressed: false,
			wantErr:        false,
		},
		{
			name:           "simple compressed",
			input:          []byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			wantData:       []byte{0x01, 0x02, 0x03},
			wantCompressed: true,
			wantErr:        false,
		},
		{
			name:    "truncated header",
			input:   []byte{0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated data",
			input:   []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02}, // claims 5 bytes, has 2
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, compressed, err := Unframe(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unframe() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !bytes.Equal(data, tt.wantData) {
				t.Errorf("Unframe() data = %v, want %v", data, tt.wantData)
			}
			if compressed != tt.wantCompressed {
				t.Errorf("Unframe() compressed = %v, want %v", compressed, tt.wantCompressed)
			}
		})
	}
}

func TestFrameUnframeRoundTrip(t *testing.T) {
	testData := [][]byte{
		{},
		{0x00},
		{0x01, 0x02, 0x03, 0x04, 0x05},
		bytes.Repeat([]byte{0xAB}, 1000),
	}

	for _, data := range testData {
		framed := Frame(data, false)
		unframed, compressed, err := Unframe(framed)
		if err != nil {
			t.Errorf("Unframe() error = %v", err)
			continue
		}
		if compressed {
			t.Error("expected uncompressed")
		}
		if !bytes.Equal(unframed, data) {
			t.Errorf("round trip failed: got %v, want %v", unframed, data)
		}
	}
}

func TestUnframeLargeMessageRejected(t *testing.T) {
	// Create a header claiming a very large message
	header := []byte{0x00, 0x10, 0x00, 0x00, 0x00} // 256MB
	_, _, err := Unframe(header)
	if err == nil {
		t.Error("expected error for large message")
	}
}

func TestReadFrame(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantData       []byte
		wantCompressed bool
		wantErr        bool
		wantEOF        bool
	}{
		{
			name:           "empty message",
			input:          []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantData:       []byte{},
			wantCompressed: false,
		},
		{
			name:           "simple uncompressed",
			input:          []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			wantData:       []byte{0x01, 0x02, 0x03},
			wantCompressed: false,
		},
		{
			name:           "simple compressed",
			input:          []byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			wantData:       []byte{0x01, 0x02, 0x03},
			wantCompressed: true,
		},
		{
			name:    "empty reader",
			input:   []byte{},
			wantEOF: true,
		},
		{
			name:    "truncated header",
			input:   []byte{0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated data",
			input:   []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "oversized message",
			input:   []byte{0x00, 0x10, 0x00, 0x00, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			data, compressed, err := ReadFrame(r)
			if tt.wantEOF {
				if err != io.EOF {
					t.Errorf("ReadFrame() error = %v, want io.EOF", err)
				}
				return
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFrame() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !bytes.Equal(data, tt.wantData) {
				t.Errorf("ReadFrame() data = %v, want %v", data, tt.wantData)
			}
			if compressed != tt.wantCompressed {
				t.Errorf("ReadFrame() compressed = %v, want %v", compressed, tt.wantCompressed)
			}
		})
	}
}

func TestReadFrameMultiple(t *testing.T) {
	// Create a reader with two frames.
	frame1 := Frame([]byte{0x01, 0x02}, false)
	frame2 := Frame([]byte{0x03, 0x04, 0x05}, true)
	r := bytes.NewReader(append(frame1, frame2...))

	// Read first frame.
	data, compressed, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame() first frame error = %v", err)
	}
	if !bytes.Equal(data, []byte{0x01, 0x02}) {
		t.Errorf("first frame data = %v, want [0x01, 0x02]", data)
	}
	if compressed {
		t.Error("first frame: expected uncompressed")
	}

	// Read second frame.
	data, compressed, err = ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame() second frame error = %v", err)
	}
	if !bytes.Equal(data, []byte{0x03, 0x04, 0x05}) {
		t.Errorf("second frame data = %v, want [0x03, 0x04, 0x05]", data)
	}
	if !compressed {
		t.Error("second frame: expected compressed")
	}

	// No more frames.
	_, _, err = ReadFrame(r)
	if err != io.EOF {
		t.Errorf("ReadFrame() after last frame: error = %v, want io.EOF", err)
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	testData := [][]byte{
		{},
		{0x00},
		{0x01, 0x02, 0x03, 0x04, 0x05},
		bytes.Repeat([]byte{0xAB}, 1000),
	}

	for _, data := range testData {
		framed := Frame(data, false)
		r := bytes.NewReader(framed)
		unframed, compressed, err := ReadFrame(r)
		if err != nil {
			t.Errorf("ReadFrame() error = %v", err)
			continue
		}
		if compressed {
			t.Error("expected uncompressed")
		}
		if !bytes.Equal(unframed, data) {
			t.Errorf("round trip failed: got %v, want %v", unframed, data)
		}
	}
}
