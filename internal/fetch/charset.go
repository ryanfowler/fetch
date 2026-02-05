package fetch

import (
	"io"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/ianaindex"
)

// charsetDecoder returns an *encoding.Decoder for the given charset,
// or nil if no transcoding is needed.
func charsetDecoder(charset string) *encoding.Decoder {
	if charset == "" {
		return nil
	}
	lower := strings.ToLower(charset)
	if lower == "utf-8" || lower == "utf8" || lower == "us-ascii" || lower == "ascii" {
		return nil
	}
	enc, err := ianaindex.MIME.Encoding(charset)
	if err != nil || enc == nil {
		return nil
	}
	return enc.NewDecoder()
}

// transcodeReader wraps r to transcode from charset to UTF-8.
// Returns r unchanged if no transcoding is needed.
func transcodeReader(r io.Reader, charset string) io.Reader {
	if dec := charsetDecoder(charset); dec != nil {
		return dec.Reader(r)
	}
	return r
}

// transcodeBytes transcodes buf from charset to UTF-8.
// Returns buf unchanged if no transcoding is needed.
func transcodeBytes(buf []byte, charset string) []byte {
	dec := charsetDecoder(charset)
	if dec == nil {
		return buf
	}
	out, err := dec.Bytes(buf)
	if err != nil {
		return buf
	}
	return out
}
