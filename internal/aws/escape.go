package aws

import (
	"bytes"
	"unicode/utf8"
)

func escapeURIPath(w *bytes.Buffer, uri string) {
	var n int
	for i, c := range uri {
		if validURIBytes[uri[i]] {
			continue
		}

		w.WriteString(uri[n:i])
		n = i + utf8.RuneLen(c)

		var buf [utf8.UTFMax]byte
		length := utf8.EncodeRune(buf[:], c)

		w.WriteByte('%')
		encodeHexUpper(w, buf[:length])
	}
	w.WriteString(uri[n:])
}

func encodeHexUpper(w *bytes.Buffer, s []byte) {
	const hexUpper = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		b := s[i]
		w.WriteByte(hexUpper[b>>4])
		w.WriteByte(hexUpper[b&0x0F])
	}
}

var validURIBytes = [256]bool{
	// -
	45: true,

	// .
	46: true,

	// /
	47: true,

	// 0-9
	48: true,
	49: true,
	50: true,
	51: true,
	52: true,
	53: true,
	54: true,
	55: true,
	56: true,
	57: true,

	// A-Z
	65: true,
	66: true,
	67: true,
	68: true,
	69: true,
	70: true,
	71: true,
	72: true,
	73: true,
	74: true,
	75: true,
	76: true,
	77: true,
	78: true,
	79: true,
	80: true,
	81: true,
	82: true,
	83: true,
	84: true,
	85: true,
	86: true,
	87: true,
	88: true,
	89: true,
	90: true,

	// _
	95: true,

	// a-z
	97:  true,
	98:  true,
	99:  true,
	100: true,
	101: true,
	102: true,
	103: true,
	104: true,
	105: true,
	106: true,
	107: true,
	108: true,
	109: true,
	110: true,
	111: true,
	112: true,
	113: true,
	114: true,
	115: true,
	116: true,
	117: true,
	118: true,
	119: true,
	120: true,
	121: true,
	122: true,

	// ~
	126: true,
}
