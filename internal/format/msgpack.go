package format

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatMsgPack formats the provided raw MessagePack data to the Printer as JSON.
//
// MessagePack map keys are not restricted to strings, unlike JSON object keys.
// This parser converts the supported scalar key types to their JSON string
// representation before formatting. Binary keys use base64 so arbitrary bytes
// remain representable. It also validates strings itself so malformed strings
// produce a parser error before JSON formatting.
func FormatMsgPack(buf []byte, p *core.Printer) error {
	parser := msgPackParser{input: buf}
	var out bytes.Buffer
	if err := parser.writeValue(&out, 0); err != nil {
		p.Discard()
		return err
	}
	if parser.pos != len(buf) {
		p.Discard()
		return errorsMsgPack("unexpected trailing MessagePack data")
	}
	return FormatJSON(out.Bytes(), p)
}

type msgPackError string

func (e msgPackError) Error() string { return string(e) }

func errorsMsgPack(message string) error { return msgPackError(message) }

type msgPackParser struct {
	input []byte
	pos   int
}

func (p *msgPackParser) writeValue(out *bytes.Buffer, depth int) error {
	if depth > core.MaxNestingDepth {
		return errorsMsgPack(fmt.Sprintf("MessagePack nesting too deep (max %d)", core.MaxNestingDepth))
	}
	marker, err := p.readByte()
	if err != nil {
		return err
	}

	switch {
	case marker <= 0x7f:
		writeString(out, strconv.Itoa(int(marker)))
	case marker >= 0x80 && marker <= 0x8f:
		return p.writeMap(out, uint64(marker&0x0f), depth)
	case marker >= 0x90 && marker <= 0x9f:
		return p.writeArray(out, uint64(marker&0x0f), depth)
	case marker >= 0xa0 && marker <= 0xbf:
		return p.writeString(out, int(marker&0x1f))
	case marker == 0xc0:
		writeString(out, "null")
	case marker == 0xc1:
		return errorsMsgPack("reserved MessagePack marker 0xc1")
	case marker == 0xc2:
		writeString(out, "false")
	case marker == 0xc3:
		writeString(out, "true")
	case marker == 0xc4:
		length, err := p.readLen8()
		if err != nil {
			return err
		}
		return p.writeBinary(out, length)
	case marker == 0xc5:
		length, err := p.readLen16()
		if err != nil {
			return err
		}
		return p.writeBinary(out, length)
	case marker == 0xc6:
		length, err := p.readLen32()
		if err != nil {
			return err
		}
		return p.writeBinary(out, length)
	case marker == 0xc7:
		length, err := p.readLen8()
		if err != nil {
			return err
		}
		return p.writeExtension(out, length)
	case marker == 0xc8:
		length, err := p.readLen16()
		if err != nil {
			return err
		}
		return p.writeExtension(out, length)
	case marker == 0xc9:
		length, err := p.readLen32()
		if err != nil {
			return err
		}
		return p.writeExtension(out, length)
	case marker == 0xca:
		v, err := p.readU32()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatFloat(float64(math.Float32frombits(v)), 'g', -1, 32))
	case marker == 0xcb:
		v, err := p.readU64()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatFloat(math.Float64frombits(v), 'g', -1, 64))
	case marker == 0xcc:
		v, err := p.readByte()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatUint(uint64(v), 10))
	case marker == 0xcd:
		v, err := p.readU16()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatUint(uint64(v), 10))
	case marker == 0xce:
		v, err := p.readU32()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatUint(uint64(v), 10))
	case marker == 0xcf:
		v, err := p.readU64()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatUint(v, 10))
	case marker == 0xd0:
		v, err := p.readByte()
		if err != nil {
			return err
		}
		writeString(out, strconv.Itoa(int(int8(v))))
	case marker == 0xd1:
		v, err := p.readU16()
		if err != nil {
			return err
		}
		writeString(out, strconv.Itoa(int(int16(v))))
	case marker == 0xd2:
		v, err := p.readU32()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatInt(int64(int32(v)), 10))
	case marker == 0xd3:
		v, err := p.readU64()
		if err != nil {
			return err
		}
		writeString(out, strconv.FormatInt(int64(v), 10))
	case marker == 0xd4:
		return p.writeExtension(out, 1)
	case marker == 0xd5:
		return p.writeExtension(out, 2)
	case marker == 0xd6:
		return p.writeExtension(out, 4)
	case marker == 0xd7:
		return p.writeExtension(out, 8)
	case marker == 0xd8:
		return p.writeExtension(out, 16)
	case marker == 0xd9:
		length, err := p.readLen8()
		if err != nil {
			return err
		}
		return p.writeString(out, length)
	case marker == 0xda:
		length, err := p.readLen16()
		if err != nil {
			return err
		}
		return p.writeString(out, length)
	case marker == 0xdb:
		length, err := p.readLen32()
		if err != nil {
			return err
		}
		return p.writeString(out, length)
	case marker == 0xdc:
		length, err := p.readU16()
		if err != nil {
			return err
		}
		return p.writeArray(out, uint64(length), depth)
	case marker == 0xdd:
		length, err := p.readU32()
		if err != nil {
			return err
		}
		return p.writeArray(out, uint64(length), depth)
	case marker == 0xde:
		length, err := p.readU16()
		if err != nil {
			return err
		}
		return p.writeMap(out, uint64(length), depth)
	case marker == 0xdf:
		length, err := p.readU32()
		if err != nil {
			return err
		}
		return p.writeMap(out, uint64(length), depth)
	default: // negative fixint
		writeString(out, strconv.Itoa(int(int8(marker))))
	}
	return nil
}

func (p *msgPackParser) writeArray(out *bytes.Buffer, length uint64, depth int) error {
	writeString(out, "[")
	for i := uint64(0); i < length; i++ {
		if i != 0 {
			writeString(out, ",")
		}
		if err := p.writeValue(out, depth+1); err != nil {
			return err
		}
	}
	writeString(out, "]")
	return nil
}

func (p *msgPackParser) writeMap(out *bytes.Buffer, length uint64, depth int) error {
	writeString(out, "{")
	keys := make(map[string]struct{})
	for i := uint64(0); i < length; i++ {
		if i != 0 {
			writeString(out, ",")
		}
		key, err := p.writeMapKey(out, keys)
		if err != nil {
			return err
		}
		keys[key] = struct{}{}
		writeString(out, ":")
		if err := p.writeValue(out, depth+1); err != nil {
			return err
		}
	}
	writeString(out, "}")
	return nil
}

func (p *msgPackParser) writeMapKey(out *bytes.Buffer, keys map[string]struct{}) (string, error) {
	marker, err := p.readByte()
	if err != nil {
		return "", err
	}

	var key string
	switch {
	case marker <= 0x7f:
		key = strconv.Itoa(int(marker))
	case marker >= 0xe0:
		key = strconv.Itoa(int(int8(marker)))
	case marker >= 0xa0 && marker <= 0xbf:
		key, err = p.readTextKey(int(marker & 0x1f))
	case marker == 0xc4:
		length, e := p.readLen8()
		err = e
		if err == nil {
			key, err = p.readBinaryKey(length)
		}
	case marker == 0xc5:
		length, e := p.readLen16()
		err = e
		if err == nil {
			key, err = p.readBinaryKey(length)
		}
	case marker == 0xc6:
		length, e := p.readLen32()
		err = e
		if err == nil {
			key, err = p.readBinaryKey(length)
		}
	case marker == 0xd9 || marker == 0xda || marker == 0xdb:
		var length int
		if marker == 0xd9 {
			length, err = p.readLen8()
		} else if marker == 0xda {
			length, err = p.readLen16()
		} else {
			length, err = p.readLen32()
		}
		if err == nil {
			key, err = p.readTextKey(length)
		}
	case marker == 0xcc:
		v, e := p.readByte()
		err = e
		key = strconv.Itoa(int(v))
	case marker == 0xcd:
		v, e := p.readU16()
		err = e
		key = strconv.FormatUint(uint64(v), 10)
	case marker == 0xce:
		v, e := p.readU32()
		err = e
		key = strconv.FormatUint(uint64(v), 10)
	case marker == 0xcf:
		v, e := p.readU64()
		err = e
		key = strconv.FormatUint(v, 10)
	case marker == 0xd0:
		v, e := p.readByte()
		err = e
		key = strconv.Itoa(int(int8(v)))
	case marker == 0xd1:
		v, e := p.readU16()
		err = e
		key = strconv.Itoa(int(int16(v)))
	case marker == 0xd2:
		v, e := p.readU32()
		err = e
		key = strconv.FormatInt(int64(int32(v)), 10)
	case marker == 0xd3:
		v, e := p.readU64()
		err = e
		key = strconv.FormatInt(int64(v), 10)
	default:
		return "", errorsMsgPack("unsupported MessagePack map key type")
	}
	if err != nil {
		return "", err
	}
	if _, exists := keys[key]; exists {
		return "", errorsMsgPack("duplicate MessagePack map key after JSON conversion")
	}
	writeMsgPackJSONKey(out, key)
	return key, nil
}

func (p *msgPackParser) readTextKey(length int) (string, error) {
	b, err := p.readExact(length)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errorsMsgPack("invalid UTF-8 in MessagePack str")
	}
	return string(b), nil
}

func (p *msgPackParser) readBinaryKey(length int) (string, error) {
	b, err := p.readExact(length)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (p *msgPackParser) writeString(out *bytes.Buffer, length int) error {
	b, err := p.readExact(length)
	if err != nil {
		return err
	}
	if !utf8.Valid(b) {
		return errorsMsgPack("invalid UTF-8 in MessagePack str")
	}
	writeJSONValue(out, string(b))
	return nil
}

func (p *msgPackParser) writeBinary(out *bytes.Buffer, length int) error {
	b, err := p.readExact(length)
	if err != nil {
		return err
	}
	writeString(out, `"`+base64.StdEncoding.EncodeToString(b)+`"`)
	return nil
}

func (p *msgPackParser) writeExtension(out *bytes.Buffer, length int) error {
	typ, err := p.readByte()
	if err != nil {
		return err
	}
	b, err := p.readExact(length)
	if err != nil {
		return err
	}
	writeString(out, `{"type":`+strconv.Itoa(int(int8(typ)))+`,"data":"`+base64.StdEncoding.EncodeToString(b)+`"}`)
	return nil
}

func (p *msgPackParser) readByte() (byte, error) {
	if p.pos >= len(p.input) {
		return 0, errorsMsgPack("unexpected EOF while reading MessagePack")
	}
	v := p.input[p.pos]
	p.pos++
	return v, nil
}

func (p *msgPackParser) readU16() (uint16, error) {
	b, err := p.readExact(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (p *msgPackParser) readU32() (uint32, error) {
	b, err := p.readExact(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func (p *msgPackParser) readU64() (uint64, error) {
	b, err := p.readExact(8)
	if err != nil {
		return 0, err
	}
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), nil
}

func (p *msgPackParser) readLen8() (int, error) {
	v, err := p.readByte()
	return int(v), err
}

func (p *msgPackParser) readLen16() (int, error) {
	v, err := p.readU16()
	return int(v), err
}

func (p *msgPackParser) readLen32() (int, error) {
	v, err := p.readU32()
	if err != nil {
		return 0, err
	}
	if uint64(v) > uint64(^uint(0)>>1) {
		return 0, errorsMsgPack("MessagePack length overflows int")
	}
	return int(v), nil
}

func (p *msgPackParser) readExact(length int) ([]byte, error) {
	if length < 0 {
		return nil, errorsMsgPack("MessagePack length overflows int")
	}
	end := p.pos + length
	if end < p.pos || end > len(p.input) {
		return nil, errorsMsgPack("unexpected EOF while reading MessagePack")
	}
	b := p.input[p.pos:end]
	p.pos = end
	return b, nil
}

func writeString(out *bytes.Buffer, s string) { _, _ = out.WriteString(s) }

func writeJSONValue(out *bytes.Buffer, s string) {
	b, _ := json.Marshal(s) // s was validated as UTF-8 by the caller.
	_, _ = out.Write(b)
}

func writeMsgPackJSONKey(out *bytes.Buffer, s string) { writeJSONValue(out, s) }
