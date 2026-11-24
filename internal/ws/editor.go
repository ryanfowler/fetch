package ws

import (
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

// lineEditor is a simple line editor with cursor positioning.
// It operates purely on rune data with no terminal I/O.
type lineEditor struct {
	buf          []rune
	pos          int // cursor position (0..len(buf))
	byteLen      int
	limitReached bool
}

func (e *lineEditor) insert(r rune) {
	e.buf = append(e.buf, 0)
	copy(e.buf[e.pos+1:], e.buf[e.pos:])
	e.buf[e.pos] = r
	e.pos++
	e.byteLen += utf8.RuneLen(r)
}

// insertRunes inserts runes at the cursor with one copy of the text after
// the cursor, so that a paste into the middle of a line takes linear time.
func (e *lineEditor) insertRunes(runes []rune) {
	if len(runes) == 0 {
		return
	}
	tail := len(e.buf) - e.pos
	e.buf = append(e.buf, runes...)
	copy(e.buf[e.pos+len(runes):], e.buf[e.pos:e.pos+tail])
	copy(e.buf[e.pos:], runes)
	e.pos += len(runes)
	for _, r := range runes {
		e.byteLen += utf8.RuneLen(r)
	}
}

func (e *lineEditor) backspace() bool {
	if e.pos == 0 {
		return false
	}
	e.pos--
	e.byteLen -= utf8.RuneLen(e.buf[e.pos])
	e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	if e.byteLen < 0 {
		e.byteLen = len(string(e.buf))
	}
	if e.byteLen < int(core.MaxWebSocketInteractiveEntry) {
		e.limitReached = false
	}
	return true
}

func (e *lineEditor) delete() bool {
	if e.pos >= len(e.buf) {
		return false
	}
	e.byteLen -= utf8.RuneLen(e.buf[e.pos])
	e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	if e.byteLen < 0 {
		e.byteLen = len(string(e.buf))
	}
	if e.byteLen < int(core.MaxWebSocketInteractiveEntry) {
		e.limitReached = false
	}
	return true
}

func (e *lineEditor) moveLeft() bool {
	if e.pos == 0 {
		return false
	}
	e.pos--
	return true
}

func (e *lineEditor) moveRight() bool {
	if e.pos >= len(e.buf) {
		return false
	}
	e.pos++
	return true
}

func (e *lineEditor) home() {
	e.pos = 0
}

func (e *lineEditor) end() {
	e.pos = len(e.buf)
}

func (e *lineEditor) clearLine() {
	e.buf = e.buf[:0]
	e.pos = 0
	e.byteLen = 0
	e.limitReached = false
}

func (e *lineEditor) deleteWord() {
	if e.pos == 0 {
		return
	}
	// Use the bounded mutation helpers so byte accounting stays correct.
	for e.pos > 0 && e.buf[e.pos-1] == ' ' {
		e.backspace()
	}
	for e.pos > 0 && e.buf[e.pos-1] != ' ' {
		e.backspace()
	}
}

func (e *lineEditor) submit() string {
	s := string(e.buf)
	e.buf = e.buf[:0]
	e.pos = 0
	e.byteLen = 0
	e.limitReached = false
	return s
}

func (e *lineEditor) text() string {
	return string(e.buf)
}

func (e *lineEditor) setText(s string) {
	e.buf = []rune(s)
	e.pos = len(e.buf)
	e.byteLen = len(s)
	e.limitReached = false
}
