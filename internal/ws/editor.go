package ws

// lineEditor is a simple line editor with cursor positioning.
// It operates purely on rune data with no terminal I/O.
type lineEditor struct {
	buf []rune
	pos int // cursor position (0..len(buf))
}

func (e *lineEditor) insert(r rune) {
	e.buf = append(e.buf, 0)
	copy(e.buf[e.pos+1:], e.buf[e.pos:])
	e.buf[e.pos] = r
	e.pos++
}

func (e *lineEditor) backspace() bool {
	if e.pos == 0 {
		return false
	}
	e.pos--
	e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	return true
}

func (e *lineEditor) delete() bool {
	if e.pos >= len(e.buf) {
		return false
	}
	e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
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
}

func (e *lineEditor) deleteWord() {
	if e.pos == 0 {
		return
	}
	// Skip trailing spaces.
	for e.pos > 0 && e.buf[e.pos-1] == ' ' {
		e.pos--
		e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	}
	// Delete until next space or beginning.
	for e.pos > 0 && e.buf[e.pos-1] != ' ' {
		e.pos--
		e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	}
}

func (e *lineEditor) submit() string {
	s := string(e.buf)
	e.buf = e.buf[:0]
	e.pos = 0
	return s
}

func (e *lineEditor) text() string {
	return string(e.buf)
}

func (e *lineEditor) setText(s string) {
	e.buf = []rune(s)
	e.pos = len(e.buf)
}
