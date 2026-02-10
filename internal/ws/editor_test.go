package ws

import "testing"

func TestLineEditorInsert(t *testing.T) {
	e := &lineEditor{}
	e.insert('h')
	e.insert('i')
	if got := e.text(); got != "hi" {
		t.Fatalf("expected %q, got %q", "hi", got)
	}
	if e.pos != 2 {
		t.Fatalf("expected pos 2, got %d", e.pos)
	}
}

func TestLineEditorBackspace(t *testing.T) {
	e := &lineEditor{}
	e.insert('a')
	e.insert('b')
	e.insert('c')
	if !e.backspace() {
		t.Fatal("backspace should return true")
	}
	if got := e.text(); got != "ab" {
		t.Fatalf("expected %q, got %q", "ab", got)
	}

	// Backspace at position 0.
	e.home()
	if e.backspace() {
		t.Fatal("backspace at 0 should return false")
	}
}

func TestLineEditorDelete(t *testing.T) {
	e := &lineEditor{}
	e.insert('a')
	e.insert('b')
	e.insert('c')
	e.home()
	if !e.delete() {
		t.Fatal("delete should return true")
	}
	if got := e.text(); got != "bc" {
		t.Fatalf("expected %q, got %q", "bc", got)
	}

	// Delete at end.
	e.end()
	if e.delete() {
		t.Fatal("delete at end should return false")
	}
}

func TestLineEditorMovement(t *testing.T) {
	e := &lineEditor{}
	e.insert('a')
	e.insert('b')
	e.insert('c')

	if !e.moveLeft() {
		t.Fatal("moveLeft should return true")
	}
	if e.pos != 2 {
		t.Fatalf("expected pos 2, got %d", e.pos)
	}

	e.home()
	if e.pos != 0 {
		t.Fatalf("expected pos 0, got %d", e.pos)
	}
	if e.moveLeft() {
		t.Fatal("moveLeft at 0 should return false")
	}

	e.end()
	if e.pos != 3 {
		t.Fatalf("expected pos 3, got %d", e.pos)
	}
	if e.moveRight() {
		t.Fatal("moveRight at end should return false")
	}

	e.home()
	if !e.moveRight() {
		t.Fatal("moveRight should return true")
	}
	if e.pos != 1 {
		t.Fatalf("expected pos 1, got %d", e.pos)
	}
}

func TestLineEditorClearLine(t *testing.T) {
	e := &lineEditor{}
	e.insert('a')
	e.insert('b')
	e.clearLine()
	if got := e.text(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	if e.pos != 0 {
		t.Fatalf("expected pos 0, got %d", e.pos)
	}
}

func TestLineEditorDeleteWord(t *testing.T) {
	e := &lineEditor{}
	for _, r := range "hello world" {
		e.insert(r)
	}
	e.deleteWord()
	if got := e.text(); got != "hello " {
		t.Fatalf("expected %q, got %q", "hello ", got)
	}

	e.deleteWord()
	if got := e.text(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}

	// deleteWord at position 0 is a no-op.
	e.deleteWord()
	if got := e.text(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestLineEditorSubmit(t *testing.T) {
	e := &lineEditor{}
	for _, r := range "test" {
		e.insert(r)
	}
	s := e.submit()
	if s != "test" {
		t.Fatalf("expected %q, got %q", "test", s)
	}
	if got := e.text(); got != "" {
		t.Fatalf("expected empty after submit, got %q", got)
	}
	if e.pos != 0 {
		t.Fatalf("expected pos 0 after submit, got %d", e.pos)
	}
}

func TestLineEditorUnicode(t *testing.T) {
	e := &lineEditor{}
	e.insert('日')
	e.insert('本')
	e.insert('語')
	if got := e.text(); got != "日本語" {
		t.Fatalf("expected %q, got %q", "日本語", got)
	}
	e.moveLeft()
	e.backspace()
	if got := e.text(); got != "日語" {
		t.Fatalf("expected %q, got %q", "日語", got)
	}
}

func TestLineEditorInsertMiddle(t *testing.T) {
	e := &lineEditor{}
	e.insert('a')
	e.insert('c')
	e.moveLeft()
	e.insert('b')
	if got := e.text(); got != "abc" {
		t.Fatalf("expected %q, got %q", "abc", got)
	}
	if e.pos != 2 {
		t.Fatalf("expected pos 2, got %d", e.pos)
	}
}

func TestHandleEscapeArrows(t *testing.T) {
	im := &interactiveMode{
		editor: &lineEditor{},
		term:   &terminal{rows: 24, cols: 80},
		cfg:    Config{},
	}

	// Insert some text.
	im.editor.insert('a')
	im.editor.insert('b')
	im.editor.insert('c')

	// Left arrow: \x1b[D
	n := im.handleEscape([]byte{0x1b, '[', 'D'})
	if n != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", n)
	}
	if im.editor.pos != 2 {
		t.Fatalf("expected pos 2, got %d", im.editor.pos)
	}

	// Right arrow: \x1b[C
	n = im.handleEscape([]byte{0x1b, '[', 'C'})
	if n != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", n)
	}
	if im.editor.pos != 3 {
		t.Fatalf("expected pos 3, got %d", im.editor.pos)
	}

	// Home: \x1b[H
	n = im.handleEscape([]byte{0x1b, '[', 'H'})
	if n != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", n)
	}
	if im.editor.pos != 0 {
		t.Fatalf("expected pos 0, got %d", im.editor.pos)
	}

	// End: \x1b[F
	n = im.handleEscape([]byte{0x1b, '[', 'F'})
	if n != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", n)
	}
	if im.editor.pos != 3 {
		t.Fatalf("expected pos 3, got %d", im.editor.pos)
	}
}

func TestHandleEscapeDelete(t *testing.T) {
	im := &interactiveMode{
		editor: &lineEditor{},
		term:   &terminal{rows: 24, cols: 80},
		cfg:    Config{},
	}

	im.editor.insert('a')
	im.editor.insert('b')
	im.editor.home()

	// Delete: \x1b[3~
	n := im.handleEscape([]byte{0x1b, '[', '3', '~'})
	if n != 4 {
		t.Fatalf("expected 4 bytes consumed, got %d", n)
	}
	if got := im.editor.text(); got != "b" {
		t.Fatalf("expected %q, got %q", "b", got)
	}
}

func TestHandleEscapeIncomplete(t *testing.T) {
	im := &interactiveMode{
		editor: &lineEditor{},
		term:   &terminal{rows: 24, cols: 80},
		cfg:    Config{},
	}

	// Just ESC byte — incomplete.
	n := im.handleEscape([]byte{0x1b})
	if n != 0 {
		t.Fatalf("expected 0 for incomplete, got %d", n)
	}

	// ESC [ — incomplete CSI.
	n = im.handleEscape([]byte{0x1b, '['})
	if n != 0 {
		t.Fatalf("expected 0 for incomplete CSI, got %d", n)
	}

	// ESC [ 3 — incomplete delete sequence.
	n = im.handleEscape([]byte{0x1b, '[', '3'})
	if n != 0 {
		t.Fatalf("expected 0 for incomplete delete, got %d", n)
	}
}
