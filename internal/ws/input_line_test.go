package ws

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	func() {
		defer func() { os.Stdout = previous }()
		fn()
	}()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func newTestInputMode(cols int) *interactiveMode {
	return &interactiveMode{
		term:     &terminal{rows: 24, cols: cols},
		rows:     24,
		cols:     cols,
		editor:   &lineEditor{},
		sendDone: make(chan sendResult, 1),
	}
}

func TestDrawInputLineScrollsToTheCursor(t *testing.T) {
	im := newTestInputMode(promptWidth + 5)
	im.editor.setText("abcdefghij")
	out := captureStdout(t, func() {
		im.mu.Lock()
		im.drawInputLineLocked()
		im.mu.Unlock()
	})
	// Five columns are available, and the cursor needs one of them, so the
	// last four characters are visible and the cursor follows them.
	if !strings.Contains(out, promptStr+"\x1b[0mghij\x1b[23;") {
		t.Fatalf("input line = %q, want the last four characters", out)
	}
	wantCursor := "\x1b[23;" + strconv.Itoa(promptWidth+4+1) + "H"
	if !strings.HasSuffix(out, wantCursor) {
		t.Fatalf("input line = %q, want the cursor at %q", out, wantCursor)
	}
}

// pasteInChunks feeds input to handleInput in read-sized chunks, as the
// terminal reader does, and returns the time it took.
func pasteInChunks(t *testing.T, im *interactiveMode, input []byte) time.Duration {
	t.Helper()
	var elapsed time.Duration
	captureStdout(t, func() {
		start := time.Now()
		var pending []byte
		for len(input) > 0 {
			n := min(len(input), readBufSize)
			pending = im.handleInput(context.Background(), append(pending, input[:n]...))
			input = input[n:]
		}
		elapsed = time.Since(start)
	})
	return elapsed
}

func TestLargePasteIsFast(t *testing.T) {
	// Each pasted character used to redraw the whole line, so a paste took
	// time with the square of its length.
	for name, test := range map[string]struct {
		text   string
		midway bool
	}{
		"at the end":       {text: strings.Repeat("x", 200_000)},
		"in the middle":    {text: strings.Repeat("x", 100_000), midway: true},
		"zero-width runes": {text: strings.Repeat("a\u0301\u200b", 40_000)},
	} {
		t.Run(name, func(t *testing.T) {
			im := newTestInputMode(80)
			if test.midway {
				im.editor.setText("start end")
				im.editor.pos = len("start ")
			}
			elapsed := pasteInChunks(t, im, []byte(test.text))
			if elapsed > 2*time.Second {
				t.Fatalf("pasting took %v", elapsed)
			}
			want := len([]rune(test.text))
			if test.midway {
				want += len("start end")
				if got := string(im.editor.buf); !strings.HasPrefix(got, "start x") || !strings.HasSuffix(got, "xend") {
					t.Fatalf("paste was not inserted at the cursor")
				}
			}
			if got := len(im.editor.buf); got != want {
				t.Fatalf("editor has %d runes, want %d", got, want)
			}
		})
	}
}

func TestHandleInputBatches(t *testing.T) {
	im := newTestInputMode(80)
	// A rune that is split across two reads is completed by the next one.
	euro := []byte("€")
	var rest []byte
	captureStdout(t, func() {
		rest = im.handleInput(context.Background(), append([]byte("ab"), euro[:2]...))
	})
	if string(im.editor.buf) != "ab" || len(rest) != 2 {
		t.Fatalf("editor = %q, rest = %q; want ab and the partial rune", string(im.editor.buf), rest)
	}
	captureStdout(t, func() {
		im.handleInput(context.Background(), append(rest, euro[2:]...))
	})
	if string(im.editor.buf) != "ab€" {
		t.Fatalf("editor = %q, want ab€", string(im.editor.buf))
	}

	// Invalid bytes and C1 controls are dropped; DEL ends the batch and
	// deletes a rune.
	captureStdout(t, func() {
		im.handleInput(context.Background(), []byte("c\xffd\u0085e\x7f"))
	})
	if got := string(im.editor.buf); got != "ab€cd" {
		t.Fatalf("editor = %q, want ab€cd", got)
	}

	// Runes past the size limit are refused.
	im.editor.byteLen = int(core.MaxWebSocketInteractiveEntry) - 1
	captureStdout(t, func() {
		im.handleInput(context.Background(), []byte("fg"))
	})
	if got := string(im.editor.buf); got != "ab€cdf" || !im.editor.limitReached {
		t.Fatalf("editor = %q, limit = %t; want one more rune and the limit", got, im.editor.limitReached)
	}
}

func TestDrawInputLineMatchesTheVisibleWindow(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		pos     int
		cols    int
		visible string
		cursor  int // column after the prompt
	}{
		{name: "short text", text: "abc", pos: 3, cols: 20, visible: "abc", cursor: 3},
		{name: "cursor at start", text: "abcdefghij", pos: 0, cols: 5, visible: "abcde", cursor: 0},
		{name: "cursor in the middle", text: "abcdefghij", pos: 7, cols: 5, visible: "defgh", cursor: 4},
		// Six columns are available, and the cursor needs one of them.
		{name: "wide runes", text: "日本語テキスト", pos: 7, cols: 6, visible: "スト", cursor: 4},
		{name: "one column", text: "abc", pos: 3, cols: 1, visible: "", cursor: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			im := newTestInputMode(promptWidth + test.cols)
			im.editor.setText(test.text)
			im.editor.pos = test.pos
			out := captureStdout(t, func() {
				im.mu.Lock()
				im.drawInputLineLocked()
				im.mu.Unlock()
			})
			wantText := promptStr + "\x1b[0m" + test.visible + "\x1b[23;"
			wantCursor := "\x1b[23;" + strconv.Itoa(promptWidth+test.cursor+1) + "H"
			if !strings.Contains(out, wantText) || !strings.HasSuffix(out, wantCursor) {
				t.Fatalf("input line = %q, want %q and %q", out, test.visible, wantCursor)
			}
		})
	}
}
