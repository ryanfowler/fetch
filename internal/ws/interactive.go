package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/format"

	"github.com/coder/websocket"
	"github.com/mattn/go-runewidth"
)

const (
	promptStr    = "❯ "
	minRows      = 5
	readBufSize  = 256
	stdinChanBuf = 64
	maxMessages  = 10000
)

var promptWidth = runewidth.StringWidth(promptStr)

// runInteractive enters interactive WebSocket mode with a scroll region for
// messages and a fixed input line at the bottom. Messages fill the scroll
// region from the top; once full, the region scrolls naturally.
func runInteractive(ctx context.Context, cfg Config) error {
	t := newTerminal()
	if err := t.enterRaw(); err != nil {
		return err
	}
	defer t.restore()

	rows, cols := t.size()
	if rows < minRows {
		// Terminal too small; fall back to read-only.
		t.restore()
		return readLoop(ctx, cfg)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	im := &interactiveMode{
		cfg:    cfg,
		term:   t,
		editor: &lineEditor{},
		cancel: cancel,
	}

	im.setupScreen(rows, cols)

	// Channel for raw stdin bytes.
	inputCh := make(chan []byte, stdinChanBuf)
	// Channel for server messages.
	type serverMsg struct {
		typ  websocket.MessageType
		data []byte
		err  error
	}
	msgCh := make(chan serverMsg, 16)
	// Channel for resize events.
	resizeCh := make(chan struct{}, 1)

	// Read raw stdin.
	go func() {
		buf := make([]byte, readBufSize)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				select {
				case inputCh <- b:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				close(inputCh)
				return
			}
		}
	}()

	// Read server messages.
	go func() {
		for {
			typ, data, err := cfg.Conn.Read(ctx)
			select {
			case msgCh <- serverMsg{typ, data, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Watch for terminal resize.
	go t.watchResize(ctx, resizeCh)

	// Send initial message from -d / -j flag.
	if len(cfg.InitialMsg) > 0 {
		err := cfg.Conn.Write(ctx, websocket.MessageText, cfg.InitialMsg)
		if err != nil && !errors.Is(err, context.Canceled) {
			im.teardownScreen()
			return err
		}
		im.renderSentMessage(cfg.InitialMsg)
	}

	// Pending buffer for partial UTF-8 / escape sequences.
	var pending []byte

	for {
		select {
		case raw, ok := <-inputCh:
			if !ok {
				im.teardownScreen()
				cancel()
				return nil
			}
			pending = append(pending, raw...)
			pending = im.handleInput(ctx, pending)

		case msg := <-msgCh:
			if msg.err != nil {
				im.teardownScreen()
				return handleReadErr(msg.err)
			}
			switch msg.typ {
			case websocket.MessageText:
				im.renderReceivedMessage(msg.data)
			case websocket.MessageBinary:
				im.renderBinaryIndicator(len(msg.data))
			}

		case <-resizeCh:
			rows, cols := t.size()
			if rows >= minRows {
				im.setupScreen(rows, cols)
			}

		case <-ctx.Done():
			im.teardownScreen()
			return nil
		}
	}
}

// messageEntry records a message for redraw.
type messageEntry struct {
	arrow string // "→" or "←"; empty for binary indicator
	data  []byte // message content; nil for binary indicator
	binN  int    // byte count for binary indicator
}

// interactiveMode holds the state for the interactive terminal UI.
type interactiveMode struct {
	cfg    Config
	term   *terminal
	editor *lineEditor
	cancel context.CancelFunc

	mu       sync.Mutex
	rows     int
	cols     int
	nextRow  int // next row to write a message in the scroll region (1-indexed)
	messages []messageEntry
}

// setupScreen configures the scroll region and draws the separators and input line.
// Layout: scroll region (1..N-3), separator (N-2), input (N-1), separator (N).
func (im *interactiveMode) setupScreen(rows, cols int) {
	im.mu.Lock()
	defer im.mu.Unlock()

	firstSetup := im.rows == 0

	im.rows = rows
	im.cols = cols

	scrollEnd := rows - 3

	// Clamp nextRow to the new scroll region.
	if im.nextRow == 0 {
		im.nextRow = 1
	}
	if im.nextRow > scrollEnd {
		im.nextRow = scrollEnd
	}

	if !firstSetup {
		// Reset scroll region and clear each row in place. Using
		// per-line EL (\x1b[2K) instead of ED (\x1b[2J) avoids
		// pushing the corrupted screen content into scrollback.
		// Messages are re-rendered from history after the chrome
		// is drawn.
		fmt.Fprint(os.Stdout, "\x1b[r")
		for r := 1; r <= rows; r++ {
			fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K", r)
		}
		im.nextRow = 1
	}

	if firstSetup {
		// Keep existing content (command/response info) visible at the
		// top of the screen. Query the current cursor row so new
		// messages start right after the existing output.
		curRow := im.term.cursorRow()

		if curRow >= scrollEnd {
			// Cursor is at or past the scroll region boundary (common
			// when the shell prompt was near the bottom). Push content
			// up into scrollback to make room for messages and the UI.
			shift := curRow - scrollEnd + 2
			fmt.Fprintf(os.Stdout, "\x1b[%d;1H", rows)
			for range shift {
				fmt.Fprint(os.Stdout, "\n")
			}
			curRow -= shift
		}

		if curRow > 0 {
			im.nextRow = min(curRow+1, scrollEnd)
		}

		// Clear the area below the existing content.
		for r := im.nextRow; r <= rows; r++ {
			fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K", r)
		}
	}

	// Set scroll region to top N-3 rows.
	fmt.Fprintf(os.Stdout, "\x1b[1;%dr", scrollEnd)

	im.drawSeparatorLocked(rows - 2)
	im.drawSeparatorLocked(rows)

	if !firstSetup {
		im.replayMessagesLocked()
	}

	im.drawInputLineLocked()
}

// replayMessagesLocked re-renders the most recent messages that fit
// in the current scroll region. Must be called with im.mu held and
// im.nextRow == 1.
func (im *interactiveMode) replayMessagesLocked() {
	if len(im.messages) == 0 {
		return
	}

	// Each message occupies ~2 rows (content + spacing).
	scrollEnd := im.rows - 3
	capacity := (scrollEnd + 1) / 2
	start := len(im.messages) - capacity
	if start < 0 {
		start = 0
	}

	for _, msg := range im.messages[start:] {
		if msg.data != nil {
			im.writeMessageLocked(msg.arrow, msg.data)
		} else {
			im.writeBinaryLocked(msg.binN)
		}
	}
}

// teardownScreen resets scroll region and moves cursor just below the
// last message, collapsing any empty space between messages and the
// separator/input line.
func (im *interactiveMode) teardownScreen() {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Reset scroll region to full terminal.
	fmt.Fprint(os.Stdout, "\x1b[r")

	// Clear the separators and input line.
	for _, row := range []int{im.rows - 2, im.rows - 1, im.rows} {
		fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K", row)
	}

	// Place cursor right after the last message.
	scrollEnd := im.rows - 3
	exitRow := min(im.nextRow, scrollEnd+1)
	fmt.Fprintf(os.Stdout, "\x1b[%d;1H", exitRow)
}

func (im *interactiveMode) drawSeparatorLocked(row int) {
	fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K\x1b[90m", row)
	for range im.cols {
		os.Stdout.WriteString("─")
	}
	fmt.Fprint(os.Stdout, "\x1b[0m")
}

func (im *interactiveMode) drawInputLineLocked() {
	inputRow := im.rows - 1
	text := im.editor.text()
	pos := im.editor.pos

	avail := max(im.cols-promptWidth, 1)

	runes := []rune(text)
	displayStart := 0

	widthToCursor := 0
	for i := range pos {
		widthToCursor += runewidth.RuneWidth(runes[i])
	}

	if widthToCursor >= avail {
		w := 0
		for i := pos - 1; i >= 0; i-- {
			w += runewidth.RuneWidth(runes[i])
			if w >= avail {
				displayStart = i + 1
				break
			}
		}
	}

	cursorCol := promptWidth
	for i := displayStart; i < pos; i++ {
		cursorCol += runewidth.RuneWidth(runes[i])
	}

	// Move to input row, clear, write prompt + visible text.
	fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K", inputRow)
	fmt.Fprintf(os.Stdout, "\x1b[1m%s\x1b[0m", promptStr)

	displayW := 0
	for i := displayStart; i < len(runes); i++ {
		rw := runewidth.RuneWidth(runes[i])
		if displayW+rw > avail {
			break
		}
		fmt.Fprintf(os.Stdout, "%c", runes[i])
		displayW += rw
	}

	fmt.Fprintf(os.Stdout, "\x1b[%d;%dH", inputRow, cursorCol+1)
}

// writeMessageLine positions the cursor for a new message line. If the scroll
// region is not yet full, the message is placed at nextRow (with a blank line
// after it for spacing). Once full, the region scrolls naturally.
func (im *interactiveMode) writeMessageLine() {
	scrollEnd := im.rows - 3

	if im.nextRow <= scrollEnd {
		// Space remaining — place the message directly.
		fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K", im.nextRow)
		// Reserve a blank line for spacing (if room allows).
		if im.nextRow+1 <= scrollEnd {
			im.nextRow += 2
		} else {
			im.nextRow++
		}
	} else {
		// Scroll region is full — scroll by writing at the bottom.
		fmt.Fprintf(os.Stdout, "\x1b[%d;1H\n\x1b[2K", scrollEnd)
	}
}

// renderSentMessage displays a sent message in the scroll region.
func (im *interactiveMode) renderSentMessage(data []byte) {
	im.renderMessage("→", data)
}

// renderReceivedMessage displays a received message in the scroll region.
func (im *interactiveMode) renderReceivedMessage(data []byte) {
	im.renderMessage("←", data)
}

func (im *interactiveMode) renderMessage(arrow string, data []byte) {
	im.mu.Lock()
	defer im.mu.Unlock()

	im.messages = append(im.messages, messageEntry{arrow: arrow, data: data})
	if len(im.messages) > maxMessages {
		im.messages = im.messages[len(im.messages)-maxMessages:]
	}
	im.writeMessageLocked(arrow, data)
	im.drawInputLineLocked()
}

// renderBinaryIndicator displays a binary message indicator.
func (im *interactiveMode) renderBinaryIndicator(n int) {
	im.mu.Lock()
	defer im.mu.Unlock()

	im.messages = append(im.messages, messageEntry{binN: n})
	if len(im.messages) > maxMessages {
		im.messages = im.messages[len(im.messages)-maxMessages:]
	}
	im.writeBinaryLocked(n)
	im.drawInputLineLocked()
}

func (im *interactiveMode) writeMessageLocked(arrow string, data []byte) {
	im.writeMessageLine()
	fmt.Fprintf(os.Stdout, "\x1b[2m%s \x1b[0m", arrow)
	im.writeFormattedMessage(data)
}

func (im *interactiveMode) writeBinaryLocked(n int) {
	im.writeMessageLine()
	fmt.Fprintf(os.Stdout, "\x1b[2m← [binary %d bytes]\x1b[0m", n)
}

func (im *interactiveMode) writeFormattedMessage(data []byte) {
	if shouldFormat(im.cfg.Format) && json.Valid(data) {
		p := im.cfg.Stdout
		if format.FormatJSONLine(data, p) == nil {
			p.Flush()
			return
		}
		p.Discard()
	}
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")
}

// handleInput processes accumulated raw bytes, returning any unconsumed bytes.
func (im *interactiveMode) handleInput(ctx context.Context, buf []byte) []byte {
	i := 0
	for i < len(buf) {
		b := buf[i]

		// Escape sequence.
		if b == 0x1b {
			consumed := im.handleEscape(buf[i:])
			if consumed == 0 {
				return buf[i:]
			}
			i += consumed
			continue
		}

		// Control characters.
		switch b {
		case 0x03, 0x04: // Ctrl+C, Ctrl+D
			im.cancel()
			return nil
		case 0x0D: // Enter
			im.sendMessage(ctx)
			i++
			continue
		case 0x7F, 0x08: // Backspace
			im.mu.Lock()
			im.editor.backspace()
			im.drawInputLineLocked()
			im.mu.Unlock()
			i++
			continue
		case 0x01: // Ctrl+A (Home)
			im.mu.Lock()
			im.editor.home()
			im.drawInputLineLocked()
			im.mu.Unlock()
			i++
			continue
		case 0x05: // Ctrl+E (End)
			im.mu.Lock()
			im.editor.end()
			im.drawInputLineLocked()
			im.mu.Unlock()
			i++
			continue
		case 0x15: // Ctrl+U (Clear line)
			im.mu.Lock()
			im.editor.clearLine()
			im.drawInputLineLocked()
			im.mu.Unlock()
			i++
			continue
		case 0x17: // Ctrl+W (Delete word)
			im.mu.Lock()
			im.editor.deleteWord()
			im.drawInputLineLocked()
			im.mu.Unlock()
			i++
			continue
		}

		// Printable character or UTF-8 leading byte.
		if b >= 0x20 {
			r, size := utf8.DecodeRune(buf[i:])
			if r == utf8.RuneError && size <= 1 {
				if !utf8.FullRune(buf[i:]) {
					return buf[i:]
				}
				i++
				continue
			}
			im.mu.Lock()
			im.editor.insert(r)
			im.drawInputLineLocked()
			im.mu.Unlock()
			i += size
			continue
		}

		// Unknown control character; skip.
		i++
	}
	return nil
}

// handleEscape processes an escape sequence starting at buf[0] == 0x1b.
// Returns the number of bytes consumed, or 0 if the sequence is incomplete.
func (im *interactiveMode) handleEscape(buf []byte) int {
	if len(buf) < 2 {
		return 0
	}

	if buf[1] != '[' {
		return 1
	}

	if len(buf) < 3 {
		return 0
	}

	switch buf[2] {
	case 'C': // Right arrow
		im.mu.Lock()
		im.editor.moveRight()
		im.drawInputLineLocked()
		im.mu.Unlock()
		return 3
	case 'D': // Left arrow
		im.mu.Lock()
		im.editor.moveLeft()
		im.drawInputLineLocked()
		im.mu.Unlock()
		return 3
	case 'H': // Home
		im.mu.Lock()
		im.editor.home()
		im.drawInputLineLocked()
		im.mu.Unlock()
		return 3
	case 'F': // End
		im.mu.Lock()
		im.editor.end()
		im.drawInputLineLocked()
		im.mu.Unlock()
		return 3
	case '3': // Delete (\x1b[3~)
		if len(buf) < 4 {
			return 0
		}
		if buf[3] == '~' {
			im.mu.Lock()
			im.editor.delete()
			im.drawInputLineLocked()
			im.mu.Unlock()
			return 4
		}
		return 3
	}

	// Unknown CSI sequence — consume up to the final byte.
	for j := 2; j < len(buf); j++ {
		if buf[j] >= 0x40 && buf[j] <= 0x7E {
			return j + 1
		}
	}
	return 0
}

// sendMessage sends the current editor contents as a WebSocket text message.
func (im *interactiveMode) sendMessage(ctx context.Context) {
	im.mu.Lock()
	text := im.editor.submit()
	im.drawInputLineLocked()
	im.mu.Unlock()

	if len(text) == 0 {
		return
	}

	data := []byte(text)
	err := im.cfg.Conn.Write(ctx, websocket.MessageText, data)
	if err != nil {
		// Restore the text so the user doesn't lose their input.
		im.mu.Lock()
		im.editor.setText(text)
		im.drawInputLineLocked()
		im.mu.Unlock()
		return
	}
	im.renderSentMessage(data)
}
