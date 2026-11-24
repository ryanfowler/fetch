package ws

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/format"

	"github.com/coder/websocket"
	"github.com/mattn/go-runewidth"
)

const (
	promptStr    = "❯ "
	minRows      = 5
	readBufSize  = 256
	stdinChanBuf = 64
	// History is a redraw aid, not a transcript store. Keep it byte bounded
	// so a peer cannot make an interactive session retain many large frames.
	maxHistoryBytes = 1 << 20
	maxPendingInput = 4 * readBufSize
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
	// Restore the terminal before stdin is closed. When no read is in
	// progress, Close releases the descriptor at once, and a restore after
	// it would fail and leave the terminal in raw mode. Deferred calls run
	// in reverse order, so the session is cancelled before this runs.
	defer t.restoreAndClose(os.Stdin)

	rows, cols := t.size()
	if rows < minRows {
		// Terminal too small; fall back to read-only.
		t.restore()
		if err := sendInitialMessage(ctx, &cfg); err != nil {
			return err
		}
		return readLoop(ctx, cfg)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	im := &interactiveMode{
		cfg:      cfg,
		term:     t,
		editor:   &lineEditor{},
		cancel:   cancel,
		status:   "connected",
		sendDone: make(chan sendResult, 1),
	}

	// The input channel is intentionally small. The reader blocks instead of
	// accumulating terminal input while rendering is busy.
	inputCh := make(chan []byte, stdinChanBuf)
	inputErr := make(chan error, 1)
	msgQueue := newMessageQueue()
	resizeCh := make(chan struct{}, 1)

	go func() {
		buf := make([]byte, readBufSize)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				b := append([]byte(nil), buf[:n]...)
				select {
				case inputCh <- b:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					inputErr <- fmt.Errorf("read WebSocket terminal input: %w", err)
				}
				close(inputCh)
				return
			}
		}
	}()

	initialRow, pending := detectCursorRow(inputCh)
	im.setupScreen(rows, cols, initialRow)

	// There is exactly one connection reader. messageQueue applies a byte
	// budget before this goroutine accepts another complete message.
	go func() {
		for {
			typ, data, err := cfg.Conn.Read(ctx)
			if msgQueue.push(ctx, wsMessage{typ: typ, data: data, err: err}) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	}()

	go t.watchResize(ctx, resizeCh)

	// Join a write that is still running when the session ends. Deferred
	// calls run in reverse order, so this runs before the deferred cancel.
	defer func() {
		if im.sending {
			cancel()
			<-im.sendDone
		}
	}()

	initialType, initialData, hasInitial, err := initialMessage(&cfg)
	if err != nil {
		im.teardownScreen()
		return err
	}
	if hasInitial {
		im.startSend(ctx, sendResult{typ: initialType, data: initialData, initial: true})
	}

	var inputSource <-chan []byte = inputCh
	var inputError <-chan error = inputErr
	var closeDone <-chan error
	for {
		// Do not show received messages while a write runs. A reply must
		// not appear above the message that caused it. The queue applies
		// backpressure meanwhile.
		received := msgQueue.C()
		if im.sending {
			received = nil
		}
		select {
		case err := <-inputError:
			inputError = nil
			im.teardownScreen()
			cancel()
			_ = cfg.Conn.CloseNow()
			return err
		case raw, ok := <-inputSource:
			if !ok {
				im.localEOF = true
				inputSource = nil
			} else {
				pending = append(pending, raw...)
				if len(pending) > maxPendingInput {
					pending = pending[len(pending)-maxPendingInput:]
				}
				pending = im.handleInput(ctx, pending)
			}
			if im.localEOF && closeDone == nil {
				if im.sending {
					// Close after the write. Ctrl+C still ends the
					// session if the peer never reads the message.
					im.setStatus("closing after the message is sent")
				} else {
					closeDone = startNormalClose(cfg.Conn)
				}
			}

		case <-received:
			msg := msgQueue.pop()
			if msg.err != nil {
				im.teardownScreen()
				cancel()
				return handleReadErr(msg.err)
			}
			switch msg.typ {
			case websocket.MessageText:
				im.renderReceivedMessage(msg.data)
			case websocket.MessageBinary:
				im.renderBinaryIndicator(len(msg.data))
			}

		case result := <-im.sendDone:
			if err := im.finishSend(result); err != nil {
				im.teardownScreen()
				cancel()
				_ = cfg.Conn.CloseNow()
				return err
			}
			if im.localEOF && closeDone == nil {
				closeDone = startNormalClose(cfg.Conn)
			}

		case <-resizeCh:
			rows, cols := t.size()
			if rows >= minRows {
				im.setupScreen(rows, cols, 0)
			} else {
				im.teardownScreen()
				cancel()
				_ = cfg.Conn.CloseNow()
				return nil
			}

		case err := <-closeDone:
			im.teardownScreen()
			cancel()
			return normalizeCloseError(err)

		case <-ctx.Done():
			im.teardownScreen()
			_ = cfg.Conn.CloseNow()
			return contextTerminationError(ctx)
		}
	}
}

const localCloseDrainDelay = 50 * time.Millisecond

func startNormalClose(conn *websocket.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		timer := time.NewTimer(localCloseDrainDelay)
		defer timer.Stop()
		<-timer.C
		done <- conn.Close(websocket.StatusNormalClosure, "")
	}()
	return done
}

func detectCursorRow(inputCh <-chan []byte) (int, []byte) {
	return detectCursorRowWithTimeout(inputCh, time.Second)
}

func detectCursorRowWithTimeout(inputCh <-chan []byte, timeoutDur time.Duration) (int, []byte) {
	fmt.Fprint(os.Stdout, "\x1b[6n")

	timeout := time.NewTimer(timeoutDur)
	defer timeout.Stop()

	var captured []byte
	for {
		if row, remaining, ok := extractCursorRow(captured); ok {
			if row <= 0 {
				row = 1
			}
			return row, remaining
		}

		select {
		case raw, ok := <-inputCh:
			if !ok {
				return 1, captured
			}
			captured = append(captured, raw...)
		case <-timeout.C:
			return 1, captured
		}
	}
}

// messageEntry records a message for redraw.
type messageEntry struct {
	arrow  string // "→" or "←"; empty for binary indicator
	data   []byte // message content, including an empty text message
	binN   int    // byte count for binary indicator
	binary bool
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
	status   string
	messages []messageEntry
	// localEOF requests a normal close after Ctrl-D or stdin EOF. It is
	// separate from cancel so the close handshake can finish first.
	localEOF     bool
	historyBytes int64

	// sending is true while a write runs on its own goroutine. Only the
	// session goroutine reads or writes it. sendDone receives the result
	// of that write.
	sending  bool
	sendDone chan sendResult
}

// sendResult describes one interactive WebSocket write and its result.
type sendResult struct {
	typ  websocket.MessageType
	data []byte
	// text is the editor text to restore if the write fails. It is empty
	// for the initial message.
	text string
	// initial is true for the initial message. Its failure ends the
	// session, as in non-interactive mode.
	initial bool
	err     error
}

// setupScreen configures the scroll region and draws the separators and input line.
// Layout: scroll region (1..N-3), status (N-2), input (N-1), separator (N).
func (im *interactiveMode) setupScreen(rows, cols, initialCursorRow int) {
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
		curRow := initialCursorRow
		if curRow <= 0 {
			curRow = 1
		}

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

	im.drawStatusLocked()
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

	scrollEnd := im.rows - 3
	start := len(im.messages)
	used := 0
	for i := len(im.messages) - 1; i >= 0; i-- {
		rows := im.messageRowCount(im.messages[i])
		if used+rows > scrollEnd && start != len(im.messages) {
			break
		}
		used += rows
		start = i
	}

	for _, msg := range im.messages[start:] {
		if msg.binary {
			im.writeBinaryLocked(msg.arrow, msg.binN)
		} else {
			im.writeMessageLocked(msg.arrow, msg.data)
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

func (im *interactiveMode) drawStatusLocked() {
	row := im.rows - 2
	status := strings.ReplaceAll(sanitizeMessageText(im.status), "\n", " ")
	msg := fitDisplayWidth(status, im.cols)
	fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K\x1b[90m%s\x1b[0m", row, msg)
}

// drawInputLineLocked draws the visible part of the input line. Its work
// depends on the terminal width, not on the length of the line, and it
// writes the line with one write.
func (im *interactiveMode) drawInputLineLocked() {
	inputRow := im.rows - 1
	runes := im.editor.buf
	pos := im.editor.pos

	avail := max(im.cols-promptWidth, 1)

	// Show the text before the cursor that fits; scroll when it does not.
	// Zero-width runes, such as combining marks, never fill the line, so
	// the scan is also limited to a number of runes.
	maxRunes := 4*avail + 16
	displayStart := 0
	widthBeforeCursor := 0
	for i := pos - 1; i >= 0; i-- {
		widthBeforeCursor += runewidth.RuneWidth(runes[i])
		if widthBeforeCursor >= avail || pos-i >= maxRunes {
			displayStart = i + 1
			break
		}
	}

	cursorCol := promptWidth
	for i := displayStart; i < pos; i++ {
		cursorCol += runewidth.RuneWidth(runes[i])
	}

	// Move to input row, clear, write prompt + visible text.
	var line strings.Builder
	fmt.Fprintf(&line, "\x1b[%d;1H\x1b[2K", inputRow)
	fmt.Fprintf(&line, "\x1b[1m%s\x1b[0m", promptStr)

	displayW := 0
	for i := displayStart; i < len(runes) && i-displayStart < maxRunes; i++ {
		rw := runewidth.RuneWidth(runes[i])
		if displayW+rw > avail {
			break
		}
		line.WriteRune(runes[i])
		displayW += rw
	}

	fmt.Fprintf(&line, "\x1b[%d;%dH", inputRow, cursorCol+1)
	_, _ = io.WriteString(os.Stdout, line.String())
}

// writePhysicalLine positions the cursor for one rendered message row. Once
// the scroll region is full, the region scrolls naturally.
func (im *interactiveMode) writePhysicalLine() {
	scrollEnd := im.rows - 3

	if im.nextRow <= scrollEnd {
		fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K", im.nextRow)
		im.nextRow++
	} else {
		// Scroll region is full — scroll by writing at the bottom.
		fmt.Fprintf(os.Stdout, "\x1b[%d;1H\n\x1b[2K", scrollEnd)
	}
}

func (im *interactiveMode) writeMessageSpacer() {
	if im.nextRow <= im.rows-3 {
		im.writePhysicalLine()
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

	im.retainMessageLocked(messageEntry{arrow: arrow, data: data})
	im.writeMessageLocked(arrow, data)
	im.drawInputLineLocked()
}

// renderBinaryIndicator displays a received binary message indicator.
func (im *interactiveMode) renderBinaryIndicator(n int) {
	im.renderBinaryIndicatorWithArrow("←", n)
}

func (im *interactiveMode) renderSentBinaryIndicator(n int) {
	im.renderBinaryIndicatorWithArrow("→", n)
}

func (im *interactiveMode) renderBinaryIndicatorWithArrow(arrow string, n int) {
	im.mu.Lock()
	defer im.mu.Unlock()

	// A binary message is represented by a small indicator in history, not
	// by retaining its payload.
	im.retainMessageLocked(messageEntry{arrow: arrow, binN: n, binary: true})
	im.writeBinaryLocked(arrow, n)
	im.drawInputLineLocked()
}

func (im *interactiveMode) retainMessageLocked(msg messageEntry) {
	entryBytes := int64(len(msg.data))
	if entryBytes > maxHistoryBytes {
		return
	}
	if msg.binary {
		// Keep a bounded accounting unit for binary indicators.
		entryBytes = 32
	} else {
		msg.data = append([]byte(nil), msg.data...)
	}
	im.messages = append(im.messages, msg)
	im.historyBytes += entryBytes
	for im.historyBytes > maxHistoryBytes && len(im.messages) > 0 {
		old := im.messages[0]
		im.messages = im.messages[1:]
		if old.binary {
			im.historyBytes -= 32
		} else {
			im.historyBytes -= int64(len(old.data))
		}
	}
}

func (im *interactiveMode) writeMessageLocked(arrow string, data []byte) {
	prefix := arrow + " "
	continuation := "  "
	width := max(im.cols-runewidth.StringWidth(prefix), 1)
	lines := wrapDisplayLines(im.formatMessage(data), width)
	for i, line := range lines {
		im.writePhysicalLine()
		if i == 0 {
			fmt.Fprintf(os.Stdout, "\x1b[2m%s\x1b[0m", prefix)
		} else {
			fmt.Fprint(os.Stdout, continuation)
		}
		fmt.Fprint(os.Stdout, line)
	}
	im.writeMessageSpacer()
}

func (im *interactiveMode) writeBinaryLocked(arrow string, n int) {
	if arrow == "" {
		arrow = "←"
	}
	im.writePhysicalLine()
	fmt.Fprintf(os.Stdout, "\x1b[2m%s [binary %d bytes]\x1b[0m", arrow, n)
	im.writeMessageSpacer()
}

func (im *interactiveMode) formatMessage(data []byte) string {
	if shouldFormat(im.cfg.Format) && jsontext.Value(data).IsValid() {
		p := core.TestPrinter(false)
		if format.FormatJSONLine(data, p) == nil {
			_ = p.Flush()
			return sanitizeMessageText(strings.TrimSuffix(string(p.Bytes()), "\n"))
		}
	}
	return sanitizeMessageText(string(data))
}

func (im *interactiveMode) messageRowCount(msg messageEntry) int {
	if msg.binary {
		return 2
	}
	prefixWidth := runewidth.StringWidth(msg.arrow + " ")
	width := max(im.cols-prefixWidth, 1)
	return len(wrapDisplayLines(im.formatMessage(msg.data), width)) + 1
}

func sanitizeMessageText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(core.TerminalSafeText(s), "\t", "    ")
}

func wrapDisplayLines(s string, width int) []string {
	if width < 1 {
		width = 1
	}

	parts := strings.Split(s, "\n")
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			lines = append(lines, "")
			continue
		}

		var line strings.Builder
		lineWidth := 0
		for _, r := range part {
			rw := runewidth.RuneWidth(r)
			if rw < 1 {
				rw = 1
			}
			if lineWidth > 0 && lineWidth+rw > width {
				lines = append(lines, line.String())
				line.Reset()
				lineWidth = 0
			}
			line.WriteRune(r)
			lineWidth += rw
		}
		lines = append(lines, line.String())
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func fitDisplayWidth(s string, width int) string {
	if width < 1 {
		return ""
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := runewidth.RuneWidth(r)
		if rw < 1 {
			rw = 1
		}
		if used+rw > width {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String()
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
		case 0x03: // Ctrl+C
			im.cancel()
			return nil
		case 0x04: // Ctrl+D
			im.localEOF = true
			return buf[i+1:]
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

		// Printable characters or UTF-8 leading bytes. Insert the whole run,
		// such as a paste, and then draw the input line once.
		if b >= 0x20 {
			im.mu.Lock()
			var runes []rune
			var rest []byte
			byteLen := int64(im.editor.byteLen)
			overLimit := false
			for i < len(buf) && buf[i] >= 0x20 && buf[i] != 0x7f {
				r, size := utf8.DecodeRune(buf[i:])
				if r == utf8.RuneError && size <= 1 {
					if !utf8.FullRune(buf[i:]) {
						rest = buf[i:]
						break
					}
					i++
					continue
				}
				i += size
				if unicode.IsControl(r) {
					// A C1 control character, which a terminal would
					// interpret. Received messages are filtered the same way.
					continue
				}
				if byteLen+int64(utf8.RuneLen(r)) > core.MaxWebSocketInteractiveEntry {
					overLimit = true
					continue
				}
				byteLen += int64(utf8.RuneLen(r))
				runes = append(runes, r)
			}
			if len(runes) > 0 {
				im.editor.insertRunes(runes)
				im.drawInputLineLocked()
			}
			if overLimit {
				im.editor.limitReached = true
				im.status = "message exceeds 16 MiB limit"
				im.drawStatusLocked()
			}
			im.mu.Unlock()
			if rest != nil {
				return rest
			}
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

// sendMessage sends the current editor contents using the configured message
// mode. Interactive input is always valid UTF-8 because it comes from runes.
func (im *interactiveMode) sendMessage(ctx context.Context) {
	im.mu.Lock()
	if im.localEOF {
		im.status = "closing; new messages are not sent"
		im.drawStatusLocked()
		im.mu.Unlock()
		return
	}
	if im.sending {
		// Keep the text in the editor. The user can press Enter again when
		// the previous write has finished.
		im.status = "previous message is still sending"
		im.drawStatusLocked()
		im.mu.Unlock()
		return
	}
	if im.editor.limitReached {
		im.status = "message exceeds 16 MiB limit"
		im.drawStatusLocked()
		im.mu.Unlock()
		return
	}
	text := im.editor.submit()
	im.drawInputLineLocked()
	im.mu.Unlock()

	// An empty entry is a valid interactive text message. This also keeps
	// interactive input consistent with empty piped lines.
	data := []byte(text)
	typ, typeErr := initialMessageType(im.cfg.MessageMode, data)
	if typeErr != nil {
		im.mu.Lock()
		im.status = "send failed: " + typeErr.Error()
		im.editor.setText(text)
		im.drawStatusLocked()
		im.drawInputLineLocked()
		im.mu.Unlock()
		return
	}
	im.startSend(ctx, sendResult{typ: typ, data: data, text: text})
}

// startSend writes msg on another goroutine and delivers the result to
// im.sendDone. A peer that does not read can block the write until the
// context ends. The session goroutine must keep handling input meanwhile,
// so Ctrl+C can cancel the session and stop the write.
func (im *interactiveMode) startSend(ctx context.Context, msg sendResult) {
	im.sending = true
	go func() {
		msg.err = im.cfg.Conn.Write(ctx, msg.typ, msg.data)
		im.sendDone <- msg
	}()
}

// finishSend shows the result of a write that startSend started. It returns
// an error only when the initial message fails, which ends the session.
func (im *interactiveMode) finishSend(result sendResult) error {
	im.sending = false
	if result.err != nil {
		if result.initial {
			return initialWriteError(result.err)
		}
		im.mu.Lock()
		if len(im.editor.buf) == 0 {
			// Restore the text so the user doesn't lose their input.
			im.status = "send failed: " + result.err.Error()
			im.editor.setText(result.text)
		} else {
			im.status = "send failed, message discarded: " + result.err.Error()
		}
		im.drawStatusLocked()
		im.drawInputLineLocked()
		im.mu.Unlock()
		return nil
	}
	if !result.initial {
		im.setStatus(fmt.Sprintf("sent %d bytes", len(result.data)))
	}
	if result.typ == websocket.MessageBinary {
		im.renderSentBinaryIndicator(len(result.data))
	} else {
		im.renderSentMessage(result.data)
	}
	return nil
}

// setStatus replaces the status line.
func (im *interactiveMode) setStatus(status string) {
	im.mu.Lock()
	im.status = status
	im.drawStatusLocked()
	im.mu.Unlock()
}
