// Package wt contains the protocol-independent WebTransport session loop.
package wt

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/quic-go/webtransport-go"
	"github.com/ryanfowler/fetch/internal/core"
)

// Session is the small part of a WebTransport session needed by the CLI.
type Session interface {
	OpenStream(context.Context) (io.ReadWriteCloser, error)
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Close() error
}

type Config struct {
	Session           Session
	Stdin             io.Reader
	Stdout            io.Writer
	Mode              core.WTMode
	DatagramMode      core.WTDatagramMode
	InitialPayload    []byte
	InitialPayloadSet bool
	InitialReader     io.Reader
	TerminalOutput    bool
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.Session == nil || cfg.Stdout == nil {
		return errors.New("WebTransport session and stdout are required")
	}
	if cfg.Mode == core.WTDatagram {
		return runDatagrams(ctx, cfg)
	}
	return runStream(ctx, cfg)
}

type streamResult struct{ err error }

func runStream(ctx context.Context, cfg Config) error {
	stream, err := cfg.Session.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open WebTransport stream: %w", err)
	}
	defer stream.Close()
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-workCtx.Done():
			_ = cfg.Session.Close()
			closeInput(cfg.InitialReader)
			closeInput(cfg.Stdin)
		case <-stopWatch:
		}
	}()
	defer func() { close(stopWatch); <-watchDone }()
	writeDone := make(chan streamResult, 1)
	go func() {
		err := writeStream(workCtx, stream, cfg)
		if err != nil {
			_ = cfg.Session.Close()
			cancel()
		}
		writeDone <- streamResult{err}
	}()

	reader := io.Reader(stream)
	var output io.Writer = cfg.Stdout
	var safe *terminalWriter
	if cfg.TerminalOutput {
		safe = &terminalWriter{dst: cfg.Stdout}
		output = safe
	}
	buf := make([]byte, 32*1024)
	readErr := error(nil)
	for {
		n, read := reader.Read(buf)
		if n > 0 {
			if _, write := output.Write(buf[:n]); write != nil {
				readErr = write
				cancel()
				_ = cfg.Session.Close()
				break
			}
		}
		if read == io.EOF {
			break
		}
		if read != nil {
			readErr = read
			cancel()
			break
		}
	}
	if safe != nil && readErr == nil {
		readErr = safe.Flush()
	}
	write := (<-writeDone).err
	if readErr != nil && !isCleanClose(readErr) {
		_ = cfg.Session.Close()
		return fmt.Errorf("read WebTransport stream: %w", readErr)
	}
	if write != nil {
		_ = cfg.Session.Close()
		return write
	}
	return nil
}

func writeStream(ctx context.Context, stream io.WriteCloser, cfg Config) error {
	write := func(r io.Reader) error {
		if r == nil {
			return nil
		}
		_, err := io.CopyBuffer(stream, r, make([]byte, 32*1024))
		if err != nil {
			return fmt.Errorf("write WebTransport stream: %w", err)
		}
		return nil
	}
	if cfg.InitialPayloadSet {
		if _, err := stream.Write(cfg.InitialPayload); err != nil {
			return fmt.Errorf("write initial WebTransport payload: %w", err)
		}
	}
	if cfg.InitialReader != nil {
		if err := write(cfg.InitialReader); err != nil {
			closeInput(cfg.InitialReader)
			return err
		}
		closeInput(cfg.InitialReader)
	}
	if cfg.Stdin != nil {
		if err := writeContext(ctx, stream, cfg.Stdin); err != nil {
			closeInput(cfg.Stdin)
			return err
		}
		closeInput(cfg.Stdin)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close WebTransport stream: %w", err)
	}
	return nil
}

func writeContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, e := dst.Write(buf[:n]); e != nil {
				return e
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func runDatagrams(ctx context.Context, cfg Config) error {
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-workCtx.Done():
			_ = cfg.Session.Close()
			closeInput(cfg.InitialReader)
			closeInput(cfg.Stdin)
		case <-stopWatch:
		}
	}()
	defer func() { close(stopWatch); <-watchDone }()
	receiveDone := make(chan error, 1)
	go func() {
		err := receiveDatagrams(workCtx, cfg)
		cancel()
		receiveDone <- err
	}()

	var sendErr error
	if cfg.InitialPayloadSet {
		sendErr = sendDatagram(cfg.Session, cfg.InitialPayload)
	}
	if sendErr == nil && cfg.InitialReader != nil {
		data, err := core.ReadAllLimited(cfg.InitialReader, core.MaxCompositeMaterialization, "WebTransport initial datagram")
		closeInput(cfg.InitialReader)
		if err != nil {
			sendErr = err
		} else {
			sendErr = sendDatagram(cfg.Session, data)
		}
	}
	if sendErr == nil && cfg.Stdin != nil {
		sendErr = sendInputDatagrams(workCtx, cfg.Session, cfg.Stdin, cfg.DatagramMode)
		closeInput(cfg.Stdin)
	}
	if sendErr != nil {
		cancel()
		_ = cfg.Session.Close()
		<-receiveDone
		return sendErr
	}
	return normalizeDatagramClose(ctx, <-receiveDone)
}

func receiveDatagrams(ctx context.Context, cfg Config) error {
	seq := uint64(0)
	for {
		data, err := cfg.Session.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}
		record, _ := json.Marshal(struct {
			Sequence uint64 `json:"sequence"`
			Length   int    `json:"length"`
			Data     string `json:"data"`
		}{seq, len(data), base64.StdEncoding.EncodeToString(data)})
		record = append(record, '\n')
		if _, err := cfg.Stdout.Write(record); err != nil {
			_ = cfg.Session.Close()
			return err
		}
		seq++
	}
}

func isCleanClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}
	var streamErr *webtransport.StreamError
	if errors.As(err, &streamErr) && streamErr.ErrorCode == 0 {
		return true
	}
	var sessionErr *webtransport.SessionError
	return errors.As(err, &sessionErr) && sessionErr.ErrorCode == 0
}

func normalizeDatagramClose(parent context.Context, err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	if parent.Err() != nil {
		return context.Cause(parent)
	}
	var sessionErr *webtransport.SessionError
	if errors.As(err, &sessionErr) && sessionErr.ErrorCode == 0 {
		return nil
	}
	return err
}

func sendDatagram(s Session, data []byte) error {
	if err := s.SendDatagram(data); err != nil {
		return fmt.Errorf("send WebTransport datagram (%d bytes): %w", len(data), err)
	}
	return nil
}

func sendInputDatagrams(ctx context.Context, s Session, r io.Reader, mode core.WTDatagramMode) error {
	if mode == core.WTDatagramBinary {
		buf := make([]byte, core.MaxWebTransportBinaryChunk)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if e := sendDatagram(s, append([]byte(nil), buf[:n]...)); e != nil {
					return e
				}
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read WebTransport datagram input: %w", err)
			}
		}
	}
	br := bufio.NewReaderSize(r, int(core.MaxWebTransportDatagramLine)+1)
	for {
		line, err := readLine(br)
		if len(line) > int(core.MaxWebTransportDatagramLine) {
			return core.LimitError{Subsystem: "WebTransport datagram line", Limit: core.MaxWebTransportDatagramLine}
		}
		if len(line) > 0 || err != io.EOF {
			if e := sendDatagram(s, line); e != nil {
				return e
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read WebTransport datagram input: %w", err)
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, 128)
	for {
		part, err := r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > int(core.MaxWebTransportDatagramLine)+1 {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			if len(line) > 0 && line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			return line, err
		}
	}
}

func closeInput(r io.Reader) {
	if c, ok := r.(io.Closer); ok {
		_ = c.Close()
	}
}

// terminalWriter holds incomplete UTF-8 until the next read. All controls are
// escaped, so an attacker cannot create a terminal control sequence.
type terminalWriter struct {
	dst     io.Writer
	pending []byte
}

func (w *terminalWriter) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	cut := incompleteUTF8Start(w.pending)
	if cut < 0 {
		cut = len(w.pending)
	}
	if cut == 0 {
		return len(p), nil
	}
	out := core.AppendTerminalSafeBytes(nil, w.pending[:cut])
	if _, err := w.dst.Write(out); err != nil {
		return 0, err
	}
	w.pending = append(w.pending[:0], w.pending[cut:]...)
	return len(p), nil
}
func incompleteUTF8Start(p []byte) int {
	for i := len(p) - 1; i >= 0 && i >= len(p)-4; i-- {
		if !utf8.RuneStart(p[i]) {
			continue
		}
		if !utf8.FullRune(p[i:]) {
			return i
		}
		break
	}
	return -1
}

func (w *terminalWriter) Flush() error {
	if len(w.pending) == 0 {
		return nil
	}
	out := core.AppendTerminalSafeBytes(nil, w.pending)
	w.pending = nil
	_, err := w.dst.Write(out)
	return err
}
