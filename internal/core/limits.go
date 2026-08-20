package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"
)

// Shared resource limits. Keep feature-specific limits here so callers and
// tests use the same security boundary instead of duplicating constants.
const (
	MaxArticleBodyBytes          int64 = 16 << 20
	MaxReadabilityElements             = 500_000
	MaxHARRequestBodyBytes       int64 = 16 << 20
	MaxHARResponseBodyBytes      int64 = 16 << 20
	MaxWebSocketMessageBytes     int64 = 16 << 20
	MaxWebSocketPipedTextLine    int64 = 16 << 20
	MaxWebSocketInteractiveEntry int64 = 16 << 20
	MaxStreamingRecordBytes      int64 = 16 << 20
	MaxCompositeMaterialization  int64 = 16 << 20
	MaxGRPCMessageBytes          int64 = 64 << 20
	MaxReflectionMessages              = 128
	MaxReflectionBytes           int64 = 64 << 20
	MaxNestingDepth                    = 128
	MaxClipboardBytes            int64 = 1 << 20
	MaxDOHWireResponseBytes      int64 = 65_535
	MaxDOHJSONResponseBytes      int64 = 1 << 20
	MaxUpdaterReleaseMetadata    int64 = 1 << 20
	MaxUpdaterChecksumSidecar    int64 = 1 << 10
	MaxUpdaterArtifact           int64 = 128 << 20
	MaxUpdaterUnpackedData       int64 = 512 << 20
	MaxUpdaterArchiveEntries           = 128
	MaxDryRunBodyPreview         int64 = 1_024
	MaxRetryAfter                      = 30 * time.Second
	MaxUpdateRedirects                 = 10
	DefaultDOHTimeout                  = 5 * time.Second
)

const (
	// MaxFormattedBodyBytes is the existing cap for complete response
	// formatting and clipboard capture.
	MaxFormattedBodyBytes = 1 << 20

	// Descriptive aliases keep call sites self-documenting while preserving
	// one canonical value for each limit.
	MaxCompositeMaterializationBytes = MaxCompositeMaterialization
	MaxUpdaterReleaseMetadataBytes   = MaxUpdaterReleaseMetadata
	MaxUpdaterChecksumSidecarBytes   = MaxUpdaterChecksumSidecar
	MaxUpdaterArtifactBytes          = MaxUpdaterArtifact
	MaxUpdaterUnpackedDataBytes      = MaxUpdaterUnpackedData
	MaxDryRunBodyPreviewBytes        = MaxDryRunBodyPreview
)

// ErrLimitExceeded identifies an input that exceeded a bounded operation.
var ErrLimitExceeded = errors.New("resource limit exceeded")

// LimitError reports a bounded operation that exceeded its configured limit.
// The subsystem is included in the message so a user can identify which
// operation needs a smaller input or a streaming path.
type LimitError struct {
	Subsystem string
	Limit     int64
}

func (err LimitError) Error() string {
	if err.Subsystem == "" {
		return fmt.Sprintf("input exceeds %d-byte limit", err.Limit)
	}
	return fmt.Sprintf("%s exceeds %d-byte limit", err.Subsystem, err.Limit)
}

func (err LimitError) Unwrap() error { return ErrLimitExceeded }

// LimitedReader returns a reader that permits at most max bytes plus one. The
// extra byte lets callers distinguish an exact-limit input from an overflow
// without reading unbounded input.
func LimitedReader(r io.Reader, max int64) io.Reader {
	if max < 0 {
		return io.LimitReader(r, 0)
	}
	if max == int64(^uint64(0)>>1) {
		return io.LimitReader(r, max)
	}
	return io.LimitReader(r, max+1)
}

// ReadAllLimited reads up to max bytes and reports a LimitError if one more
// byte is available. It is intended for explicitly bounded materialization,
// not ordinary streaming response paths.
func ReadAllLimited(r io.Reader, max int64, subsystem string) ([]byte, error) {
	if max < 0 {
		return nil, LimitError{Subsystem: subsystem, Limit: max}
	}
	buf, err := io.ReadAll(LimitedReader(r, max))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, LimitError{Subsystem: subsystem, Limit: max}
	}
	return buf, nil
}

// BoundedBuffer is an io.Writer that never retains more than max bytes.
type BoundedBuffer struct {
	buf       bytes.Buffer
	max       int64
	subsystem string
}

func NewBoundedBuffer(max int64, subsystem string) *BoundedBuffer {
	return &BoundedBuffer{max: max, subsystem: subsystem}
}

func (b *BoundedBuffer) Write(p []byte) (int, error) {
	if b.max < 0 || int64(b.buf.Len()) > b.max {
		return 0, LimitError{Subsystem: b.subsystem, Limit: b.max}
	}
	remaining := b.max - int64(b.buf.Len())
	if int64(len(p)) > remaining {
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		return int(remaining), LimitError{Subsystem: b.subsystem, Limit: b.max}
	}
	return b.buf.Write(p)
}

func (b *BoundedBuffer) Bytes() []byte { return b.buf.Bytes() }

func (b *BoundedBuffer) Len() int { return b.buf.Len() }

func (b *BoundedBuffer) Reset() { b.buf.Reset() }
