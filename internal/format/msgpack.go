package format

import (
	"bytes"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/tinylib/msgp/msgp"
)

// FormatMsgPack formats the provided raw MessagePack data to the Printer as JSON.
func FormatMsgPack(buf []byte, p *core.Printer) error {
	var out bytes.Buffer
	_, err := msgp.CopyToJSON(&out, bytes.NewReader(buf))
	if err != nil {
		return err
	}

	return FormatJSON(out.Bytes(), p)
}
