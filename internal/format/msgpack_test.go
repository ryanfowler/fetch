package format

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/tinylib/msgp/msgp"
)

func TestFormatMsgPack(t *testing.T) {
	v := map[string]string{
		"key1": "val1",
		"key2": "val2",
	}

	var buf bytes.Buffer
	w := msgp.NewWriter(&buf)
	w.WriteIntf(v)
	if err := w.Flush(); err != nil {
		t.Fatalf("unable to encode msgpack map: %s", err.Error())
	}

	p := core.NewHandle(core.ColorOff).Stderr()
	err := FormatMsgPack(buf.Bytes(), p)
	if err != nil {
		t.Fatalf("unable to format msgpack data: %s", err.Error())
	}

	var out map[string]string
	err = json.Unmarshal(p.Bytes(), &out)
	if err != nil {
		t.Fatalf("unable to unmarshal json output: %s", err.Error())
	}

	if !reflect.DeepEqual(v, out) {
		t.Fatalf("unexpected output: %+v", out)
	}
}
