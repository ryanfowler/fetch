package complete

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/cli"
)

func TestCompleteFish(t *testing.T) {
	var app cli.App
	flags := app.CLI().Flags
	_, long := getFlagMaps(flags)

	tests := []struct {
		name  string
		shell Shell
		args  []string
		exp   string
	}{
		{
			name:  "should return nothing when no args",
			shell: Fish{},
			args:  nil,
			exp:   "",
		},
		{
			name:  "should return nothing when only arg is command",
			shell: Fish{},
			args:  []string{"fetch"},
			exp:   "",
		},
		{
			name:  "should complete color flag",
			shell: Fish{},
			args:  []string{"fetch", "--col"},
			exp:   "--color\t" + long["color"].Description + "\n",
		},
		{
			name:  "should complete color value",
			shell: Fish{},
			args:  []string{"fetch", "--color", ""},
			exp: func() string {
				var sb strings.Builder
				for _, kv := range long["color"].Values {
					sb.WriteString(kv.Key)
					sb.WriteByte('\t')
					sb.WriteString(kv.Val)
					sb.WriteByte('\n')
				}
				return sb.String()
			}(),
		},
		{
			name:  "should complete color value with prefix",
			shell: Fish{},
			args:  []string{"fetch", "--color", "o"},
			exp: func() string {
				var sb strings.Builder
				for _, kv := range long["color"].Values {
					if !strings.HasPrefix(kv.Key, "o") {
						continue
					}
					sb.WriteString(kv.Key)
					sb.WriteByte('\t')
					sb.WriteString(kv.Val)
					sb.WriteByte('\n')
				}
				return sb.String()
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := Complete(test.shell, test.args)
			if res != test.exp {
				t.Fatalf("Unexpected result:\n%s", res)
			}
		})
	}
}
