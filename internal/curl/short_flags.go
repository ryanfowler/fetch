package curl

import (
	"fmt"
	"strconv"
	"strings"
)

func parseShortFlags(r *Result, flags string, rest []string) (int, error) {
	total := 0
	for i := 0; i < len(flags); i++ {
		c := flags[i]
		remaining := flags[i+1:]

		consumeArg := func() (string, int, error) {
			if len(remaining) > 0 {
				v := remaining
				i = len(flags) // skip rest of short flags
				return v, 0, nil
			}
			return nextArg(rest[total:])
		}

		switch c {
		case 'X':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-X requires an argument")
			}
			r.Method = v
			total += n
		case 'H':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-H requires an argument")
			}
			h, err := parseHeader(v)
			if err != nil {
				return 0, err
			}
			r.Headers = append(r.Headers, h)
			if strings.EqualFold(h.Name, "content-type") {
				r.HasContentType = true
			}
			if strings.EqualFold(h.Name, "accept") {
				r.HasAccept = true
			}
			total += n
		case 'd':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-d requires an argument")
			}
			r.DataValues = append(r.DataValues, DataValue{Value: v})
			total += n
		case 'F':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-F requires an argument")
			}
			r.FormFields = append(r.FormFields, parseFormField(v))
			total += n
		case 'T':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-T requires an argument")
			}
			r.UploadFile = v
			total += n
		case 'u':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-u requires an argument")
			}
			r.BasicAuth = v
			total += n
		case 'E':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-E requires an argument")
			}
			r.Cert = v
			total += n
		case 'o':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-o requires an argument")
			}
			r.Output = v
			total += n
		case 'x':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-x requires an argument")
			}
			r.Proxy = v
			total += n
		case 'm':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-m requires an argument")
			}
			secs, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid -m value: %s", v)
			}
			r.Timeout = secs
			total += n
		case 'r':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-r requires an argument")
			}
			r.Ranges = append(r.Ranges, v)
			total += n
		case 'A':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-A requires an argument")
			}
			r.UserAgent = v
			total += n
		case 'e':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-e requires an argument")
			}
			r.Referer = v
			total += n
		case 'b':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-b requires an argument")
			}
			if err := validateCookieValue(v); err != nil {
				return 0, err
			}
			r.Cookie = v
			total += n
		case 'I':
			r.Head = true
		case 'k':
			r.Insecure = true
		case 'O':
			r.RemoteName = true
		case 'J':
			r.RemoteHeaderName = true
		case 'L':
			r.FollowRedirects = true
		case 'G':
			r.GetFlag = true
		case 'v':
			r.Verbose++
		case 's':
			r.Silent = true
		case 'S', 'N', 'n', 'f':
			// No-ops.
		case '#':
			// No-op: --progress-bar.
		case '0':
			r.HTTPVersion = "1.0"
		default:
			return 0, fmt.Errorf("unsupported curl flag '-%c'", c)
		}
	}
	return total, nil
}
