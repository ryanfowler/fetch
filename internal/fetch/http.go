package fetch

import (
	"net/http"
	"slices"
	"strings"

	"github.com/ryanfowler/fetch/internal/vars"
)

func getHeaders(headers http.Header) []vars.KeyVal {
	out := make([]vars.KeyVal, 0, len(headers))
	for k, v := range headers {
		k = strings.ToLower(k)
		out = append(out, vars.KeyVal{Key: k, Val: strings.Join(v, ",")})
	}
	slices.SortFunc(out, func(a, b vars.KeyVal) int {
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

func addHeader(headers []vars.KeyVal, h vars.KeyVal) []vars.KeyVal {
	i, _ := slices.BinarySearchFunc(headers, h, func(a, b vars.KeyVal) int {
		return strings.Compare(a.Key, b.Key)
	})
	return slices.Insert(headers, i, h)
}
