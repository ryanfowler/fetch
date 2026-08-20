package core

import (
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// ParseSeconds parses a non-negative number of seconds into a duration.
// Zero means no timeout. Fractional seconds are truncated to nanoseconds;
// negative, NaN, infinite, and overflowing values are rejected.
func ParseSeconds(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, strconv.ErrSyntax
	}

	// Rat accepts decimal values with exponents while retaining exactness, so
	// a value at the int64 duration boundary is not misclassified by float
	// rounding. Fractions are intentionally not accepted as durations.
	if strings.Contains(value, "/") {
		return 0, strconv.ErrSyntax
	}
	rat, ok := new(big.Rat).SetString(value)
	if !ok || rat.Sign() < 0 {
		return 0, strconv.ErrSyntax
	}
	nanos := new(big.Rat).Mul(rat, big.NewRat(int64(time.Second), 1))
	max := new(big.Rat).SetInt64(math.MaxInt64)
	if nanos.Cmp(max) > 0 {
		return 0, strconv.ErrRange
	}
	n := new(big.Int).Quo(nanos.Num(), nanos.Denom())
	return time.Duration(n.Int64()), nil
}
