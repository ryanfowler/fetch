package core

import "math"

// CheckedAddUint64 returns false when a+b would overflow uint64.
func CheckedAddUint64(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

// CheckedAddInt64 returns false when a+b would overflow int64.
func CheckedAddInt64(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, false
	}
	return a + b, true
}

// CheckedAddInt returns false when a+b would overflow int.
func CheckedAddInt(a, b int) (int, bool) {
	if b > 0 && a > maxInt-b {
		return 0, false
	}
	if b < 0 && a < minInt-b {
		return 0, false
	}
	return a + b, true
}

// CheckedUint64ToInt converts v only when it is representable as int.
func CheckedUint64ToInt(v uint64) (int, bool) {
	if v > uint64(maxInt) {
		return 0, false
	}
	return int(v), true
}

// CheckedUint64ToInt64 converts v only when it is representable as int64.
func CheckedUint64ToInt64(v uint64) (int64, bool) {
	if v > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}

// CheckedInt64ToInt converts v only when it is representable as int.
func CheckedInt64ToInt(v int64) (int, bool) {
	if v < int64(minInt) || v > int64(maxInt) {
		return 0, false
	}
	return int(v), true
}

// CheckedInt64ToUint64 converts v only when it is non-negative.
func CheckedInt64ToUint64(v int64) (uint64, bool) {
	if v < 0 {
		return 0, false
	}
	return uint64(v), true
}

// CheckedIntToInt64 converts v only on platforms where int fits in int64.
func CheckedIntToInt64(v int) (int64, bool) {
	if v < 0 {
		return int64(v), true
	}
	if uintSize == 64 && uint64(v) > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}

// CheckedIntToUint64 converts v only when it is non-negative.
func CheckedIntToUint64(v int) (uint64, bool) {
	if v < 0 {
		return 0, false
	}
	return uint64(v), true
}

const (
	maxInt   = int(^uint(0) >> 1)
	minInt   = -maxInt - 1
	uintSize = 32 << (^uint(0) >> 63)
)
