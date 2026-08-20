package core

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"
)

func TestBudgetUsesOneAbsoluteDeadline(t *testing.T) {
	start := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	budget, err := NewBudgetAt(10*time.Second, start)
	if err != nil {
		t.Fatal(err)
	}

	if got, limited := budget.RemainingAt(start.Add(4 * time.Second)); !limited || got != 6*time.Second {
		t.Fatalf("remaining = %s, limited = %t; want 6s, true", got, limited)
	}
	child := budget.Child("TLS handshake")
	if got, limited := child.budget.RemainingAt(start.Add(4 * time.Second)); !limited || got != 6*time.Second {
		t.Fatalf("child remaining = %s, limited = %t; want 6s, true", got, limited)
	}
	if err := budget.ErrAt(start.Add(11*time.Second), "request body"); err == nil || err.Error() != "request timed out during request body after 10s" {
		t.Fatalf("expired error = %v", err)
	}
}

func TestBudgetRejectsNegativeAndAllowsZero(t *testing.T) {
	start := time.Now()
	if _, err := NewBudgetAt(-time.Nanosecond, start); err == nil {
		t.Fatal("negative budget should fail")
	}
	budget, err := NewBudgetAt(0, start)
	if err != nil {
		t.Fatal(err)
	}
	if budget.Limited() || budget.ErrAt(start.Add(100*time.Hour), "") != nil {
		t.Fatal("zero budget should be unlimited")
	}
}

func TestBudgetContextDoesNotResetParentDeadline(t *testing.T) {
	start := time.Now()
	budget, err := NewBudgetAt(time.Second, start)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancelParent := context.WithDeadline(context.Background(), start.Add(100*time.Millisecond))
	defer cancelParent()
	ctx, cancel := budget.WithContext(parent, "connect")
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(start.Add(100*time.Millisecond)) {
		t.Fatalf("child deadline = %v, want parent deadline no later than %v", deadline, start.Add(100*time.Millisecond))
	}
}

func TestBudgetContextReportsTimeoutCause(t *testing.T) {
	start := time.Now().Add(-time.Second)
	budget, err := NewBudgetAt(time.Millisecond, start)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := budget.WithContext(context.Background(), "DNS")
	defer cancel()
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 100*time.Millisecond {
		t.Fatalf("budget context deadline = %v, present = %t", deadline, ok)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("budget context did not expire")
	}
	var timeout TimeoutError
	if !errors.As(context.Cause(ctx), &timeout) || timeout.Phase != "DNS" {
		t.Fatalf("context cause = %v, want phased timeout", context.Cause(ctx))
	}
}

func TestBudgetConnectionContextReportsConnectionTimeout(t *testing.T) {
	start := time.Now().Add(-time.Second)
	budget, err := NewBudgetAt(time.Millisecond, start)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := budget.WithConnectionContext(context.Background(), "TCP connect")
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connection budget context did not expire")
	}
	var timeout ErrConnectionTimedOut
	if !errors.As(context.Cause(ctx), &timeout) {
		t.Fatalf("context cause = %v, want connection timeout", context.Cause(ctx))
	}
}

func TestParseSeconds(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{value: "0", want: 0, ok: true},
		{value: "+1.5", want: 1500 * time.Millisecond, ok: true},
		{value: "0.0000000019", want: time.Nanosecond, ok: true},
		{value: "1e-3", want: time.Millisecond, ok: true},
		{value: "-1", ok: false},
		{value: "NaN", ok: false},
		{value: "+Inf", ok: false},
		{value: "1e100", ok: false},
		{value: "9223372036.854775808", ok: false},
	}
	for _, test := range tests {
		got, err := ParseSeconds(test.value)
		if test.ok {
			if err != nil || got != test.want {
				t.Errorf("ParseSeconds(%q) = %s, %v; want %s", test.value, got, err, test.want)
			}
		} else if err == nil {
			t.Errorf("ParseSeconds(%q) succeeded with %s", test.value, got)
		}
	}
}

func TestReadAllLimitedAndBoundedBuffer(t *testing.T) {
	if _, err := ReadAllLimited(strings.NewReader("123456"), 5, "article body"); !errors.Is(err, ErrLimitExceeded) || err.Error() != "article body exceeds 5-byte limit" {
		t.Fatalf("limited read error = %v", err)
	}
	data, err := ReadAllLimited(strings.NewReader("12345"), 5, "article body")
	if err != nil || string(data) != "12345" {
		t.Fatalf("exact limited read = %q, %v", data, err)
	}
	buf := NewBoundedBuffer(3, "preview")
	n, err := io.WriteString(buf, "abcd")
	if n != 3 || !errors.Is(err, ErrLimitExceeded) || string(buf.Bytes()) != "abc" {
		t.Fatalf("bounded write = n:%d err:%v data:%q", n, err, buf.Bytes())
	}
}

func TestCheckedArithmetic(t *testing.T) {
	if _, ok := CheckedAddUint64(^uint64(0), 1); ok {
		t.Fatal("uint64 overflow was accepted")
	}
	if _, ok := CheckedAddInt64(math.MaxInt64, 1); ok {
		t.Fatal("int64 overflow was accepted")
	}
	if _, ok := CheckedAddInt64(-1<<63, -1); ok {
		t.Fatal("int64 underflow was accepted")
	}
	if _, ok := CheckedUint64ToInt(^uint64(0)); ok {
		t.Fatal("uint64 to int overflow was accepted")
	}
	if _, ok := CheckedUint64ToInt64(uint64(math.MaxInt64) + 1); ok {
		t.Fatal("uint64 to int64 overflow was accepted")
	}
	if _, ok := CheckedInt64ToUint64(-1); ok {
		t.Fatal("negative int64 to uint64 conversion was accepted")
	}
	if got, ok := CheckedIntToInt64(-1); !ok || got != -1 {
		t.Fatalf("negative int conversion = %d, %t", got, ok)
	}
}

func TestErrorCategoriesPreserveCause(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	err := NewCategoryError(CategoryNetwork, cause)
	if CategoryOf(err) != CategoryNetwork || !errors.Is(err, cause) {
		t.Fatalf("category = %v, cause preserved = %t", CategoryOf(err), errors.Is(err, cause))
	}
}
