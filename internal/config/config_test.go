package config

import (
	"reflect"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestParseHeader(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseHeader("X-Test: value"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := []core.KeyVal[string]{{Key: "X-Test", Val: "value"}}
		if !reflect.DeepEqual(c.Headers, want) {
			t.Fatalf("headers = %+v, want %+v", c.Headers, want)
		}
	})

	t.Run("empty value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseHeader("X-Test:"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := []core.KeyVal[string]{{Key: "X-Test", Val: ""}}
		if !reflect.DeepEqual(c.Headers, want) {
			t.Fatalf("headers = %+v, want %+v", c.Headers, want)
		}
	})

	tests := []struct {
		name  string
		value string
	}{
		{name: "missing colon", value: "X-Test"},
		{name: "empty name", value: ": value"},
		{name: "malformed name", value: "Bad Header: value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := &Config{}
			if err := c.ParseHeader(test.value); err == nil {
				t.Fatalf("expected error for %q", test.value)
			}
			if len(c.Headers) != 0 {
				t.Fatalf("headers = %+v, want none", c.Headers)
			}
		})
	}
}

func TestParseRetry(t *testing.T) {
	t.Run("negative value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetry("-1"); err == nil {
			t.Error("expected error for negative retry value")
		}
	})

	t.Run("valid value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetry("3"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Retry == nil || *c.Retry != 3 {
			t.Errorf("expected retry=3, got %v", c.Retry)
		}
	})

	t.Run("zero", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetry("0"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Retry == nil || *c.Retry != 0 {
			t.Errorf("expected retry=0, got %v", c.Retry)
		}
	})

	t.Run("non-integer", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetry("abc"); err == nil {
			t.Error("expected error for non-integer retry value")
		}
	})
}

func TestParseConnectTimeout(t *testing.T) {
	t.Run("negative value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseConnectTimeout("-1"); err == nil {
			t.Error("expected error for negative connect-timeout value")
		}
	})

	t.Run("valid value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseConnectTimeout("2.5"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ConnectTimeout == nil {
			t.Fatal("expected connect-timeout to be set")
		}
	})

	t.Run("zero", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseConnectTimeout("0"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ConnectTimeout == nil {
			t.Fatal("expected connect-timeout to be set")
		}
	})

	t.Run("non-numeric", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseConnectTimeout("abc"); err == nil {
			t.Error("expected error for non-numeric connect-timeout value")
		}
	})
}

func TestParseDurationSecondsRejectsNonFiniteValues(t *testing.T) {
	tests := []struct {
		name  string
		parse func(*Config, string) error
	}{
		{name: "connect-timeout", parse: (*Config).ParseConnectTimeout},
		{name: "retry-delay", parse: (*Config).ParseRetryDelay},
		{name: "timeout", parse: (*Config).ParseTimeout},
	}
	values := []string{"NaN", "+Inf", "-Inf", "Inf"}

	for _, tt := range tests {
		for _, value := range values {
			t.Run(tt.name+"/"+value, func(t *testing.T) {
				c := &Config{}
				if err := tt.parse(c, value); err == nil {
					t.Fatalf("expected error for %s=%s", tt.name, value)
				}
			})
		}
	}
}

func TestParseRetryDelay(t *testing.T) {
	t.Run("negative value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetryDelay("-1"); err == nil {
			t.Error("expected error for negative retry-delay value")
		}
	})

	t.Run("valid value", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetryDelay("2.5"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.RetryDelay == nil {
			t.Fatal("expected retry-delay to be set")
		}
	})

	t.Run("zero", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetryDelay("0"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.RetryDelay == nil {
			t.Fatal("expected retry-delay to be set")
		}
	})

	t.Run("non-numeric", func(t *testing.T) {
		c := &Config{}
		if err := c.ParseRetryDelay("abc"); err == nil {
			t.Error("expected error for non-numeric retry-delay value")
		}
	})
}
