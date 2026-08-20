package config

import (
	"reflect"
	"testing"
	"time"

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

func TestParseAutoUpdateDurationSupportsDaysFractionsAndLeadingPlus(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "+1.5d", want: 36 * time.Hour},
		{value: "1d2h30m", want: 26*time.Hour + 30*time.Minute},
		{value: ".5h", want: 30 * time.Minute},
		{value: "2μs", want: 2 * time.Microsecond},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			c := &Config{}
			if err := c.ParseAutoUpdate(test.value); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.AutoUpdate == nil || *c.AutoUpdate != test.want {
				t.Fatalf("auto-update = %v, want %s", c.AutoUpdate, test.want)
			}
		})
	}
}

func TestParseAutoUpdateDurationRejectsOverflowAndNegative(t *testing.T) {
	for _, value := range []string{"+9223372036854775808ns", "-1d", "1x", "+"} {
		t.Run(value, func(t *testing.T) {
			c := &Config{}
			if err := c.ParseAutoUpdate(value); err == nil {
				t.Fatal("expected invalid auto-update duration")
			}
		})
	}
}

func TestMergeCombinesCertificateAndKeyFromDifferentScopes(t *testing.T) {
	cli := &Config{KeyData: []byte("cli-key"), KeyPath: "cli.key"}
	global := &Config{CertData: []byte("configured-cert"), CertPath: "configured.crt"}
	cli.Merge(global)
	if string(cli.KeyData) != "cli-key" || cli.KeyPath != "cli.key" {
		t.Fatalf("key was replaced: path=%q data=%q", cli.KeyPath, cli.KeyData)
	}
	if string(cli.CertData) != "configured-cert" || cli.CertPath != "configured.crt" {
		t.Fatalf("certificate was not merged: path=%q data=%q", cli.CertPath, cli.CertData)
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

func TestParseDurationSecondsRejectsOverflow(t *testing.T) {
	tests := []struct {
		name  string
		parse func(*Config, string) error
	}{
		{name: "connect-timeout", parse: (*Config).ParseConnectTimeout},
		{name: "retry-delay", parse: (*Config).ParseRetryDelay},
		{name: "timeout", parse: (*Config).ParseTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{}
			if err := tt.parse(c, "1e100"); err == nil {
				t.Fatalf("expected overflow error for %s", tt.name)
			}
		})
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
