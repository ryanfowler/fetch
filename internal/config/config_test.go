package config

import (
	"testing"
)

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
