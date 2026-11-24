package client

import (
	"sync"
	"sync/atomic"
	"testing"
)

// These tests replace package-level state, so they must not run in parallel.

func TestRunSystemCommandRunsEachCommandOnce(t *testing.T) {
	previous := runSystemCommandFunc
	var runs atomic.Int64
	runSystemCommandFunc = func(name string, args ...string) (string, bool) {
		runs.Add(1)
		return name + " output", true
	}
	t.Cleanup(func() {
		runSystemCommandFunc = previous
		systemCommandResults.Clear()
	})
	systemCommandResults.Clear()

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if out, ok := runSystemCommand("probe-command", "get", "mode"); !ok || out != "probe-command output" {
				t.Errorf("runSystemCommand() = %q, %t", out, ok)
			}
		})
	}
	wg.Wait()
	if got := runs.Load(); got != 1 {
		t.Fatalf("the command ran %d times, want once", got)
	}
	// Other arguments are another command.
	runSystemCommand("probe-command", "get", "host")
	if got := runs.Load(); got != 2 {
		t.Fatalf("the command ran %d times, want 2", got)
	}
}

func TestRunSystemCommandRetriesAFailure(t *testing.T) {
	previous := runSystemCommandFunc
	var runs atomic.Int64
	runSystemCommandFunc = func(string, ...string) (string, bool) {
		// The first run times out, as on a cold settings daemon.
		if runs.Add(1) == 1 {
			return "", false
		}
		return "manual", true
	}
	t.Cleanup(func() {
		runSystemCommandFunc = previous
		systemCommandResults.Clear()
	})
	systemCommandResults.Clear()

	if _, ok := runSystemCommand("probe-command"); ok {
		t.Fatal("first run succeeded, want the failure")
	}
	if out, ok := runSystemCommand("probe-command"); !ok || out != "manual" {
		t.Fatalf("second run = %q, %t; want the retried result", out, ok)
	}
	if _, ok := runSystemCommand("probe-command"); !ok || runs.Load() != 2 {
		t.Fatalf("the command ran %d times, want 2: a success is cached", runs.Load())
	}
}
