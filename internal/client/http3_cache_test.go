package client

import (
	"bufio"
	"encoding/json/v2"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testH3Candidate(host string, source h3CandidateSource) automaticH3Candidate {
	now := time.Now()
	return automaticH3Candidate{
		host:      host,
		port:      443,
		addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}},
		expires:   now.Add(time.Hour),
		learned:   now,
		source:    source,
	}
}

func TestPersistentH3CacheRoundTripAndResolverScope(t *testing.T) {
	dir := t.TempDir()
	cache := newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created")
	}
	keyA := "https://example.com:443|udp://resolver-a"
	keyB := "https://example.com:443|udp://resolver-b"
	memory := newAutomaticH3CacheWithPersistent(cache)
	memory.replaceDNS(keyA, []automaticH3Candidate{testH3Candidate("edge-a.example", h3SourceDNS)})
	memory.addAltSvc(keyA, testH3Candidate("alt-a.example", h3SourceAltSvc))
	memory.replaceDNS(keyB, []automaticH3Candidate{testH3Candidate("edge-b.example", h3SourceDNS)})
	cache.close()

	reloaded := newPersistentH3CacheAt(dir)
	if reloaded == nil {
		t.Fatal("reloaded cache was not created")
	}
	defer reloaded.close()
	got := newAutomaticH3CacheWithPersistent(reloaded).get(keyA, time.Now())
	if len(got) != 2 || got[0].host != "alt-a.example" || got[1].host != "edge-a.example" {
		t.Fatalf("resolver A entries = %+v", got)
	}
	if got := newAutomaticH3CacheWithPersistent(reloaded).get(keyB, time.Now()); len(got) != 1 || got[0].host != "edge-b.example" {
		t.Fatalf("resolver B entries = %+v", got)
	}
}

func TestPersistentH3CacheDNSReplacementAndAltSvcClear(t *testing.T) {
	dir := t.TempDir()
	cache := newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created")
	}
	key := "https://example.com:443|system"
	memory := newAutomaticH3CacheWithPersistent(cache)
	memory.addAltSvc(key, testH3Candidate("alt.example", h3SourceAltSvc))
	memory.replaceDNS(key, []automaticH3Candidate{testH3Candidate("old.example", h3SourceDNS)})
	cache.close()

	cache = newPersistentH3CacheAt(dir)
	memory = newAutomaticH3CacheWithPersistent(cache)
	memory.replaceDNS(key, []automaticH3Candidate{{
		host:      "new.example",
		port:      443,
		addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.2")}},
		expires:   time.Now().Add(time.Hour),
		learned:   time.Now(),
		source:    h3SourceDNS,
	}})
	cache.close()

	cache = newPersistentH3CacheAt(dir)
	memory = newAutomaticH3CacheWithPersistent(cache)
	got := memory.get(key, time.Now())
	if len(got) != 2 || got[0].host != "alt.example" || got[1].host != "new.example" {
		t.Fatalf("replacement entries = %+v", got)
	}
	memory.clearAltSvc(key)
	cache.close()

	cache = newPersistentH3CacheAt(dir)
	defer cache.close()
	got = newAutomaticH3CacheWithPersistent(cache).get(key, time.Now())
	if len(got) != 1 || got[0].host != "new.example" {
		t.Fatalf("cleared entries = %+v", got)
	}
}

func TestPersistentH3CacheCapsRetentionAndExpiresEntries(t *testing.T) {
	dir := t.TempDir()
	cache := newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created")
	}
	key := "https://example.com:443|system"
	old := time.Now().Add(-h3CacheMaxAge - time.Minute)
	memory := newAutomaticH3CacheWithPersistent(cache)
	memory.replaceDNS(key, []automaticH3Candidate{{
		host:      "too-old.example",
		port:      443,
		addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.3")}},
		learned:   old,
		expires:   time.Now().Add(time.Hour),
		source:    h3SourceDNS,
	}})
	for i := 0; i < h3CacheMaxCandidates+2; i++ {
		memory.addAltSvc(key, testH3Candidate("alt-"+string(rune('a'+i))+".example", h3SourceAltSvc))
	}
	cache.close()

	cache = newPersistentH3CacheAt(dir)
	defer cache.close()
	got := newAutomaticH3CacheWithPersistent(cache).get(key, time.Now())
	if len(got) != h3CacheMaxCandidates {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), h3CacheMaxCandidates, got)
	}
	for _, candidate := range got {
		if candidate.host == "too-old.example" {
			t.Fatal("retained an entry beyond the seven-day limit")
		}
	}
}

func TestPersistentH3CacheIgnoresSymlinkShard(t *testing.T) {
	if _, err := os.Lstat(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("unexpected fixture")
	}
	dir := t.TempDir()
	cache := newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created")
	}
	key := "https://example.com:443|system"
	memory := newAutomaticH3CacheWithPersistent(cache)
	memory.replaceDNS(key, []automaticH3Candidate{testH3Candidate("edge.example", h3SourceDNS)})
	cache.close()

	shard := filepath.Join(dir, h3CacheShardName(key)+".json")
	target := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(shard)
	if err != nil {
		t.Fatal(err)
	}
	var shardValue persistentH3Shard
	if err := json.Unmarshal(data, &shardValue); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(shard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, shard); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	defer os.Remove(shard)

	cache = newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created with symlink shard")
	}
	defer cache.close()
	if got := newAutomaticH3CacheWithPersistent(cache).get(key, time.Now()); len(got) != 0 {
		t.Fatalf("symlink shard was read: %+v", got)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "outside" {
		t.Fatalf("symlink target changed: %q, %v", contents, err)
	}
}

func TestPersistentH3CachePrunesDeterministically(t *testing.T) {
	dir := t.TempDir()
	cache := newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created")
	}
	for i := 0; i < h3CacheMaxShards+1; i++ {
		key := "https://" + string(rune(0x1000+i)) + ".example:443|system"
		candidate := testH3Candidate("edge.example", h3SourceDNS)
		entry, ok := h3EntryFromCandidate(candidate, time.Now())
		if !ok {
			t.Fatal("failed to make test entry")
		}
		lock, err := cache.lockShard(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.writeShardLocked(key, []persistentH3Entry{entry}); err != nil {
			unlockH3Cache(lock)
			t.Fatal(err)
		}
		unlockH3Cache(lock)
	}
	if err := cache.pruneNow(time.Now()); err != nil {
		t.Fatal(err)
	}
	cache.close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	if count > h3CacheMaxShards {
		t.Fatalf("cache has %d shards, want at most %d", count, h3CacheMaxShards)
	}
}

func TestH3CacheLockHelperProcess(t *testing.T) {
	dir := os.Getenv("FETCH_TEST_H3_LOCK_DIR")
	if dir == "" {
		return
	}
	// Hold the lock until the parent kills this process.
	if _, err := lockH3CacheFile(dir, h3CacheLockName("0")); err != nil {
		fmt.Println("lock failed:", err)
		os.Exit(1)
	}
	fmt.Println("locked")
	for {
		time.Sleep(time.Hour)
	}
}

func TestH3CacheLockIsReleasedWhenHolderDies(t *testing.T) {
	// A process that is killed while it holds the lock must not leave a
	// stale lock behind.
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestH3CacheLockHelperProcess$")
	cmd.Env = append(os.Environ(), "FETCH_TEST_H3_LOCK_DIR="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("helper did not take the lock: %q, %v", line, err)
	}
	if lock, err := lockH3CacheFile(dir, h3CacheLockName("0")); err == nil {
		unlockH3Cache(lock)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("lock was acquired while the helper held it")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	lock, err := lockH3CacheFile(dir, h3CacheLockName("0"))
	if err != nil {
		t.Fatalf("lock after the holder died: %v", err)
	}
	unlockH3Cache(lock)
}

func TestPersistentH3CacheLockExcludesSecondHolder(t *testing.T) {
	dir := t.TempDir()
	first, err := lockH3CacheFile(dir, h3CacheLockName("a"))
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockH3CacheFile(dir, h3CacheLockName("a")); err == nil {
		unlockH3Cache(second)
		unlockH3Cache(first)
		t.Fatal("a second holder acquired the cache lock")
	}
	// Another stripe is independent.
	other, err := lockH3CacheFile(dir, h3CacheLockName("b"))
	if err != nil {
		t.Fatalf("lock of another stripe: %v", err)
	}
	unlockH3Cache(other)
	unlockH3Cache(first)
	again, err := lockH3CacheFile(dir, h3CacheLockName("a"))
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	unlockH3Cache(again)
}

func TestPersistentH3CachePruneRemovesStaleLegacyLocks(t *testing.T) {
	dir := t.TempDir()
	cache := newPersistentH3CacheAt(dir)
	if cache == nil {
		t.Fatal("cache was not created")
	}
	// Stop the worker, which prunes once at startup, so that only the
	// pruneNow call below can remove files.
	cache.close()
	stale := filepath.Join(dir, "."+h3CacheShardName("https://old.example:443|system")+".lock")
	fresh := filepath.Join(dir, "."+h3CacheShardName("https://new.example:443|system")+".lock")
	for _, path := range []string{stale, fresh} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := cache.pruneNow(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale legacy lock file was not removed: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("recent legacy lock file was removed: %v", err)
	}
	for _, name := range []string{h3CacheLockName("0"), ".prune", h3CacheShardName("x") + ".json"} {
		if isLegacyH3ShardLockName(name) {
			t.Fatalf("%s matches the legacy lock name", name)
		}
	}
}
