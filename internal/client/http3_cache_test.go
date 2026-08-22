package client

import (
	"encoding/json/v2"
	"net"
	"os"
	"path/filepath"
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
