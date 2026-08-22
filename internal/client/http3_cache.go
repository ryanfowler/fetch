package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ryanfowler/fetch/internal/fileutil"
)

const (
	h3CacheVersion       = 1
	h3CacheMaxCandidates = 4
	h3CacheMaxShards     = 1024
	h3CacheMaxAge        = 7 * 24 * time.Hour
	h3CachePruneInterval = 24 * time.Hour
	h3CacheTouchInterval = time.Hour
	h3CacheLockWait      = 200 * time.Millisecond
	h3CacheMaxShardBytes = 64 * 1024
	h3CacheMaxAddresses  = 32
)

// persistentH3Cache is deliberately a small best-effort cache. Its worker
// serializes writes for this process, while the per-shard lock coordinates
// writers from other fetch processes. Cache failures never affect a request.
type h3CacheMutation func([]persistentH3Entry, time.Time) []persistentH3Entry

type h3CacheLock struct {
	release func()
}

type persistentH3Cache struct {
	dir string

	mu      sync.Mutex
	closed  bool
	ops     chan func()
	wake    chan struct{}
	pending map[string]h3CacheMutation
	done    chan struct{}
	wg      sync.WaitGroup
}

type persistentH3Shard struct {
	Version int                 `json:"version"`
	Key     string              `json:"key"`
	Entries []persistentH3Entry `json:"entries"`
}

type persistentH3Entry struct {
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	Addresses []string  `json:"addresses,omitempty"`
	Priority  uint16    `json:"priority,omitempty"`
	Source    uint8     `json:"source"`
	Learned   time.Time `json:"learned"`
	Expires   time.Time `json:"expires"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// newPersistentH3Cache creates the production cache. A cache directory that
// cannot be created or validated disables persistence rather than blocking
// normal HTTP requests.
func newPersistentH3Cache() *persistentH3Cache {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return nil
	}
	return newPersistentH3CacheAt(filepath.Join(base, "fetch", "http3"))
}

// newPersistentH3CacheAt is kept separate so cache policy can be tested with
// an isolated directory without modifying the user's cache.
func newPersistentH3CacheAt(dir string) *persistentH3Cache {
	if err := ensureH3CacheDir(dir); err != nil {
		return nil
	}
	cache := &persistentH3Cache{
		dir:     dir,
		ops:     make(chan func(), 4),
		wake:    make(chan struct{}, 1),
		pending: make(map[string]h3CacheMutation),
		done:    make(chan struct{}),
	}
	cache.wg.Add(1)
	go cache.run()
	cache.schedule(func() { cache.maybePrune(time.Now()) })
	return cache
}

func (c *persistentH3Cache) run() {
	defer c.wg.Done()
	ticker := time.NewTicker(h3CachePruneInterval)
	defer ticker.Stop()
	for {
		select {
		case op, ok := <-c.ops:
			if !ok {
				c.drainMutations()
				close(c.done)
				return
			}
			if op != nil {
				op()
			}
		case <-c.wake:
			c.runOneMutation()
		case now := <-ticker.C:
			c.maybePrune(now)
		}
	}
}

func (c *persistentH3Cache) runOneMutation() {
	c.mu.Lock()
	var key string
	var mutation h3CacheMutation
	for key, mutation = range c.pending {
		delete(c.pending, key)
		break
	}
	c.mu.Unlock()
	if mutation != nil {
		c.applyMutation(key, mutation)
	}
	c.mu.Lock()
	more := len(c.pending) > 0
	c.mu.Unlock()
	if more {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}

func (c *persistentH3Cache) drainMutations() {
	for {
		c.mu.Lock()
		if len(c.pending) == 0 {
			c.mu.Unlock()
			return
		}
		var key string
		var mutation h3CacheMutation
		for key, mutation = range c.pending {
			delete(c.pending, key)
			break
		}
		c.mu.Unlock()
		c.applyMutation(key, mutation)
	}
}

func (c *persistentH3Cache) schedule(op func()) {
	if c == nil || op == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	// This queue is reserved for best-effort maintenance. Critical shard
	// mutations use scheduleMutation, which coalesces by shard and never drops
	// a state-changing operation.
	select {
	case c.ops <- op:
	default:
	}
}

func (c *persistentH3Cache) scheduleMutation(key string, mutation h3CacheMutation) {
	if c == nil || key == "" || mutation == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if previous := c.pending[key]; previous != nil {
		c.pending[key] = func(entries []persistentH3Entry, now time.Time) []persistentH3Entry {
			return mutation(previous(entries, now), now)
		}
	} else {
		c.pending[key] = mutation
	}
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *persistentH3Cache) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		// Pending state changes are best effort at shutdown. The worker still
		// drains them, but close never waits on an unbounded backlog.
		for len(c.ops) > 0 {
			<-c.ops
		}
		close(c.ops)
	}
	c.mu.Unlock()
	select {
	case <-c.done:
	case <-time.After(250 * time.Millisecond):
	}
}

func (c *persistentH3Cache) load(key string, now time.Time) []automaticH3Candidate {
	if c == nil || key == "" {
		return nil
	}
	shard, err := c.readShard(key)
	if err != nil {
		return nil
	}
	entries := make([]automaticH3Candidate, 0, len(shard.Entries))
	for _, entry := range shard.Entries {
		candidate, ok := entry.toCandidate(now)
		if !ok {
			continue
		}
		entries = append(entries, candidate)
	}
	return cloneH3Candidates(entries)
}

func (c *persistentH3Cache) replaceDNS(key string, values []automaticH3Candidate) {
	c.mutate(key, func(entries []persistentH3Entry, now time.Time) []persistentH3Entry {
		out := make([]persistentH3Entry, 0, h3CacheMaxCandidates)
		for _, entry := range entries {
			if entry.Source == uint8(h3SourceAltSvc) {
				out = append(out, entry)
			}
		}
		for _, value := range values {
			if value.source != h3SourceDNS {
				continue
			}
			if entry, ok := h3EntryFromCandidate(value, now); ok {
				out = append(out, entry)
			}
		}
		return out
	})
}

func (c *persistentH3Cache) addAltSvc(key string, value automaticH3Candidate) {
	c.mutate(key, func(entries []persistentH3Entry, now time.Time) []persistentH3Entry {
		entry, ok := h3EntryFromCandidate(value, now)
		if !ok {
			return entries
		}
		for i := range entries {
			if entries[i].Source == uint8(h3SourceAltSvc) && entries[i].Host == entry.Host && entries[i].Port == entry.Port {
				entries[i] = entry
				return entries
			}
		}
		insertAt := len(entries)
		for i, existing := range entries {
			if existing.Source == uint8(h3SourceDNS) {
				insertAt = i
				break
			}
		}
		entries = append(entries, persistentH3Entry{})
		copy(entries[insertAt+1:], entries[insertAt:])
		entries[insertAt] = entry
		return entries
	})
}

func (c *persistentH3Cache) clearAltSvc(key string) {
	c.mutate(key, func(entries []persistentH3Entry, _ time.Time) []persistentH3Entry {
		out := entries[:0]
		for _, entry := range entries {
			if entry.Source != uint8(h3SourceAltSvc) {
				out = append(out, entry)
			}
		}
		return out
	})
}

func (c *persistentH3Cache) remove(key string, value automaticH3Candidate, generation bool) {
	c.mutate(key, func(entries []persistentH3Entry, _ time.Time) []persistentH3Entry {
		out := entries[:0]
		for _, entry := range entries {
			matches := entry.Source == uint8(value.source) && entry.Host == value.host && entry.Port == value.port
			if matches && generation && !value.learned.IsZero() && !entry.Learned.IsZero() && !entry.Learned.Equal(value.learned) {
				matches = false
			}
			if matches {
				continue
			}
			out = append(out, entry)
		}
		return out
	})
}

func (c *persistentH3Cache) touch(key string, values []automaticH3Candidate) {
	if c == nil || len(values) == 0 {
		return
	}
	c.mutate(key, func(entries []persistentH3Entry, now time.Time) []persistentH3Entry {
		for i := range entries {
			for _, value := range values {
				if entries[i].Source == uint8(value.source) && entries[i].Host == value.host && entries[i].Port == value.port {
					if value.lastUsed.IsZero() || now.Sub(entries[i].LastUsed) >= h3CacheTouchInterval {
						entries[i].LastUsed = now
					}
					break
				}
			}
		}
		return entries
	})
}

func (c *persistentH3Cache) mutate(key string, fn h3CacheMutation) {
	if c == nil || key == "" || fn == nil {
		return
	}
	c.scheduleMutation(key, fn)
}

func (c *persistentH3Cache) applyMutation(key string, fn h3CacheMutation) {
	now := time.Now()
	lock, err := c.lockShard(key)
	if err != nil {
		return
	}
	entries, readErr := c.readShardEntriesLocked(key)
	if readErr != nil && !os.IsNotExist(readErr) {
		unlockH3Cache(lock)
		return
	}
	entries = normalizeH3Entries(fn(entries, now), now)
	if len(entries) == 0 {
		_ = removeH3CacheFile(c.dir, h3CacheShardName(key)+".json")
	} else {
		_ = c.writeShardLocked(key, entries)
	}
	unlockH3Cache(lock)
	c.maybePrune(now)
}

func (c *persistentH3Cache) readShard(key string) (persistentH3Shard, error) {
	name := h3CacheShardName(key) + ".json"
	data, _, err := readH3CacheFile(c.dir, name, h3CacheMaxShardBytes)
	if err != nil {
		return persistentH3Shard{}, err
	}
	var shard persistentH3Shard
	if err := json.Unmarshal(data, &shard); err != nil {
		return persistentH3Shard{}, err
	}
	if shard.Version != h3CacheVersion || shard.Key != key {
		return persistentH3Shard{}, errors.New("invalid HTTP/3 cache shard version or key")
	}
	if len(shard.Entries) > h3CacheMaxCandidates {
		return persistentH3Shard{}, errors.New("HTTP/3 cache shard has too many candidates")
	}
	return shard, nil
}

func (c *persistentH3Cache) readShardEntriesLocked(key string) ([]persistentH3Entry, error) {
	shard, err := c.readShard(key)
	if err != nil {
		return nil, err
	}
	return shard.Entries, nil
}

func (c *persistentH3Cache) writeShardLocked(key string, entries []persistentH3Entry) error {
	shard := persistentH3Shard{Version: h3CacheVersion, Key: key, Entries: entries}
	data, err := json.Marshal(shard)
	if err != nil {
		return fmt.Errorf("encode HTTP/3 cache shard: %w", err)
	}
	if len(data) > h3CacheMaxShardBytes {
		return errors.New("HTTP/3 cache shard is too large")
	}
	return writeH3CacheFile(c.dir, h3CacheShardName(key)+".json", data)
}

func (c *persistentH3Cache) lockShard(key string) (*h3CacheLock, error) {
	if err := ensureH3CacheDir(c.dir); err != nil {
		return nil, err
	}
	return lockH3CacheFile(c.dir, "."+h3CacheShardName(key)+".lock")
}

func unlockH3Cache(lock *h3CacheLock) {
	if lock != nil && lock.release != nil {
		lock.release()
	}
}

func (c *persistentH3Cache) maybePrune(now time.Time) {
	marker := filepath.Join(c.dir, ".prune")
	force := false
	if entries, err := os.ReadDir(c.dir); err == nil {
		shards := 0
		for _, entry := range entries {
			if !entry.IsDir() && isH3ShardFileName(entry.Name()) {
				shards++
			}
		}
		force = shards > h3CacheMaxShards
	}
	if !force {
		if info, err := os.Lstat(marker); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return
			}
			if data, err := os.ReadFile(marker); err == nil {
				if stamp, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data))); err == nil && now.Sub(stamp) < h3CachePruneInterval {
					return
				}
			}
		}
	}
	_ = c.pruneNow(now)
	writeH3PruneMarker(marker, now)
}

func writeH3PruneMarker(path string, now time.Time) {
	info, err := os.Lstat(path)
	if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".h3-prune-*")
	if err != nil {
		return
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	_ = temp.Chmod(0600)
	if _, err := temp.WriteString(now.UTC().Format(time.RFC3339Nano)); err != nil {
		_ = temp.Close()
		return
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return
	}
	if err := temp.Close(); err != nil {
		return
	}
	_ = fileutil.AtomicReplaceFileNoSymlink(tempPath, path)
}

func (c *persistentH3Cache) pruneNow(now time.Time) error {
	if c == nil {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	type shardInfo struct {
		name    string
		key     string
		entries []persistentH3Entry
		used    time.Time
	}
	shards := make([]shardInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isH3ShardFileName(entry.Name()) {
			continue
		}
		data, info, err := readH3CacheFile(c.dir, entry.Name(), h3CacheMaxShardBytes)
		if err != nil {
			continue
		}
		var shard persistentH3Shard
		if json.Unmarshal(data, &shard) != nil || shard.Version != h3CacheVersion || shard.Key == "" || h3CacheShardName(shard.Key) != strings.TrimSuffix(entry.Name(), ".json") || len(shard.Entries) > h3CacheMaxCandidates {
			// Corrupt and unknown files are ignored, never selected for deletion.
			continue
		}
		normalized := normalizeH3Entries(shard.Entries, now)
		if len(normalized) != len(shard.Entries) || !sameH3Entries(normalized, shard.Entries) {
			c.rewritePrunedShard(shard.Key)
		}
		used := info.ModTime()
		for _, candidate := range normalized {
			if candidate.LastUsed.After(used) {
				used = candidate.LastUsed
			}
		}
		if len(normalized) > 0 {
			shards = append(shards, shardInfo{name: entry.Name(), key: shard.Key, entries: normalized, used: used})
		}
	}
	if len(shards) <= h3CacheMaxShards {
		return nil
	}
	sort.Slice(shards, func(i, j int) bool {
		if shards[i].used.Equal(shards[j].used) {
			return shards[i].name < shards[j].name
		}
		return shards[i].used.Before(shards[j].used)
	})
	for _, shard := range shards[:len(shards)-h3CacheMaxShards] {
		lock, err := c.lockShard(shard.key)
		if err != nil {
			continue
		}
		latest, readErr := c.readShardEntriesLocked(shard.key)
		if readErr == nil && sameH3Entries(normalizeH3Entries(latest, now), shard.entries) {
			_ = removeH3CacheFile(c.dir, h3CacheShardName(shard.key)+".json")
		}
		unlockH3Cache(lock)
	}
	return nil
}

func (c *persistentH3Cache) rewritePrunedShard(key string) {
	lock, err := c.lockShard(key)
	if err != nil {
		return
	}
	defer unlockH3Cache(lock)
	latest, err := c.readShardEntriesLocked(key)
	if err != nil {
		return
	}
	latest = normalizeH3Entries(latest, time.Now())
	if len(latest) == 0 {
		_ = removeH3CacheFile(c.dir, h3CacheShardName(key)+".json")
		return
	}
	_ = c.writeShardLocked(key, latest)
}

func sameH3Entries(a, b []persistentH3Entry) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func isH3ShardFileName(name string) bool {
	if len(name) != sha256.Size*2+len(".json") || !strings.HasSuffix(name, ".json") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(name, ".json"))
	return err == nil
}

func h3CacheShardName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func ensureH3CacheDir(path string) error {
	if path == "" {
		return errors.New("HTTP/3 cache directory is empty")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := ensureH3CacheParents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("refusing symlinked or non-directory HTTP/3 cache")
	}
	return nil
}

func ensureH3CacheParents(path string) error {
	missing := []string{}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return errors.New("refusing symlinked or non-directory HTTP/3 cache parent")
			}
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(missing[i])
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("refusing symlinked HTTP/3 cache directory")
		}
	}
	return nil
}

func h3EntryFromCandidate(candidate automaticH3Candidate, now time.Time) (persistentH3Entry, bool) {
	if !validH3CacheHost(candidate.host) || candidate.port == 0 || candidate.source == 0 || len(candidate.host) > 253 {
		return persistentH3Entry{}, false
	}
	learned := candidate.learned
	if learned.IsZero() {
		learned = now
	}
	expires := candidate.expires
	if expires.IsZero() || expires.After(learned.Add(h3CacheMaxAge)) {
		expires = learned.Add(h3CacheMaxAge)
	}
	if !expires.After(now) {
		return persistentH3Entry{}, false
	}
	addresses := make([]string, 0, min(len(candidate.addresses), h3CacheMaxAddresses))
	for _, address := range candidate.addresses {
		if address.IP == nil || (address.IP.To4() == nil && address.IP.To16() == nil) {
			continue
		}
		addresses = append(addresses, address.String())
		if len(addresses) == h3CacheMaxAddresses {
			break
		}
	}
	if len(addresses) == 0 {
		return persistentH3Entry{}, false
	}
	return persistentH3Entry{Host: candidate.host, Port: candidate.port, Addresses: addresses, Priority: candidate.priority, Source: uint8(candidate.source), Learned: learned, Expires: expires, LastUsed: candidate.lastUsed}, true
}

func normalizeH3Entries(entries []persistentH3Entry, now time.Time) []persistentH3Entry {
	candidates := make([]automaticH3Candidate, 0, len(entries))
	for _, entry := range entries {
		candidate, ok := entry.toCandidate(now)
		if ok {
			candidates = append(candidates, candidate)
		}
	}
	candidates = selectH3Candidates(candidates)
	out := make([]persistentH3Entry, 0, len(candidates))
	for _, candidate := range candidates {
		if normalized, ok := h3EntryFromCandidate(candidate, now); ok {
			out = append(out, normalized)
		}
	}
	return out
}

func validH3CacheHost(host string) bool {
	if host == "" || net.ParseIP(host) == nil && strings.Contains(host, ":") {
		return false
	}
	for _, r := range host {
		if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("/\\?#@[]", r) {
			return false
		}
	}
	return true
}

func (entry persistentH3Entry) toCandidate(now time.Time) (automaticH3Candidate, bool) {
	if entry.Source != uint8(h3SourceDNS) && entry.Source != uint8(h3SourceAltSvc) {
		return automaticH3Candidate{}, false
	}
	if !validH3CacheHost(entry.Host) || entry.Port == 0 || len(entry.Addresses) > h3CacheMaxAddresses || entry.Learned.IsZero() || !entry.Expires.After(now) || !now.Before(entry.Learned.Add(h3CacheMaxAge)) {
		return automaticH3Candidate{}, false
	}
	expires := entry.Expires
	if expires.After(entry.Learned.Add(h3CacheMaxAge)) {
		expires = entry.Learned.Add(h3CacheMaxAge)
	}
	addresses := make([]net.IPAddr, 0, len(entry.Addresses))
	for _, value := range entry.Addresses {
		ip := net.ParseIP(value)
		if ip == nil {
			return automaticH3Candidate{}, false
		}
		addresses = append(addresses, net.IPAddr{IP: ip})
	}
	if len(addresses) == 0 {
		return automaticH3Candidate{}, false
	}
	return automaticH3Candidate{host: entry.Host, port: entry.Port, addresses: addresses, priority: entry.Priority, source: h3CandidateSource(entry.Source), learned: entry.Learned, expires: expires, lastUsed: entry.LastUsed}, true
}
