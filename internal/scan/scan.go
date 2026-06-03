// Package scan finds WeChat database master keys by walking the WeChat
// process's RW memory regions, looking for the SQL literal pattern
// `x'<hex>'` that older WCDB builds used when forwarding keys to
// sqlite3_key_v2, plus optional binary layout patterns seen in newer WeChat
// 4.x heaps, and verifying each candidate against page 1 of every collected DB.
//
// Algorithm (after Thearas, adapted for SQLCipher 4 + WCDB v4 KDF):
//  1. enumerate RW non-executable regions of the WeChat task
//  2. read each region in chunks; regex-match `x'[0-9a-fA-F]{64,192}'`
//  3. for each match, take first 64 hex as candidate key, last 32 hex
//     (when present) as embedded salt
//  4. if embedded salt matches a DB salt, verify against that DB only;
//     otherwise, try every DB whose salt is still unmatched
//  5. verification = SQLCipher 4 password-or-enc_key MAC check
package scan

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/r266-tech/wxkey/internal/dbfiles"
	"github.com/r266-tech/wxkey/internal/machvm"
	"github.com/r266-tech/wxkey/internal/verify"
)

// hexLitRe finds `x'<64-192 hex chars>'` SQL literals in raw memory.
// 64 hex = key only; 96 hex = key+salt; >96 even = key + extra + salt at tail.
var hexLitRe = regexp.MustCompile(`x'([0-9a-fA-F]{64,192})'`)

// bareHexRe finds 64-character runs of ASCII hex NOT wrapped in x'...'. WCDB's
// upper-layer APIs (e.g. wcdb_open_account) take the master password as a
// 64-char ASCII hex string, which often lives in memory as a plain
// std::string. These are higher-noise (many false positives) but enable
// recovering the master password even when its `x'...'` form was never built.
// Only enabled when caller passes IncludeBareHex=true (verification cost is
// ~80ms each via 256000-round PBKDF2 — keep candidates bounded).
var bareHexRe = regexp.MustCompile(`(?:^|[^0-9a-fA-Fx'])([0-9a-fA-F]{64})(?:[^0-9a-fA-F]|$)`)

type binaryKeyPattern struct {
	pattern   []byte
	offsets   []int
	alignZero bool
	weak      bool
}

var zero16 = []byte{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}
var zero32 = make([]byte, verify.KeySize)

// v4BinaryKeyPatterns are adapted from ai-hermes/chatlog's macOS V4 key
// extractor. Newer WeChat 4.x builds may keep the 32-byte database password as
// raw bytes near these heap-layout sentinels instead of as an x'...' string.
var v4BinaryKeyPatterns = []binaryKeyPattern{
	{
		pattern: []byte{0x20, 0x66, 0x74, 0x73, 0x35, 0x28, 0x25, 0x00},
		offsets: []int{16, -80, 64},
	},
	{
		pattern:   zero16,
		offsets:   []int{-32},
		alignZero: true,
		weak:      true,
	},
}

// Default chunk for region reads. 8 MiB is what Thearas uses; small enough
// to keep regex pass cheap, large enough to amortize syscall cost.
const chunkSize = 8 * 1024 * 1024

// overlap copies the trailing OverlapBytes from the previous chunk to the
// front of the next so we don't miss matches that straddle a chunk boundary.
// hexLitRe's longest match is `x'` + 192 hex + `'` = 196 bytes; round up.
const overlap = 256

// MaxRegionSize skips any single region larger than this (typically shared
// caches or the dyld closure mapped at full virtual size).
const MaxRegionSize = 500 * 1024 * 1024

// ErrDeadlineExceeded reports a caller-supplied scan deadline. Results may be
// partial when this is returned.
var ErrDeadlineExceeded = errors.New("scan deadline exceeded")

// Result describes one matched (db, key) pair. VerifyAs records which in-memory
// representation matched; KeyHex is always normalized to the post-PBKDF2 enc_key.
type Result struct {
	DBRel    string `json:"db_rel"`    // db path relative to scan root
	DBPath   string `json:"db_path"`   // absolute db path
	SaltHex  string `json:"salt_hex"`  // 32-hex db salt
	KeyHex   string `json:"key_hex"`   // 64-hex post-PBKDF2 enc_key
	VerifyAs string `json:"verify_as"` // "password" or "enc_key"
}

// Stats summarizes a scan run.
type Stats struct {
	Regions              int           `json:"regions"`
	PriorityRegions      int           `json:"priority_regions,omitempty"`
	BytesScanned         uint64        `json:"bytes_scanned"`
	HexMatches           int           `json:"hex_matches"`
	SaltMatches          int           `json:"salt_matches,omitempty"`
	BinaryPatternMatches int           `json:"binary_pattern_matches,omitempty"`
	BareHexMatches       int           `json:"bare_hex_matches,omitempty"`
	Verifications        int           `json:"verifications"` // PBKDF2 calls actually made
	Found                int           `json:"found"`
	Elapsed              time.Duration `json:"elapsed_ns"`
}

// ProgressFn is called periodically with cumulative stats so the CLI can
// print a status line. May be nil.
type ProgressFn func(s Stats)

// BinaryPatternMode selects which WeChat V4 binary-layout sentinels to scan.
type BinaryPatternMode int

const (
	BinaryPatternsAll BinaryPatternMode = iota
	BinaryPatternsStrong
	BinaryPatternsWeak
)

// Options tunes Run.
type Options struct {
	// IncludeReadOnlyRegions scans readable non-executable regions even when
	// they are not currently writable. Some WeChat 4.1.x builds cache
	// x'<enc_key><salt>' SQL literals outside writable heap regions.
	IncludeReadOnlyRegions bool

	// IncludeSaltNeighborhood looks for known DB salts in memory and tries
	// nearby 32-byte values as raw enc_keys. This catches SQLCipher codec
	// contexts that keep salt/key bytes without the older x'...' wrapper.
	IncludeSaltNeighborhood bool

	// IncludeBinaryPatterns enables a fallback pass that looks for known WeChat
	// 4.x heap-layout sentinels and verifies nearby 32-byte raw candidates. This
	// catches versions that no longer expose x'<key><salt>' strings.
	IncludeBinaryPatterns bool
	BinaryPatternMode     BinaryPatternMode

	// IncludeBareHex enables a slower auxiliary pass that scans for bare
	// 64-hex strings (no x'...' wrapper) and tries each as the master
	// password. This recovers the master password when WCDB only ever held
	// it as a plain std::string, but each candidate costs one 256000-round
	// PBKDF2 to verify. Only enable when needed (e.g. Plan-C investigation).
	IncludeBareHex bool

	// Deadline stops long heap scans before an installer or agent call appears
	// hung. A zero value means no deadline.
	Deadline time.Time
}

type memRegion struct{ addr, size uint64 }

type binaryCandidate struct {
	key [verify.KeySize]byte
}

const saltNeighborhoodWindow = 4096

// Run scans pid's memory for keys decrypting any of dbs. It stops as soon as
// every distinct salt has at least one verified key (or the address space is
// exhausted).
func Run(pid int32, dbs []dbfiles.DB, saltIdx map[string][]int, progress ProgressFn) (map[string]Result, Stats, error) {
	return RunWithOptions(pid, dbs, saltIdx, Options{}, progress)
}

// RunWithOptions is Run with explicit options.
func RunWithOptions(pid int32, dbs []dbfiles.DB, saltIdx map[string][]int, opts Options, progress ProgressFn) (map[string]Result, Stats, error) {
	start := time.Now()
	var stats Stats
	finish := func(results map[string]Result, err error) (map[string]Result, Stats, error) {
		stats.Found = len(results)
		stats.Elapsed = time.Since(start)
		return results, stats, err
	}
	deadlineExceeded := func() bool {
		return !opts.Deadline.IsZero() && time.Now().After(opts.Deadline)
	}

	if len(dbs) == 0 {
		return nil, stats, fmt.Errorf("scan.Run: no DBs to verify against")
	}

	proc, err := machvm.Attach(pid)
	if err != nil {
		return nil, stats, err
	}
	defer proc.Detach()

	// Track which salts (and therefore which DBs) we've already cracked.
	results := map[string]Result{} // keyed by salt-hex
	remaining := map[string]struct{}{}
	for s := range saltIdx {
		remaining[s] = struct{}{}
	}

	// Collect RW non-executable regions first (so we can report total bytes).
	var regions []memRegion
	err = proc.Regions(func(r machvm.Region) bool {
		if !r.IsReadable() || r.IsExecutable() {
			return true
		}
		if !opts.IncludeReadOnlyRegions && !r.IsWritable() {
			return true
		}
		if r.Size == 0 || r.Size > MaxRegionSize {
			return true
		}
		regions = append(regions, memRegion{r.Address, r.Size})
		return true
	})
	if err != nil {
		return nil, stats, fmt.Errorf("enumerate regions: %w", err)
	}
	if opts.IncludeBinaryPatterns {
		regions, stats.PriorityRegions = prioritizeMallocRegions(pid, regions)
	}
	stats.Regions = len(regions)

	chunk := make([]byte, chunkSize+overlap)
	var carry []byte // overlap bytes from prior chunk
	seenBinaryCandidates := map[string]struct{}{}
	seenSaltNeighborhoodCandidates := map[string]struct{}{}
	passwordAnchors := preferredPasswordDBIndices(dbs)

	for _, r := range regions {
		if len(remaining) == 0 {
			break
		}
		off := uint64(0)
		carry = carry[:0]

		for off < r.size {
			n := uint64(chunkSize)
			if n > r.size-off {
				n = r.size - off
			}
			// Place fresh data after carry.
			if len(carry) > 0 {
				copy(chunk, carry)
			}
			read, rerr := proc.Read(r.addr+off, chunk[len(carry):len(carry)+int(n)])
			if rerr != nil || read == 0 {
				off += n
				carry = carry[:0]
				continue
			}
			view := chunk[:len(carry)+read]
			viewAddr := r.addr + off - uint64(len(carry))
			stats.BytesScanned += uint64(read)

			matches := hexLitRe.FindAllSubmatchIndex(view, -1)
			for _, m := range matches {
				if deadlineExceeded() {
					return finish(results, fmt.Errorf("%w after %s", ErrDeadlineExceeded, time.Since(start).Round(time.Second)))
				}
				stats.HexMatches++
				hex := view[m[2]:m[3]]
				if processed := tryCandidate(hex, dbs, saltIdx, remaining, results, &stats); processed {
					if len(remaining) == 0 {
						break
					}
				}
			}

			if opts.IncludeBinaryPatterns && len(remaining) > 0 {
				tryBinaryPatternCandidates(viewAddr, view, dbs, saltIdx, remaining, results, &stats,
					seenBinaryCandidates, passwordAnchors, opts.BinaryPatternMode, deadlineExceeded)
				if deadlineExceeded() {
					return finish(results, fmt.Errorf("%w after %s", ErrDeadlineExceeded, time.Since(start).Round(time.Second)))
				}
			}

			if opts.IncludeSaltNeighborhood && len(remaining) > 0 {
				trySaltNeighborhoodCandidates(view, dbs, saltIdx, remaining, results, &stats,
					seenSaltNeighborhoodCandidates, deadlineExceeded)
				if deadlineExceeded() {
					return finish(results, fmt.Errorf("%w after %s", ErrDeadlineExceeded, time.Since(start).Round(time.Second)))
				}
			}

			if opts.IncludeBareHex && len(remaining) > 0 {
				bare := bareHexRe.FindAllSubmatchIndex(view, -1)
				for _, m := range bare {
					if deadlineExceeded() {
						return finish(results, fmt.Errorf("%w after %s", ErrDeadlineExceeded, time.Since(start).Round(time.Second)))
					}
					stats.BareHexMatches++
					hex := view[m[2]:m[3]]
					if processed := tryCandidate(hex, dbs, saltIdx, remaining, results, &stats); processed {
						if len(remaining) == 0 {
							break
						}
					}
				}
			}

			// Save tail as carry for next chunk so we don't miss a literal
			// that straddles the boundary.
			if read > overlap {
				carry = append(carry[:0], view[len(view)-overlap:]...)
			} else {
				carry = append(carry[:0], view...)
			}
			off += n

			if progress != nil {
				stats.Elapsed = time.Since(start)
				progress(stats)
			}

			if deadlineExceeded() {
				return finish(results, fmt.Errorf("%w after %s", ErrDeadlineExceeded, time.Since(start).Round(time.Second)))
			}
			if len(remaining) == 0 {
				break
			}
		}
	}

	return finish(results, nil)
}

func tryBinaryPatternCandidates(viewAddr uint64, view []byte, dbs []dbfiles.DB, saltIdx map[string][]int,
	remaining map[string]struct{}, results map[string]Result, stats *Stats,
	seen map[string]struct{}, passwordAnchors []int, mode BinaryPatternMode, deadlineExceeded func() bool) {
	var candidates []binaryCandidate
	for _, p := range v4BinaryKeyPatterns {
		if !binaryPatternSelected(p, mode) {
			continue
		}
		searchEnd := len(view)
		for searchEnd > 0 {
			if deadlineExceeded() || len(remaining) == 0 {
				return
			}
			idx := bytes.LastIndex(view[:searchEnd], p.pattern)
			if idx < 0 {
				break
			}
			candidateBase := idx
			nextSearchEnd := idx

			if p.alignZero {
				prevNonZero := bytes.LastIndexFunc(view[:idx], func(r rune) bool {
					return r != 0
				})
				if prevNonZero < 0 {
					break
				}
				candidateBase = prevNonZero + 1
				nextSearchEnd = candidateBase
				if (viewAddr+uint64(candidateBase))%16 != 0 {
					searchEnd = nextSearchEnd
					continue
				}
			}

			stats.BinaryPatternMatches++
			for _, offset := range p.offsets {
				keyOffset := candidateBase + offset
				if keyOffset < 0 || keyOffset+verify.KeySize > len(view) {
					continue
				}
				candidate := view[keyOffset : keyOffset+verify.KeySize]
				if !looksLikeBinaryKeyCandidate(candidate) {
					continue
				}
				keyHex := hex32(candidate)
				if _, ok := seen[keyHex]; ok {
					continue
				}
				seen[keyHex] = struct{}{}
				var c binaryCandidate
				copy(c.key[:], candidate)
				candidates = append(candidates, c)
				if len(remaining) == 0 || deadlineExceeded() {
					return
				}
			}

			searchEnd = nextSearchEnd
		}
	}
	if len(candidates) == 0 || len(remaining) == 0 || deadlineExceeded() {
		return
	}
	verifyBinaryPasswordCandidates(candidates, dbs, saltIdx, remaining, results, stats, passwordAnchors, deadlineExceeded)
}

func binaryPatternSelected(p binaryKeyPattern, mode BinaryPatternMode) bool {
	switch mode {
	case BinaryPatternsStrong:
		return !p.weak
	case BinaryPatternsWeak:
		return p.weak
	default:
		return true
	}
}

func trySaltNeighborhoodCandidates(view []byte, dbs []dbfiles.DB, saltIdx map[string][]int,
	remaining map[string]struct{}, results map[string]Result, stats *Stats,
	seen map[string]struct{}, deadlineExceeded func() bool) {
	for saltStr := range remaining {
		salt := []byte(saltStr)
		searchStart := 0
		for searchStart < len(view) {
			if deadlineExceeded() || len(remaining) == 0 {
				return
			}
			idx := bytes.Index(view[searchStart:], salt)
			if idx < 0 {
				break
			}
			idx += searchStart
			stats.SaltMatches++
			if verifyNearbyEncKeys(idx, view, saltStr, dbs, saltIdx, remaining, results, stats, seen, deadlineExceeded) {
				return
			}
			searchStart = idx + 1
		}
	}
}

func verifyNearbyEncKeys(saltOffset int, view []byte, saltStr string, dbs []dbfiles.DB, saltIdx map[string][]int,
	remaining map[string]struct{}, results map[string]Result, stats *Stats,
	seen map[string]struct{}, deadlineExceeded func() bool) bool {
	start := saltOffset - saltNeighborhoodWindow
	if start < 0 {
		start = 0
	}
	end := saltOffset + verify.SaltSize + saltNeighborhoodWindow
	if end > len(view) {
		end = len(view)
	}
	dbIdxs := saltIdx[saltStr]
	for keyOffset := start; keyOffset+verify.KeySize <= end; keyOffset++ {
		if deadlineExceeded() {
			return true
		}
		candidate := view[keyOffset : keyOffset+verify.KeySize]
		if !looksLikeBinaryKeyCandidate(candidate) {
			continue
		}
		candidateHex := hex32(candidate)
		seenKey := saltStr + ":" + candidateHex
		if _, ok := seen[seenKey]; ok {
			continue
		}
		seen[seenKey] = struct{}{}
		for _, di := range dbIdxs {
			stats.Verifications++
			if !verify.VerifyAsEncKey(candidate, dbs[di].Page1) {
				continue
			}
			results[saltStr] = Result{
				DBRel:    dbs[di].Rel,
				DBPath:   dbs[di].Path,
				SaltHex:  hex32(dbs[di].Salt),
				KeyHex:   candidateHex,
				VerifyAs: "enc_key",
			}
			delete(remaining, saltStr)
			return true
		}
	}
	return false
}

func looksLikeBinaryKeyCandidate(candidate []byte) bool {
	if len(candidate) != verify.KeySize {
		return false
	}
	if bytes.Equal(candidate, zero32) {
		return false
	}
	// Heap-layout sentinels generate many null-padded false positives. A real
	// 32-byte random password can contain two consecutive NUL bytes, but that is
	// rare; skipping them keeps fallback verification bounded.
	return !bytes.Contains(candidate, []byte{0x00, 0x00})
}

func verifyBinaryPasswordCandidates(candidates []binaryCandidate, dbs []dbfiles.DB, saltIdx map[string][]int,
	remaining map[string]struct{}, results map[string]Result, stats *Stats,
	passwordAnchors []int, deadlineExceeded func() bool) {
	di, ok := firstRemainingAnchor(passwordAnchors, dbs, remaining)
	if !ok {
		return
	}

	type hit struct {
		candidate binaryCandidate
		encKey    []byte
	}
	workers := binaryVerifyWorkers(len(candidates))
	jobs := make(chan binaryCandidate)
	hits := make(chan hit, 1)
	done := make(chan struct{})
	var doneOnce sync.Once
	stop := func() {
		doneOnce.Do(func() { close(done) })
	}
	var attempts int64
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				select {
				case <-done:
					return
				default:
				}
				if deadlineExceeded() {
					stop()
					return
				}
				atomic.AddInt64(&attempts, 1)
				if encKey, ok := verify.DeriveEncKey(candidate.key[:], dbs[di].Page1); ok {
					select {
					case hits <- hit{candidate: candidate, encKey: encKey}:
					default:
					}
					stop()
					return
				}
			}
		}()
	}

sendLoop:
	for _, candidate := range candidates {
		if deadlineExceeded() {
			stop()
			break
		}
		select {
		case <-done:
			break sendLoop
		case jobs <- candidate:
		}
	}
	close(jobs)
	wg.Wait()
	stats.Verifications += int(atomic.LoadInt64(&attempts))

	select {
	case found := <-hits:
		recordPasswordHit(found.candidate.key[:], found.encKey, di, dbs, remaining, results)
		expandPasswordHit(found.candidate.key[:], dbs, saltIdx, remaining, results, stats)
	default:
	}
}

func binaryVerifyWorkers(candidateCount int) int {
	if candidateCount <= 1 {
		return 1
	}
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > candidateCount {
		workers = candidateCount
	}
	if workers < 1 {
		return 1
	}
	return workers
}

func recordPasswordHit(candidate, encKey []byte, dbIdx int, dbs []dbfiles.DB,
	remaining map[string]struct{}, results map[string]Result) {
	saltStr := string(dbs[dbIdx].Salt)
	if _, still := remaining[saltStr]; !still {
		return
	}
	results[saltStr] = Result{
		DBRel:    dbs[dbIdx].Rel,
		DBPath:   dbs[dbIdx].Path,
		SaltHex:  hex32(dbs[dbIdx].Salt),
		KeyHex:   hex32(encKey),
		VerifyAs: "password",
	}
	delete(remaining, saltStr)
}

func expandPasswordHit(candidate []byte, dbs []dbfiles.DB, saltIdx map[string][]int,
	remaining map[string]struct{}, results map[string]Result, stats *Stats) {
	for saltStr := range remaining {
		dbIdxs := saltIdx[saltStr]
		for _, di := range dbIdxs {
			stats.Verifications++
			encKey, ok := verify.DeriveEncKey(candidate, dbs[di].Page1)
			if !ok {
				continue
			}
			results[saltStr] = Result{
				DBRel:    dbs[di].Rel,
				DBPath:   dbs[di].Path,
				SaltHex:  hex32(dbs[di].Salt),
				KeyHex:   hex32(encKey),
				VerifyAs: "password",
			}
			delete(remaining, saltStr)
			break
		}
	}
}

func preferredPasswordDBIndices(dbs []dbfiles.DB) []int {
	indices := make([]int, len(dbs))
	for i := range dbs {
		indices[i] = i
	}
	sort.SliceStable(indices, func(i, j int) bool {
		ai, aj := indices[i], indices[j]
		si, sj := passwordDBScore(dbs[ai].Rel), passwordDBScore(dbs[aj].Rel)
		if si != sj {
			return si < sj
		}
		return dbs[ai].Rel < dbs[aj].Rel
	})
	return indices
}

func passwordDBScore(rel string) int {
	rel = strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	switch {
	case strings.HasSuffix(rel, "db_storage/message/message_0.db"):
		return 0
	case strings.HasSuffix(rel, "message/message_0.db"):
		return 0
	case strings.Contains(rel, "/message/"):
		return 1
	case strings.Contains(rel, "contact"):
		return 2
	default:
		return 3
	}
}

func firstRemainingAnchor(indices []int, dbs []dbfiles.DB, remaining map[string]struct{}) (int, bool) {
	for _, di := range indices {
		if di < 0 || di >= len(dbs) {
			continue
		}
		if _, ok := remaining[string(dbs[di].Salt)]; ok {
			return di, true
		}
	}
	return 0, false
}

type regionHint struct {
	addr     uint64
	size     uint64
	resident uint64
	rank     int
}

func prioritizeMallocRegions(pid int32, regions []memRegion) ([]memRegion, int) {
	hints := mallocRegionHints(pid)
	if len(hints) == 0 {
		return regions, 0
	}
	return prioritizeRegionsFromHints(regions, hints)
}

func mallocRegionHints(pid int32) []regionHint {
	out, err := exec.Command("/usr/bin/vmmap", "-wide", strconv.Itoa(int(pid))).Output()
	if err != nil {
		return nil
	}
	major := darwinMajorVersion()
	var hints []regionHint
	inWritable := false
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "==== Writable regions"):
			inWritable = true
			continue
		case strings.HasPrefix(line, "==== Legend") || strings.HasPrefix(line, "==== Summary"):
			inWritable = false
		}
		if !inWritable {
			continue
		}
		label, start, end, resident, ok := parseVMMapRegionLine(line)
		if !ok || end <= start {
			continue
		}
		rank := mallocLabelRank(label, major)
		if rank < 0 {
			continue
		}
		hints = append(hints, regionHint{addr: start, size: end - start, resident: resident, rank: rank})
	}
	sort.SliceStable(hints, func(i, j int) bool {
		if hints[i].rank != hints[j].rank {
			return hints[i].rank < hints[j].rank
		}
		if hints[i].resident != hints[j].resident {
			return hints[i].resident > hints[j].resident
		}
		return hints[i].addr > hints[j].addr
	})
	return hints
}

func parseVMMapRegionLine(line string) (string, uint64, uint64, uint64, bool) {
	bracket := strings.IndexByte(line, '[')
	if bracket < 0 {
		return "", 0, 0, 0, false
	}
	endBracket := strings.IndexByte(line[bracket:], ']')
	var resident uint64
	if endBracket > 0 {
		sizes := strings.Fields(line[bracket+1 : bracket+endBracket])
		if len(sizes) >= 2 {
			resident = parseVMMapSize(sizes[1])
		}
	}
	prefix := strings.TrimSpace(line[:bracket])
	fields := strings.Fields(prefix)
	for i := len(fields) - 1; i >= 0; i-- {
		field := fields[i]
		dash := strings.IndexByte(field, '-')
		if dash <= 0 || dash == len(field)-1 {
			continue
		}
		start, err1 := strconv.ParseUint(field[:dash], 16, 64)
		end, err2 := strconv.ParseUint(field[dash+1:], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		label := strings.TrimSpace(strings.TrimSuffix(prefix, field))
		return label, start, end, resident, true
	}
	return "", 0, 0, 0, false
}

func parseVMMapSize(raw string) uint64 {
	raw = strings.TrimSpace(strings.ToUpper(raw))
	if raw == "" {
		return 0
	}
	mult := float64(1)
	switch {
	case strings.HasSuffix(raw, "K"):
		mult = 1024
		raw = strings.TrimSuffix(raw, "K")
	case strings.HasSuffix(raw, "M"):
		mult = 1024 * 1024
		raw = strings.TrimSuffix(raw, "M")
	case strings.HasSuffix(raw, "G"):
		mult = 1024 * 1024 * 1024
		raw = strings.TrimSuffix(raw, "G")
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return uint64(n * mult)
}

func mallocLabelRank(label string, darwinMajor int) int {
	label = strings.ToUpper(strings.TrimSpace(label))
	if strings.Contains(label, "(EMPTY)") || strings.Contains(label, "METADATA") {
		return -1
	}
	isSmall := strings.HasPrefix(label, "MALLOC_SMALL")
	isNano := strings.HasPrefix(label, "MALLOC_NANO")
	isTiny := strings.HasPrefix(label, "MALLOC_TINY")
	if darwinMajor >= 25 {
		switch {
		case isSmall:
			return 0
		case isNano:
			return 1
		case isTiny:
			return 2
		}
	} else {
		switch {
		case isNano:
			return 0
		case isSmall:
			return 1
		case isTiny:
			return 2
		}
	}
	return -1
}

func darwinMajorVersion() int {
	out, err := exec.Command("/usr/bin/uname", "-r").Output()
	if err != nil {
		return 0
	}
	raw := strings.TrimSpace(string(out))
	major, _ := strconv.Atoi(strings.TrimSuffix(strings.Split(raw, ".")[0], "\n"))
	return major
}

func prioritizeRegionsFromHints(regions []memRegion, hints []regionHint) ([]memRegion, int) {
	if len(regions) == 0 || len(hints) == 0 {
		return regions, 0
	}
	out := make([]memRegion, 0, len(regions))
	used := make([]bool, len(regions))
	for _, hint := range hints {
		hStart := hint.addr
		hEnd := hint.addr + hint.size
		for i, r := range regions {
			if used[i] {
				continue
			}
			rEnd := r.addr + r.size
			if r.addr < hEnd && hStart < rEnd {
				out = append(out, r)
				used[i] = true
			}
		}
	}
	priorityCount := len(out)
	for i, r := range regions {
		if !used[i] {
			out = append(out, r)
		}
	}
	return out, priorityCount
}

// tryCandidate parses a hex literal match, verifies it against the right DBs,
// and records hits. Returns true if any verification work happened (so caller
// can decide whether to update the in-progress carry).
func tryCandidate(hexBytes []byte, dbs []dbfiles.DB, saltIdx map[string][]int,
	remaining map[string]struct{}, results map[string]Result, stats *Stats) bool {
	hexStr := string(hexBytes)
	hexLen := len(hexStr)
	if hexLen < 64 || hexLen > 192 || hexLen%2 != 0 {
		return false
	}
	keyHex := hexStr[:64]
	keyBytes, err := decodeHex(keyHex)
	if err != nil {
		return false
	}

	// Fast path: 96-hex literals embed the salt at the end.
	if hexLen == 96 || (hexLen > 96 && hexLen%2 == 0) {
		saltHex := hexStr[hexLen-32:]
		saltBytes, err := decodeHex(saltHex)
		if err == nil {
			if dbIdxs, ok := saltIdx[string(saltBytes)]; ok {
				if _, still := remaining[string(saltBytes)]; still {
					for _, di := range dbIdxs {
						stats.Verifications++
						if encKey, mode := verify.EncKeyForCandidate(keyBytes, dbs[di].Page1); mode != "" {
							results[string(saltBytes)] = Result{
								DBRel:    dbs[di].Rel,
								DBPath:   dbs[di].Path,
								SaltHex:  saltHex,
								KeyHex:   hex32(encKey),
								VerifyAs: mode,
							}
							delete(remaining, string(saltBytes))
							return true
						}
					}
					return true
				}
			}
		}
	}

	// Slow path: try this candidate against every still-unmatched salt.
	if hexLen == 64 || hexLen == 96 || hexLen > 96 {
		for saltStr := range remaining {
			dbIdxs := saltIdx[saltStr]
			for _, di := range dbIdxs {
				stats.Verifications++
				if encKey, mode := verify.EncKeyForCandidate(keyBytes, dbs[di].Page1); mode != "" {
					results[saltStr] = Result{
						DBRel:    dbs[di].Rel,
						DBPath:   dbs[di].Path,
						SaltHex:  hex32(dbs[di].Salt),
						KeyHex:   hex32(encKey),
						VerifyAs: mode,
					}
					delete(remaining, saltStr)
					break
				}
			}
		}
		return true
	}
	return false
}

func decodeHex(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, err := nibble(s[i])
		if err != nil {
			return nil, err
		}
		lo, err := nibble(s[i+1])
		if err != nil {
			return nil, err
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func nibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex byte %q", c)
	}
}

func hex32(b []byte) string {
	const tab = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = tab[v>>4]
		out[2*i+1] = tab[v&0x0F]
	}
	return string(out)
}
