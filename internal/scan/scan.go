// Package scan finds WeChat database master keys by walking the WeChat
// process's RW memory regions, looking for the SQL literal pattern
// `x'<hex>'` that WCDB uses when it forwards keys to sqlite3_key_v2,
// and verifying each candidate against page 1 of every collected DB.
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
	"errors"
	"fmt"
	"regexp"
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
	Regions        int           `json:"regions"`
	BytesScanned   uint64        `json:"bytes_scanned"`
	HexMatches     int           `json:"hex_matches"`
	BareHexMatches int           `json:"bare_hex_matches,omitempty"`
	Verifications  int           `json:"verifications"` // PBKDF2 calls actually made
	Found          int           `json:"found"`
	Elapsed        time.Duration `json:"elapsed_ns"`
}

// ProgressFn is called periodically with cumulative stats so the CLI can
// print a status line. May be nil.
type ProgressFn func(s Stats)

// Options tunes Run.
type Options struct {
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
	type reg struct{ addr, size uint64 }
	var regions []reg
	err = proc.Regions(func(r machvm.Region) bool {
		if !r.IsReadable() || r.IsExecutable() || !r.IsWritable() {
			return true
		}
		if r.Size == 0 || r.Size > MaxRegionSize {
			return true
		}
		regions = append(regions, reg{r.Address, r.Size})
		return true
	})
	if err != nil {
		return nil, stats, fmt.Errorf("enumerate regions: %w", err)
	}
	stats.Regions = len(regions)

	chunk := make([]byte, chunkSize+overlap)
	var carry []byte // overlap bytes from prior chunk

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
