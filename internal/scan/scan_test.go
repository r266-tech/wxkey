package scan

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/r266-tech/wxkey/internal/dbfiles"
	"github.com/r266-tech/wxkey/internal/verify"
)

func TestTryBinaryPatternCandidatesFindsV4FTSLayoutPassword(t *testing.T) {
	password := bytesSeq(1, verify.KeySize)
	salt := bytesSeq(101, verify.SaltSize)
	dbs, saltIdx := oneSyntheticDB(t, password, salt)
	remaining := map[string]struct{}{string(salt): struct{}{}}
	results := map[string]Result{}
	var stats Stats

	view := make([]byte, 256)
	copy(view[120:], v4BinaryKeyPatterns[0].pattern)
	copy(view[136:], password) // pattern offset +16

	tryBinaryPatternCandidates(0, view, dbs, saltIdx, remaining, results, &stats,
		map[string]struct{}{}, preferredPasswordDBIndices(dbs), BinaryPatternsAll, func() bool { return false })

	result, ok := results[string(salt)]
	if !ok {
		t.Fatalf("binary pattern scan did not find synthetic password; stats=%+v", stats)
	}
	if result.VerifyAs != "password" {
		t.Fatalf("VerifyAs = %q, want password", result.VerifyAs)
	}
	if result.KeyHex == hex32(password) {
		t.Fatalf("KeyHex should be normalized enc_key, got raw password")
	}
	if stats.BinaryPatternMatches == 0 || stats.Verifications == 0 {
		t.Fatalf("expected pattern match and verification stats, got %+v", stats)
	}
}

func TestTryBinaryPatternCandidatesFindsV4ZeroRunPassword(t *testing.T) {
	password := bytesSeq(33, verify.KeySize)
	salt := bytesSeq(151, verify.SaltSize)
	dbs, saltIdx := oneSyntheticDB(t, password, salt)
	remaining := map[string]struct{}{string(salt): struct{}{}}
	results := map[string]Result{}
	var stats Stats

	view := make([]byte, 160)
	copy(view[32:], password)
	// view[64:] remains zero-filled; the zero-run pattern should align to a
	// 16-byte boundary and use offset -32 to recover password at 32.

	tryBinaryPatternCandidates(0, view, dbs, saltIdx, remaining, results, &stats,
		map[string]struct{}{}, preferredPasswordDBIndices(dbs), BinaryPatternsAll, func() bool { return false })

	if _, ok := results[string(salt)]; !ok {
		t.Fatalf("zero-run binary pattern scan did not find synthetic password; stats=%+v", stats)
	}
}

func TestTryBinaryPatternCandidatesExpandsPasswordToAllSalts(t *testing.T) {
	password := bytesSeq(11, verify.KeySize)
	saltA := bytesSeq(61, verify.SaltSize)
	saltB := bytesSeq(91, verify.SaltSize)
	dbs := []dbfiles.DB{
		syntheticDB(t, "db_storage/contact/contact.db", password, saltA),
		syntheticDB(t, "db_storage/message/message_0.db", password, saltB),
	}
	saltIdx := map[string][]int{
		string(saltA): []int{0},
		string(saltB): []int{1},
	}
	remaining := map[string]struct{}{
		string(saltA): struct{}{},
		string(saltB): struct{}{},
	}
	results := map[string]Result{}
	var stats Stats

	view := make([]byte, 256)
	copy(view[120:], v4BinaryKeyPatterns[0].pattern)
	copy(view[136:], password)

	tryBinaryPatternCandidates(0, view, dbs, saltIdx, remaining, results, &stats,
		map[string]struct{}{}, preferredPasswordDBIndices(dbs), BinaryPatternsAll, func() bool { return false })

	if len(results) != 2 {
		t.Fatalf("results len = %d, want 2; remaining=%d stats=%+v", len(results), len(remaining), stats)
	}
	for salt, result := range results {
		if result.VerifyAs != "password" {
			t.Fatalf("salt %x VerifyAs = %q, want password", []byte(salt), result.VerifyAs)
		}
		if result.KeyHex == hex32(password) {
			t.Fatalf("salt %x KeyHex should be normalized enc_key, got raw password", []byte(salt))
		}
	}
}

func TestTrySaltNeighborhoodCandidatesFindsRawEncKey(t *testing.T) {
	password := bytesSeq(21, verify.KeySize)
	salt := bytesSeq(71, verify.SaltSize)
	dbs, saltIdx := oneSyntheticDB(t, password, salt)
	remaining := map[string]struct{}{string(salt): struct{}{}}
	results := map[string]Result{}
	var stats Stats

	encKey, ok := verify.DeriveEncKey(password, dbs[0].Page1)
	if !ok {
		t.Fatal("synthetic password did not verify")
	}
	view := make([]byte, 256)
	copy(view[80:], encKey)
	copy(view[160:], salt)

	trySaltNeighborhoodCandidates(view, dbs, saltIdx, remaining, results, &stats,
		map[string]struct{}{}, func() bool { return false })

	result, ok := results[string(salt)]
	if !ok {
		t.Fatalf("salt-neighborhood scan did not find synthetic enc_key; stats=%+v", stats)
	}
	if result.VerifyAs != "enc_key" {
		t.Fatalf("VerifyAs = %q, want enc_key", result.VerifyAs)
	}
	if result.KeyHex != hex32(encKey) {
		t.Fatalf("KeyHex = %q, want %q", result.KeyHex, hex32(encKey))
	}
	if stats.SaltMatches == 0 || stats.Verifications == 0 {
		t.Fatalf("expected salt match and verification stats, got %+v", stats)
	}
}

func TestTrySaltNeighborhoodCandidatesDoesNotTreatPasswordAsRawEncKey(t *testing.T) {
	password := bytesSeq(31, verify.KeySize)
	salt := bytesSeq(81, verify.SaltSize)
	dbs, saltIdx := oneSyntheticDB(t, password, salt)
	remaining := map[string]struct{}{string(salt): struct{}{}}
	results := map[string]Result{}
	var stats Stats

	view := make([]byte, 256)
	copy(view[80:], password)
	copy(view[160:], salt)

	trySaltNeighborhoodCandidates(view, dbs, saltIdx, remaining, results, &stats,
		map[string]struct{}{}, func() bool { return false })

	if _, ok := results[string(salt)]; ok {
		t.Fatalf("salt-neighborhood scan should not record password-only candidate; stats=%+v", stats)
	}
}

func TestPrioritizeRegionsFromHints(t *testing.T) {
	regions := []memRegion{
		{addr: 0x1000, size: 0x100},
		{addr: 0x2000, size: 0x100},
		{addr: 0x3000, size: 0x100},
	}
	hints := []regionHint{
		{addr: 0x3000, size: 0x80, rank: 0},
		{addr: 0x2000, size: 0x80, rank: 1},
	}
	got, priorityCount := prioritizeRegionsFromHints(regions, hints)
	if priorityCount != 2 {
		t.Fatalf("priorityCount = %d, want 2", priorityCount)
	}
	want := []uint64{0x3000, 0x2000, 0x1000}
	for i, addr := range want {
		if got[i].addr != addr {
			t.Fatalf("got[%d].addr = %#x, want %#x", i, got[i].addr, addr)
		}
	}
}

func oneSyntheticDB(t *testing.T, password, salt []byte) ([]dbfiles.DB, map[string][]int) {
	t.Helper()
	dbs := []dbfiles.DB{syntheticDB(t, "message/message_0.db", password, salt)}
	return dbs, map[string][]int{string(dbs[0].Salt): []int{0}}
}

func syntheticDB(t *testing.T, rel string, password, salt []byte) dbfiles.DB {
	t.Helper()
	page1 := syntheticPage1(t, password, salt)
	return dbfiles.DB{
		Path:  "/tmp/" + rel,
		Rel:   rel,
		Page1: page1,
		Salt:  page1[:verify.SaltSize],
	}
}

func syntheticPage1(t *testing.T, password, salt []byte) []byte {
	t.Helper()
	page1 := make([]byte, verify.PageSize)
	copy(page1, salt)

	encKey, err := pbkdf2.Key(sha512.New, string(password), salt, verify.KDFIter, verify.KeySize)
	if err != nil {
		t.Fatalf("derive enc_key: %v", err)
	}
	macSalt := make([]byte, verify.SaltSize)
	for i, b := range salt {
		macSalt[i] = b ^ 0x3A
	}
	macKey, err := pbkdf2.Key(sha512.New, string(encKey), macSalt, 2, verify.KeySize)
	if err != nil {
		t.Fatalf("derive mac_key: %v", err)
	}
	h := hmac.New(sha512.New, macKey)
	h.Write(page1[verify.SaltSize : verify.PageSize-verify.HMACSize])
	var pageNum [4]byte
	binary.LittleEndian.PutUint32(pageNum[:], 1)
	h.Write(pageNum[:])
	copy(page1[verify.PageSize-verify.HMACSize:], h.Sum(nil))
	return page1
}

func bytesSeq(start, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(start + i)
	}
	return out
}
