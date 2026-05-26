package verify

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// liveDB returns the path of a small known WCDB file we can use for ground-truth
// verification, plus the 64-hex master key. Empty strings if env not present.
func liveDB(t *testing.T) (path, hexKey string) {
	t.Helper()
	candidate := os.Getenv("WXKEY_TEST_DB")
	if candidate == "" {
		t.Skip("WXKEY_TEST_DB not set")
	}
	if _, err := os.Stat(candidate); err != nil {
		t.Skipf("live DB not present: %v", err)
	}
	keyEnv := os.Getenv("WXKEY_TEST_HEX")
	if keyEnv == "" {
		t.Skip("WXKEY_TEST_HEX not set")
	}
	return candidate, keyEnv
}

func TestVerify_LiveKey(t *testing.T) {
	path, hexKey := liveDB(t)

	page1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(page1) < PageSize {
		t.Fatalf("db too small: %d bytes", len(page1))
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	mode := VerifyCandidate(key, page1[:PageSize])
	if mode == "" {
		t.Fatalf("real key did NOT verify against %s — algorithm/params off", filepath.Base(path))
	}
	t.Logf("verified as %s", mode)
}

func TestVerify_WrongKey(t *testing.T) {
	path, _ := liveDB(t)
	page1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	bogus := make([]byte, KeySize)
	for i := range bogus {
		bogus[i] = byte(i)
	}
	if VerifyCandidate(bogus, page1[:PageSize]) != "" {
		t.Fatal("bogus key unexpectedly verified")
	}
}

func TestEncKeyForCandidateNormalizesPassword(t *testing.T) {
	password := bytesOf("0123456789abcdef0123456789abcdef")
	salt := bytesOf("1234567890abcdef")
	page1 := buildSyntheticPage1(t, password, salt)

	encKey, mode := EncKeyForCandidate(password, page1)
	if mode != "password" {
		t.Fatalf("EncKeyForCandidate mode = %q, want password", mode)
	}
	if len(encKey) != KeySize {
		t.Fatalf("enc_key length = %d, want %d", len(encKey), KeySize)
	}
	if string(encKey) == string(password) {
		t.Fatalf("password candidate was not normalized to derived enc_key")
	}
	if !VerifyAsEncKey(encKey, page1) {
		t.Fatalf("normalized enc_key does not verify")
	}
}

func bytesOf(s string) []byte {
	return []byte(s)
}

func buildSyntheticPage1(t *testing.T, password, salt []byte) []byte {
	t.Helper()
	page1 := make([]byte, PageSize)
	copy(page1, salt)
	for i := SaltSize; i < PageSize-HMACSize; i++ {
		page1[i] = byte(i)
	}
	encKey, err := pbkdf2.Key(sha512.New, string(password), salt, KDFIter, KeySize)
	if err != nil {
		t.Fatalf("derive test enc_key: %v", err)
	}
	fillPage1MAC(page1, encKey)
	return page1
}

func fillPage1MAC(page1, encKey []byte) {
	salt := page1[:SaltSize]
	macSalt := make([]byte, SaltSize)
	for i, b := range salt {
		macSalt[i] = b ^ 0x3A
	}
	macKey, _ := pbkdf2.Key(sha512.New, string(encKey), macSalt, 2, KeySize)
	h := hmac.New(sha512.New, macKey)
	h.Write(page1[SaltSize : PageSize-HMACSize])
	var pageNum [4]byte
	binary.LittleEndian.PutUint32(pageNum[:], 1)
	h.Write(pageNum[:])
	copy(page1[PageSize-HMACSize:], h.Sum(nil))
}
