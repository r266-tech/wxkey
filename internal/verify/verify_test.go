package verify

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// liveDB returns the path of a small known WCDB file we can use for ground-truth
// verification, plus the 64-hex master key. Empty strings if env not present.
func liveDB(t *testing.T) (path, hexKey string) {
	t.Helper()
	const candidate = "/Users/admin/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_3qqa0aja1kf612_f06d/db_storage/contact/contact.db"
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
