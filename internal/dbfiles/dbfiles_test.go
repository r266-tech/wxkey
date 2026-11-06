package dbfiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectSkipsWCDBFactoryBackups(t *testing.T) {
	root := t.TempDir()
	page := make([]byte, 4096)
	write := func(rel string, saltByte byte) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		page[0] = saltByte
		if err := os.WriteFile(path, page, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("db_storage/message/message_0.db", 1)
	write("db_storage/message/message_0.db.factory/2026-05-19_13-19-26/message_0.db", 2)

	dbs, salts, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 1 || dbs[0].Rel != filepath.Join("db_storage", "message", "message_0.db") || len(salts) != 1 {
		t.Fatalf("got %d dbs (%v), %d salts; want only the live message_0.db", len(dbs), dbs, len(salts))
	}
}
