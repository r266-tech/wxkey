// Package dbfiles walks a WeChat 4.x xwechat_files account directory and
// collects every encrypted .db it finds, along with the file's first page
// (needed for SQLCipher salt + HMAC verification).
package dbfiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/r266-tech/wxkey/internal/verify"
)

// DB represents one WCDB file we'll try to verify candidates against.
type DB struct {
	Path  string // absolute path
	Rel   string // path relative to the walked root (for human display)
	Page1 []byte // first 4096 bytes (salt + ciphertext + IV + HMAC)
	Salt  []byte // first 16 bytes of Page1 (also the SQLCipher salt)
}

// Collect walks root and returns every regular .db file >= 4096 bytes
// (skipping -wal / -shm sidecars). Returns the DB slice plus a salt→[]int
// map so callers can look up which DBs share a salt.
func Collect(root string) ([]DB, map[string][]int, error) {
	if root == "" {
		return nil, nil, fmt.Errorf("dbfiles.Collect: empty root")
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("dbfiles.Collect: stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("dbfiles.Collect: %s is not a directory", root)
	}

	var dbs []DB
	saltIndex := map[string][]int{}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best effort: skip unreadable dirs/files
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".db") {
			return nil
		}
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		buf := make([]byte, verify.PageSize)
		n, err := f.Read(buf)
		if err != nil || n < verify.PageSize {
			return nil // too small to be encrypted with SQLCipher 4 layout
		}

		rel, _ := filepath.Rel(root, path)
		salt := buf[:verify.SaltSize]
		dbs = append(dbs, DB{
			Path:  path,
			Rel:   rel,
			Page1: buf,
			Salt:  salt,
		})
		saltIndex[string(salt)] = append(saltIndex[string(salt)], len(dbs)-1)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(dbs) == 0 {
		return nil, nil, fmt.Errorf("dbfiles.Collect: no encrypted .db found under %s", root)
	}
	return dbs, saltIndex, nil
}
