// Package verify implements WCDB-flavor SQLCipher 4 page-1 HMAC verification.
//
// Page 1 layout (4096 bytes):
//
//	[0:16]      salt
//	[16:4016]   encrypted content
//	[4016:4032] IV
//	[4032:4096] HMAC-SHA512 over (content || IV || LE32(page_num=1))
//
// Standard SQLCipher 4 derivation (WCDB v4 follows this):
//
//	enc_key = PBKDF2-HMAC-SHA512(password, salt,           iter=KDFIter, dklen=32)
//	mac_key = PBKDF2-HMAC-SHA512(enc_key,  salt XOR 0x3A,  iter=2,       dklen=32)
//
// `password` is what callers pass to sqlite3_key_v2. When wx-mcp / WeFlow stash
// the 64-hex "key" in their config, that hex is the password (NOT the post-KDF
// enc_key) — WCDB still runs the 256000-round PBKDF2 internally on each open.
//
// Memory may hold the candidate as either the password or the enc_key,
// depending on which lifecycle stage we catch. VerifyCandidate tries both.
package verify

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
)

const (
	PageSize = 4096
	SaltSize = 16
	KeySize  = 32
	HMACSize = 64
	IVSize   = 16
	// KDFIter is the password→enc_key PBKDF2 round count for SQLCipher 4
	// (and WCDB v4). The cost dominates per-candidate verification.
	KDFIter = 256000
)

// VerifyAsPassword treats candidate as the user-supplied password (the 32 bytes
// passed to sqlite3_key_v2). Cost: one 256000-round PBKDF2 + one 2-round PBKDF2.
func VerifyAsPassword(candidate, page1 []byte) bool {
	if len(candidate) != KeySize || len(page1) < PageSize {
		return false
	}
	salt := page1[:SaltSize]
	encKey, err := pbkdf2.Key(sha512.New, string(candidate), salt, KDFIter, KeySize)
	if err != nil {
		return false
	}
	return verifyMAC(encKey, page1)
}

// VerifyAsEncKey treats candidate as the post-KDF enc_key (skips the
// 256000-round PBKDF2). Cost: one 2-round PBKDF2.
func VerifyAsEncKey(candidate, page1 []byte) bool {
	if len(candidate) != KeySize || len(page1) < PageSize {
		return false
	}
	return verifyMAC(candidate, page1)
}

// VerifyCandidate runs both interpretations and returns the matching mode
// ("password" or "enc_key") on success, "" on failure. Cheap path runs first.
func VerifyCandidate(candidate, page1 []byte) string {
	if VerifyAsEncKey(candidate, page1) {
		return "enc_key"
	}
	if VerifyAsPassword(candidate, page1) {
		return "password"
	}
	return ""
}

func verifyMAC(encKey, page1 []byte) bool {
	salt := page1[:SaltSize]
	macSalt := make([]byte, SaltSize)
	for i, b := range salt {
		macSalt[i] = b ^ 0x3A
	}
	macKey, err := pbkdf2.Key(sha512.New, string(encKey), macSalt, 2, KeySize)
	if err != nil {
		return false
	}
	h := hmac.New(sha512.New, macKey)
	h.Write(page1[SaltSize : PageSize-HMACSize]) // [16:4032] = content + IV
	var pageNum [4]byte
	binary.LittleEndian.PutUint32(pageNum[:], 1)
	h.Write(pageNum[:])
	return hmac.Equal(h.Sum(nil), page1[PageSize-HMACSize:PageSize])
}
