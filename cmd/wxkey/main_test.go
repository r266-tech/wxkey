package main

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r266-tech/wxkey/internal/scan"
)

func TestClassifyWeChatSignatureAdHoc(t *testing.T) {
	st := classifyWeChatSignature(`Executable=/Applications/WeChat.app/Contents/MacOS/WeChat
Identifier=com.tencent.xinWeChat
Format=app bundle with Mach-O universal
CodeDirectory v=20500 size=123 flags=0x2(adhoc) hashes=1+5 location=embedded
Signature=adhoc
TeamIdentifier=not set`)
	if !st.AdHoc {
		t.Fatalf("expected ad-hoc signature")
	}
	if st.Runtime {
		t.Fatalf("did not expect runtime signature")
	}
}

func TestClassifyWeChatSignatureRuntime(t *testing.T) {
	st := classifyWeChatSignature(`Executable=/Applications/WeChat.app/Contents/MacOS/WeChat
Identifier=com.tencent.xinWeChat
Format=app bundle with Mach-O universal
CodeDirectory v=20500 size=19617 flags=0x10000(runtime) hashes=602+7 location=embedded
Signature size=9092
TeamIdentifier=5A4RE8SF68`)
	if !st.Runtime {
		t.Fatalf("expected hardened runtime signature")
	}
	if st.AdHoc {
		t.Fatalf("did not expect ad-hoc signature")
	}
}

func TestSudoKeychainAccountPrefersOriginalUser(t *testing.T) {
	t.Setenv("WXKEY_ORIG_USER", "alice")
	t.Setenv("SUDO_USER", "bob")
	if got := sudoKeychainAccount(); got != "alice" {
		t.Fatalf("sudoKeychainAccount = %q, want alice", got)
	}
}

func TestPathInsideApp(t *testing.T) {
	app := "/Users/alice/Library/Application Support/wx-mcp/WeChat-shadow.app"
	proc := "/Users/alice/Library/Application Support/wx-mcp/WeChat-shadow.app/Contents/MacOS/WeChat"
	if !pathInsideApp(proc, app) {
		t.Fatalf("expected process path to be inside app bundle")
	}
	other := "/Applications/WeChat.app/Contents/MacOS/WeChat"
	if pathInsideApp(other, app) {
		t.Fatalf("did not expect original app process to match shadow app")
	}
}

func TestPBKDFProbeTargetSupportsExplicitApp(t *testing.T) {
	app := filepath.Join(t.TempDir(), "WeChat-test.app")
	exe := filepath.Join(app, "Contents", "MacOS", "WeChat")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WXKEY_PBKDF_WECHAT_APP", app)

	target, err := pbkdfProbeTargetForBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if target.AppPath != app || target.ExePath != exe || target.Mode != "custom" {
		t.Fatalf("target = %#v, want custom app/exe", target)
	}
}

func TestConfigHasImageKey(t *testing.T) {
	if configHasImageKey(wxcliConfig{ImageKey: "   "}) {
		t.Fatalf("blank image key should not be ready")
	}
	if configHasImageKey(wxcliConfig{ImageKey: "abcdefghijklmnop"}) {
		t.Fatalf("image key without xor key should be refreshed")
	}
	xorKey := 240
	if !configHasImageKey(wxcliConfig{ImageKey: "abcdefghijklmnop", ImageXORKey: &xorKey}) {
		t.Fatalf("non-empty image key with xor key should be ready")
	}
}

func TestWriteImageKeyToConfigPreservesDBKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := wxcliConfig{
		SchemaVersion: 2,
		WxID:          "wxid_test",
		DBRoot:        "/tmp/root",
		Keys:          map[string]string{"salt": "enc"},
		KeyEpoch:      123,
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	xorKey := 240
	if err := writeImageKeyToConfig(path, "  abcdefghijklmnop  ", &xorKey); err != nil {
		t.Fatal(err)
	}
	var got wxcliConfig
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ImageKey != "abcdefghijklmnop" || got.ImageXORKey == nil || *got.ImageXORKey != 240 || got.Keys["salt"] != "enc" || got.KeyEpoch != 123 {
		t.Fatalf("config after image_key write = %#v", got)
	}
}

func TestMergeScanResultsKeepsWrappedPassResults(t *testing.T) {
	base := map[string]scan.Result{
		"salt_a": {SaltHex: "salt_a", KeyHex: "key_a", VerifyAs: "enc_key"},
		"salt_b": {SaltHex: "salt_b", KeyHex: "key_b", VerifyAs: "enc_key"},
	}
	overlay := map[string]scan.Result{
		"salt_b": {SaltHex: "salt_b", KeyHex: "new_key_b", VerifyAs: "password"},
		"salt_c": {SaltHex: "salt_c", KeyHex: "key_c", VerifyAs: "enc_key"},
	}
	got := mergeScanResults(base, overlay)
	if got["salt_a"].KeyHex != "key_a" || got["salt_b"].KeyHex != "new_key_b" || got["salt_c"].KeyHex != "key_c" {
		t.Fatalf("merged scan results = %#v", got)
	}
}

func TestPBKDFNoKeyDiagnosisExplainsFailureMode(t *testing.T) {
	tests := []struct {
		name    string
		probe   pbkdfProbeFile
		want    string
		wantAll []string
	}{
		{
			name: "no breakpoint hits",
			probe: pbkdfProbeFile{
				DBCount:     26,
				UniqueSalts: 26,
				Counters:    map[string]int{"stops": 0, "hits": 0},
			},
			want: "No PBKDF calls were observed",
		},
		{
			name: "salt mismatch",
			probe: pbkdfProbeFile{
				DBCount:     26,
				UniqueSalts: 26,
				Counters:    map[string]int{"stops": 12, "hits": 12},
			},
			want: "wrong WeChat account directory",
		},
		{
			name: "matched salt but did not verify",
			probe: pbkdfProbeFile{
				DBCount:     26,
				UniqueSalts: 26,
				Counters:    map[string]int{"stops": 12, "hits": 12, "kdf_256k_salt_hits": 2},
			},
			want: "no derived key verified",
			wantAll: []string{
				"matching_db_salt_calls=2",
				"root=/tmp/root",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pbkdfNoKeyDiagnosis(tt.probe, "/tmp/root")
			if !strings.Contains(got, tt.want) {
				t.Fatalf("diagnosis = %q, want substring %q", got, tt.want)
			}
			for _, want := range tt.wantAll {
				if !strings.Contains(got, want) {
					t.Fatalf("diagnosis = %q, want substring %q", got, want)
				}
			}
		})
	}
}

func TestSameAccountConfigCleansRoot(t *testing.T) {
	cfg := wxcliConfig{WxID: "wxid_test", DBRoot: "/tmp/root/../root"}
	if !sameAccountConfig(cfg, "wxid_test", "/tmp/root") {
		t.Fatalf("sameAccountConfig should match cleaned roots")
	}
	if sameAccountConfig(cfg, "other", "/tmp/root") {
		t.Fatalf("sameAccountConfig matched wrong wxid")
	}
}

func TestDeriveImageKeyFromDiskUsesKVComm(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WXKEY_ORIG_HOME", home)
	root := filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "xwechat_files", "wxid_test_abcd")
	imgDir := filepath.Join(root, "msg", "attach", "chat", "2026-05", "Img")
	if err := os.MkdirAll(imgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kvcomm := filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm")
	if err := os.MkdirAll(kvcomm, 0o755); err != nil {
		t.Fatal(err)
	}
	code := uint32(2270404336)
	if err := os.WriteFile(filepath.Join(kvcomm, fmt.Sprintf("key_%d_test.statistic", code)), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	key := deriveImageKeyFromKVCode(code, "wxid_test")
	datPath := filepath.Join(imgDir, "sample_t.dat")
	if err := os.WriteFile(datPath, testImageKeyV2DAT(t, []byte(key), byte(code&0xff), []byte{0xff, 0xd8, 0xff, 0xe0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}), 0o644); err != nil {
		t.Fatal(err)
	}

	tpl, err := findImageKeyTemplate(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := deriveImageKeyFromDisk(root, tpl, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != key {
		t.Fatalf("derived key = %q, want %q", got.Key, key)
	}
	if got.XORKey == nil || *got.XORKey != int(code&0xff) {
		t.Fatalf("derived xor_key = %#v, want %d", got.XORKey, code&0xff)
	}
	if got.TemplateSource != "kvcomm_t.dat" || got.Regions != 0 || got.BytesScanned != 0 {
		t.Fatalf("disk-derived metadata = %#v", got)
	}
}

func testImageKeyV2DAT(t *testing.T, key []byte, xorKey byte, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		t.Fatal(err)
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	encrypted := make([]byte, len(padded))
	for start := 0; start < len(padded); start += aes.BlockSize {
		block.Encrypt(encrypted[start:start+aes.BlockSize], padded[start:start+aes.BlockSize])
	}
	header := make([]byte, 15)
	copy(header, wechatV4ImageHeader2ForTest)
	binary.LittleEndian.PutUint32(header[6:10], uint32(len(plain)))
	binary.LittleEndian.PutUint32(header[10:14], 2)
	header[14] = 1
	return append(append(header, encrypted...), 0xff^xorKey, 0xd9^xorKey)
}

var wechatV4ImageHeader2ForTest = []byte{0x07, 0x08, 0x56, 0x32, 0x08, 0x07}

func TestDeriveImageKeyFromKVCode(t *testing.T) {
	got := deriveImageKeyFromKVCode(42, "your_wxid")
	sum := md5.Sum([]byte("42your_wxid"))
	want := fmt.Sprintf("%x", sum)[:aes.BlockSize]
	if got != want {
		t.Fatalf("deriveImageKeyFromKVCode = %q, want %q", got, want)
	}
}
