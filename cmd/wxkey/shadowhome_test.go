package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerDocumentsForRoot(t *testing.T) {
	docs := "/Users/u/Library/Containers/com.tencent.xinWeChat/Data/Documents"
	if got, ok := containerDocumentsForRoot(docs + "/xwechat_files/wxid_a"); !ok || got != docs {
		t.Fatalf("container root: got %q ok=%v", got, ok)
	}
	for _, root := range []string{
		"/tmp/xwechat_files/wxid_a",
		"/Users/u/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/4.0.5/wxid_a",
	} {
		if _, ok := containerDocumentsForRoot(root); ok {
			t.Fatalf("non-container root %q should not be cloned", root)
		}
	}
}

func TestCloneContainerDocumentsKeepsKeyDataAndSkipsMedia(t *testing.T) {
	src := filepath.Join(t.TempDir(), "Documents")
	dst := filepath.Join(t.TempDir(), "clone", "Documents")
	files := map[string]bool{ // path -> expected in clone
		"xwechat_files/wxid_a/db_storage/message/message_0.db": true,
		"xwechat_files/wxid_a/config/c":                        true,
		"xwechat_files/wxid_a/msg/attach/big.dat":              false,
		"xwechat_files/wxid_a/cache/x":                         false,
		"xwechat_files/all_users/login/wxid_a/key_info.db":     true,
		"app_data/login/state":                                 true,
		"app_data/log/mm.xlog":                                 false,
		"app_data/radium/blob":                                 false,
		"other/file":                                           true,
	}
	for rel := range files {
		path := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rel), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cloneContainerDocuments(src, dst); err != nil {
		t.Fatal(err)
	}
	for rel, want := range files {
		_, err := os.Stat(filepath.Join(dst, rel))
		if got := err == nil; got != want {
			t.Errorf("%s present=%v want %v (err=%v)", rel, got, want, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dst, "xwechat_files/wxid_a/db_storage/message/message_0.db")); err != nil || string(data) != "xwechat_files/wxid_a/db_storage/message/message_0.db" {
		t.Fatalf("cloned DB content mismatch: %q %v", data, err)
	}
}

func TestPidsUnderAppIncludesHelpers(t *testing.T) {
	app := "/Users/u/Library/Application Support/wx-mcp/WeChat-shadow.app"
	ps := "  101 " + app + "/Contents/MacOS/WeChat\n" +
		"  102 " + app + "/Contents/Frameworks/crashpad_handler\n" +
		"  103 " + app + "/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/Helpers/WeChatAppEx Helper (GPU).app/Contents/MacOS/WeChatAppEx Helper (GPU)\n" +
		"  104 /Applications/WeChat.app/Contents/MacOS/WeChat\n" +
		"  105 /Users/u/Library/Application Support/wx-mcp/WeChat-shadow.app.bak/Contents/MacOS/WeChat\n"
	got := pidsUnderApp(ps, app)
	if len(got) != 3 || got[0] != 101 || got[1] != 102 || got[2] != 103 {
		t.Fatalf("pidsUnderApp = %v, want [101 102 103]", got)
	}
}

func TestLSASNsParsesFindOutput(t *testing.T) {
	got := lsASNs("ASN:0x0-0x245245-\"微信\": ASN:0x0-0x253253-\"微信\":\n")
	if len(got) != 2 || got[0] != "ASN:0x0-0x245245:" || got[1] != "ASN:0x0-0x253253:" {
		t.Fatalf("lsASNs = %v", got)
	}
	if got := lsASNs(""); len(got) != 0 {
		t.Fatalf("empty output parsed as %v", got)
	}
}
