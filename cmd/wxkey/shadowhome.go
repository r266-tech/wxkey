package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// macOS App Data protection (sandboxd -> tccd kTCCServiceSystemPolicyAppDataDetailed)
// denies the ad-hoc signed shadow WeChat any access to the official WeChat
// container (~/Library/Containers/com.tencent.xinWeChat), because that container
// is owned by Tencent's Developer ID signature. The shadow then dies on its first
// log write (EPERM, exit 255) before it ever opens a DB, so neither the passive
// scan nor the PBKDF breakpoint sees a key.
//
// The shadow honors HOME/CFFIXED_USER_HOME, so we give it a private home whose
// Library/Containers/com.tencent.xinWeChat/Data/Documents is an APFS clone of the
// real container's small, key-relevant parts. The DB files keep the same salts,
// so the keys WeChat derives there are valid for the real DBs. The real
// container is only read, never written by the shadow.

const shadowHomeName = "WeChat-shadow-home"

// Bulky directories the shadow does not need to log in and open DBs.
var shadowHomeSkipAccountDirs = map[string]bool{"msg": true, "cache": true, "temp": true}
var shadowHomeSkipAppDataDirs = map[string]bool{"log": true, "radium": true, "crashinfo": true, "xplugin": true, "xplayer": true}

func shadowHomeRelDocuments() string {
	return filepath.Join("Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents")
}

// containerDocumentsForRoot maps .../Data/Documents/xwechat_files/<wxid> to
// .../Data/Documents when root lives inside the official WeChat container.
func containerDocumentsForRoot(root string) (string, bool) {
	root = filepath.Clean(root)
	parent := filepath.Dir(root)
	if filepath.Base(parent) != "xwechat_files" {
		return "", false
	}
	docs := filepath.Dir(parent)
	if !strings.HasSuffix(docs, string(os.PathSeparator)+shadowHomeRelDocuments()) {
		return "", false
	}
	return docs, true
}

func shadowHomeEnv(home string) []string {
	if home == "" {
		return nil
	}
	return []string{"HOME=" + home, "CFFIXED_USER_HOME=" + home}
}

// prepareShadowHome builds the cloned home for the shadow WeChat. It returns
// an empty home (and no error) when root is not inside the official container,
// in which case callers launch the shadow with the normal home as before.
// The cleanup func removes the clone and is safe to call more than once.
func prepareShadowHome(root string) (string, func(), error) {
	noop := func() {}
	docs, ok := containerDocumentsForRoot(root)
	if !ok {
		return "", noop, nil
	}
	_, rootPath, _, err := validateShadowWeChatPath(shadowWeChatPath())
	if err != nil {
		return "", noop, err
	}
	if err := removeShadowHome(rootPath); err != nil {
		return "", noop, fmt.Errorf("remove stale shadow home: %w", err)
	}
	home := filepath.Join(rootPath, shadowHomeName)
	dstDocs := filepath.Join(home, shadowHomeRelDocuments())
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if envTrue("WXKEY_KEEP_SHADOW_HOME") {
				return
			}
			_ = removeShadowHome(rootPath)
		})
	}
	if err := mkdirAsInvokingUser(dstDocs); err != nil {
		cleanup()
		return "", noop, err
	}
	if err := cloneContainerDocuments(docs, dstDocs); err != nil {
		cleanup()
		return "", noop, err
	}
	if out, err := combinedOutputAsInvokingUser("/bin/ln", "-s", shadowHomeRelDocuments(), filepath.Join(home, "Documents")); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("link shadow home Documents: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return home, cleanup, nil
}

func removeShadowHome(rootPath string) error {
	root, err := openManagedShadowRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat(shadowHomeName); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s is not a real directory", filepath.Join(rootPath, shadowHomeName))
		}
	} else if errors.Is(err, os.ErrNotExist) {
		return nil
	} else {
		return err
	}
	return root.RemoveAll(shadowHomeName)
}

func mkdirAsInvokingUser(path string) error {
	if out, err := combinedOutputAsInvokingUser("/bin/mkdir", "-p", "-m", "700", path); err != nil {
		return fmt.Errorf("mkdir %s: %w\n%s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// cloneContainerDocuments copies the parts of Data/Documents the shadow needs
// (account DBs and config, login state, app_data metadata), skipping media,
// caches and logs. On APFS `cp -c` makes copy-on-write clones: near-instant
// and no extra disk space.
func cloneContainerDocuments(srcDocs, dstDocs string) error {
	if _, err := os.Stat(srcDocs); err != nil {
		return fmt.Errorf("read WeChat container Documents: %w", err)
	}
	return cloneTree(srcDocs, dstDocs, nil, func(dir string, child os.DirEntry) map[string]bool {
		switch {
		case dir == srcDocs && child.Name() == "app_data":
			return shadowHomeSkipAppDataDirs
		case dir == srcDocs && child.Name() == "xwechat_files":
			return map[string]bool{}
		case filepath.Base(dir) == "xwechat_files":
			if st, err := os.Stat(filepath.Join(dir, child.Name(), "db_storage")); err == nil && st.IsDir() {
				return shadowHomeSkipAccountDirs
			}
		}
		return nil
	})
}

// cloneTree clones src into dst, omitting children named in skip. When
// descend returns a non-nil skip set for a child directory, that child is
// cloned recursively with that skip set instead of whole.
func cloneTree(src, dst string, skip map[string]bool, descend func(dir string, child os.DirEntry) map[string]bool) error {
	if err := mkdirAsInvokingUser(dst); err != nil {
		return err
	}
	children, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, child := range children {
		if skip[child.Name()] {
			continue
		}
		if child.IsDir() && descend != nil {
			if childSkip := descend(src, child); childSkip != nil {
				if err := cloneTree(filepath.Join(src, child.Name()), filepath.Join(dst, child.Name()), childSkip, descend); err != nil {
					return err
				}
				continue
			}
		}
		if err := clonePath(filepath.Join(src, child.Name()), dst); err != nil {
			return err
		}
	}
	return nil
}

func clonePath(src, dstDir string) error {
	if out, err := combinedOutputAsInvokingUser("/bin/cp", "-c", "-pR", src, dstDir+string(os.PathSeparator)); err != nil {
		// Not APFS (or clone unsupported): fall back to a real copy.
		if out2, err2 := combinedOutputAsInvokingUser("/bin/cp", "-pR", src, dstDir+string(os.PathSeparator)); err2 != nil {
			return fmt.Errorf("copy %s: %w\n%s\n%s", src, err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}
