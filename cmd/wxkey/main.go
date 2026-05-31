// wxkey extracts WeChat 4.x WCDB master keys from the live WeChat process on
// macOS. Pure Go (purego + Mach VM syscalls). Passively scans WeChat's heap
// for the SQL literal `x'<hex>'` that WCDB constructs when forwarding keys to
// sqlite3_key_v2, then verifies each candidate via SQLCipher 4 page-1 HMAC.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	userpkg "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/r266-tech/wxkey/internal/dbfiles"
	"github.com/r266-tech/wxkey/internal/scan"
)

const usage = `wxkey - extract WeChat 4.x WCDB master keys (macOS)

Usage:
  wxkey bootstrap  [--root /path/to/xwechat_files/<wxid>] [--config ~/.config/wxcli/config.json]
  wxkey scan       [--pid N] [--root /path/to/xwechat_files/<wxid>] [--quiet] [--image-key]
  wxkey image-key  [--pid N] [--root /path/to/xwechat_files/<wxid>] [--quiet]
  wxkey setup      [--pid N] [--root ...] [--config ~/.config/wxcli/config.json]
  wxkey doctor     [--pid N] [--root ...] [--config ...] [--quiet] [--scan]
  wxkey resign-wechat
  wxkey list-pids
  wxkey -h | --help

Subcommands:
  bootstrap   One-command first-run setup for humans/agents: checks existing
              config, prepares an ad-hoc signed wechat-cli shadow copy of WeChat
              when needed, runs setup, and only prints a summary (not key
              material). Existing DB-key config still continues when image_key
              is missing, so local image decode can be repaired.
  scan        Scan WeChat memory and print JSON: {pid, root, stats, results[]}.
              results[] entries map a DB salt to its 64-hex master key.
  image-key   Derive the WeChat V4 local image_key from macOS kvcomm cache and
              a local *_t.dat validation sample; falls back to memory scan if
              disk derivation cannot verify a key. This does not read/write DB keys.
  setup       Like scan, but also writes ~/.config/wxcli/config.json so wechat-cli
              can pick up the key on next start. Picks the most populated DB
              under root to publish (typically contact.db or message db).
              Also best-effort scans a WeChat V4 image_key when a *_t.dat
              validation sample exists, so wechat-cli can decode local image .dat.
  doctor      Read-only health check: WeChat process, account dir, DB count,
              libWCDB.dylib presence, and cached key coverage from config.
              It does not scan memory by default; pass --scan for the slower
              live task_for_pid + key coverage check.
  resign-wechat
              Operator diagnostic path: quit WeChat, ad-hoc re-sign
              /Applications/WeChat.app, then reopen it. Bootstrap uses a
              wechat-cli shadow copy by default to avoid App Store app-management
              prompts.
  list-pids   Print one WeChat PID per line (or empty if not running).

Notes:
  - WeChat must be running and have opened at least one DB this session.
  - SIP stays enabled. First-time key extraction uses one route only:
    ad-hoc-signed WeChat + sudo privileges. Bootstrap signs a wechat-cli-managed
    shadow copy when the installed WeChat cannot be modified. wxkey asks for
    the admin password once and stores it in the user's macOS Keychain for
    later unattended refreshes.
  - wxkey will re-launch itself through sudo -S when direct attach fails (set
    WXKEY_NO_ELEVATE=1 to disable that auto-relaunch).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	startOrphanWatchdog()
	switch os.Args[1] {
	case "-h", "--help", "help":
		fmt.Print(usage)
	case "bootstrap":
		runBootstrap(os.Args[2:])
	case "scan":
		runScan(os.Args[2:], false)
	case "image-key":
		runImageKey(os.Args[2:])
	case "setup":
		runScan(os.Args[2:], true)
	case "doctor":
		runDoctor(os.Args[2:])
	case "resign-wechat":
		runResignWeChat()
	case "list-pids":
		runListPids()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

type scanFlags struct {
	pid            int
	root           string
	quiet          bool
	config         string
	includeBareHex bool
	liveScan       bool
	imageKey       bool
}

func parseFlags(args []string) scanFlags {
	var f scanFlags
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--quiet":
			f.quiet = true
		case a == "--bare-hex":
			f.includeBareHex = true
		case a == "--image-key":
			f.imageKey = true
		case a == "--scan":
			f.liveScan = true
		case strings.HasPrefix(a, "--pid="):
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--pid="))
			if err != nil {
				dieUsage("invalid --pid: %v", err)
			}
			f.pid = n
		case a == "--pid":
			i++
			if i >= len(args) {
				dieUsage("--pid requires a value")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil {
				dieUsage("invalid --pid: %v", err)
			}
			f.pid = n
		case strings.HasPrefix(a, "--root="):
			f.root = strings.TrimPrefix(a, "--root=")
		case a == "--root":
			i++
			if i >= len(args) {
				dieUsage("--root requires a value")
			}
			f.root = args[i]
		case strings.HasPrefix(a, "--config="):
			f.config = strings.TrimPrefix(a, "--config=")
		case a == "--config":
			i++
			if i >= len(args) {
				dieUsage("--config requires a value")
			}
			f.config = args[i]
		default:
			dieUsage("unknown flag: %s", a)
		}
	}
	return f
}

type scanOutput struct {
	PID           int             `json:"pid"`
	Root          string          `json:"scan_root"`
	WxID          string          `json:"wxid"`
	Stats         scan.Stats      `json:"stats"`
	Results       []scan.Result   `json:"results"`
	ImageKey      *imageKeyOutput `json:"image_key,omitempty"`
	ImageKeyError string          `json:"image_key_error,omitempty"`
}

type setupOutput struct {
	scanOutput
	ConfigPath string `json:"config_path,omitempty"`
}

type imageKeyCommandOutput struct {
	PID      int             `json:"pid"`
	Root     string          `json:"scan_root"`
	WxID     string          `json:"wxid"`
	ImageKey *imageKeyOutput `json:"image_key,omitempty"`
}

// wxcliConfig is the on-disk schema written to ~/.config/wxcli/config.json
// after a successful `wxkey setup`. The "keys" map carries one per-DB
// SQLCipher 4 enc_key (post-PBKDF2) per file salt. wechat-cli passes them to
// sqlite3_key_v2 as 96-hex `x'<key><salt>'` SQL literals (raw-key path),
// avoiding the 256000-round PBKDF2 on every DB open.
type wxcliConfig struct {
	SchemaVersion int               `json:"schema_version"`
	WxID          string            `json:"wxid"`
	DBRoot        string            `json:"db_root"`
	Keys          map[string]string `json:"keys"`
	ImageKey      string            `json:"image_key,omitempty"`
	ImageXORKey   *int              `json:"image_xor_key,omitempty"`
	KeyEpoch      int64             `json:"key_epoch"`
}

func runScan(args []string, doSetup bool) {
	f := parseFlags(args)
	pid := f.pid
	if pid == 0 {
		p, err := pickWeChatPID()
		if err != nil {
			fail("%v", err)
		}
		pid = p
	}
	root := f.root
	if root == "" {
		r, err := pickAccountRoot()
		if err != nil {
			fail("%v", err)
		}
		root = r
	}

	dbs, saltIdx, err := dbfiles.Collect(root)
	if err != nil {
		fail("collect dbs: %v", err)
	}
	logf(f.quiet, "[wxkey] scanning pid=%d root=%s (%d dbs, %d unique salts)\n",
		pid, root, len(dbs), len(saltIdx))

	// Setup uses a two-pass scan: first the fast wrapped SQL literal pattern
	// used by wx-cli/wechat-decrypt, then a slower bare-hex fallback within the
	// same timeout budget. The standalone scan command keeps --bare-hex explicit
	// for diagnostics.
	includeBareHex := f.includeBareHex || doSetup
	var results map[string]scan.Result
	var stats scan.Stats
	if doSetup {
		results, stats, err = runSetupKeyScan(pid, dbs, saltIdx, setupTimeout(), f.quiet)
	} else {
		results, stats, err = runKeyScan(pid, dbs, saltIdx, scan.Options{IncludeBareHex: includeBareHex}, 0, f.quiet)
	}
	if err != nil {
		if errors.Is(err, scan.ErrDeadlineExceeded) && doSetup && len(results) > 0 {
			fmt.Fprintf(os.Stderr, "[wxkey] WARNING: scan timed out after %s; writing partial key coverage (%d/%d). Rerun `wxkey setup` after opening missing chats/pages in WeChat.\n",
				stats.Elapsed.Round(time.Second), len(results), len(saltIdx))
		} else {
			// Auto-elevate on permission failure.
			if isPermissionErr(err) && !envTrue("WXKEY_NO_ELEVATE") && !envTrue("WXKEY_ELEVATED") {
				logf(f.quiet, "[wxkey] task_for_pid denied; re-launching via stored sudo credential...\n")
				if reErr := reExecElevated(); reErr != nil {
					fail("%s", buildElevateFailHint(reErr, err))
				}
				return // child handled it
			}
			if isPermissionErr(err) {
				printPermissionAdvice(f.quiet, err)
			}
			fail("scan: %v", err)
		}
	}

	wxid := filepath.Base(root)

	out := scanOutput{
		PID:     pid,
		Root:    root,
		WxID:    wxid,
		Stats:   stats,
		Results: collapseResults(results),
	}

	if doSetup || f.imageKey {
		img, err := scanImageKey(pid, root, f.quiet)
		if err != nil {
			out.ImageKeyError = err.Error()
			logf(f.quiet, "[wxkey] image_key scan skipped/failed: %v\n", err)
		} else {
			out.ImageKey = img
		}
	}

	if !doSetup {
		writeJSON(out)
		return
	}

	if len(out.Results) == 0 {
		fail("no keys found — make sure WeChat is logged in and has opened a chat this session")
	}

	cfgPath := f.config
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		fail("mkdir config dir: %v", err)
	}
	chownToInvokingUser(filepath.Dir(cfgPath))

	keysMap := make(map[string]string, len(out.Results))
	for _, r := range out.Results {
		keysMap[r.SaltHex] = r.KeyHex
	}
	existingCfg, hadExistingCfg := readWxcliConfig(cfgPath)
	if hadExistingCfg && sameAccountConfig(existingCfg, wxid, root) {
		for salt, key := range existingCfg.Keys {
			if _, ok := keysMap[salt]; !ok {
				keysMap[salt] = key
			}
		}
	}

	cfg := wxcliConfig{
		SchemaVersion: 2,
		WxID:          wxid,
		DBRoot:        root,
		Keys:          keysMap,
		KeyEpoch:      time.Now().Unix(),
	}
	if out.ImageKey != nil && out.ImageKey.Key != "" {
		cfg.ImageKey = out.ImageKey.Key
		cfg.ImageXORKey = out.ImageKey.XORKey
	} else if hadExistingCfg && sameAccountConfig(existingCfg, wxid, root) {
		cfg.ImageKey = existingCfg.ImageKey
		cfg.ImageXORKey = existingCfg.ImageXORKey
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append(data, '\n')
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		fail("write config: %v", err)
	}
	chownToInvokingUser(cfgPath)
	chownToDirOwner(cfgPath)
	if len(out.Results) < len(saltIdx) {
		fmt.Fprintf(os.Stderr, "[wxkey] WARNING: 部分 key 缺失 (%d/%d). Agent 应继续跑 `wxkey doctor` 轻量定位缺失 DB；只让用户在 WeChat 里打开对应聊天/页面，然后由 agent 重跑 `wxkey setup`。\n",
			len(out.Results), len(saltIdx))
	}
	writeJSON(setupOutput{scanOutput: out, ConfigPath: cfgPath})
}

const defaultSetupTimeout = 3 * time.Minute

func runSetupKeyScan(pid int, dbs []dbfiles.DB, saltIdx map[string][]int, timeout time.Duration, quiet bool) (map[string]scan.Result, scan.Stats, error) {
	start := time.Now()
	deadline := time.Time{}
	if timeout > 0 {
		deadline = start.Add(timeout)
	}

	logf(quiet, "[wxkey] pass 1/2: wrapped SQL literal scan\n")
	results, stats, err := runKeyScan(pid, dbs, saltIdx, scan.Options{Deadline: deadline}, 0, quiet)
	if err != nil && !errors.Is(err, scan.ErrDeadlineExceeded) {
		return results, stats, err
	}
	if len(results) == len(saltIdx) || errors.Is(err, scan.ErrDeadlineExceeded) {
		return results, stats, err
	}

	remainingBudget := time.Duration(0)
	if !deadline.IsZero() {
		remainingBudget = time.Until(deadline)
		if remainingBudget <= 0 {
			return results, stats, fmt.Errorf("%w after %s", scan.ErrDeadlineExceeded, time.Since(start).Round(time.Second))
		}
	}
	logf(quiet, "[wxkey] pass 2/2: bare-hex fallback scan (remaining %s)\n", remainingBudget.Round(time.Second))
	fallbackResults, fallbackStats, fallbackErr := runKeyScan(pid, dbs, saltIdx, scan.Options{IncludeBareHex: true, Deadline: deadline}, stats.Elapsed, quiet)
	merged := mergeScanResults(results, fallbackResults)
	fallbackStats.BytesScanned += stats.BytesScanned
	fallbackStats.HexMatches += stats.HexMatches
	fallbackStats.BareHexMatches += stats.BareHexMatches
	fallbackStats.Verifications += stats.Verifications
	fallbackStats.Found = len(merged)
	fallbackStats.Elapsed = time.Since(start)
	return merged, fallbackStats, fallbackErr
}

func runKeyScan(pid int, dbs []dbfiles.DB, saltIdx map[string][]int, opts scan.Options, elapsedOffset time.Duration, quiet bool) (map[string]scan.Result, scan.Stats, error) {
	return scan.RunWithOptions(int32(pid), dbs, saltIdx, opts, offsetProgressFn(quiet, elapsedOffset))
}

func mergeScanResults(base, overlay map[string]scan.Result) map[string]scan.Result {
	out := make(map[string]scan.Result, len(base)+len(overlay))
	for salt, result := range base {
		out[salt] = result
	}
	for salt, result := range overlay {
		out[salt] = result
	}
	return out
}

func runListPids() {
	pids, err := wechatPIDs()
	if err != nil {
		fail("list pids: %v", err)
	}
	for _, p := range pids {
		fmt.Println(p)
	}
}

func runImageKey(args []string) {
	f := parseFlags(args)
	pid := f.pid
	root := f.root
	if root == "" {
		r, err := pickAccountRoot()
		if err != nil {
			fail("%v", err)
		}
		root = r
	}
	img, err := scanImageKey(pid, root, f.quiet)
	if err != nil {
		if isPermissionErr(err) && !envTrue("WXKEY_NO_ELEVATE") && !envTrue("WXKEY_ELEVATED") {
			logf(f.quiet, "[wxkey] task_for_pid denied; re-launching via stored sudo credential...\n")
			if reErr := reExecElevated(); reErr != nil {
				fail("%s", buildElevateFailHint(reErr, err))
			}
			return
		}
		if isPermissionErr(err) {
			printPermissionAdvice(f.quiet, err)
		}
		fail("image-key scan: %v", err)
	}
	writeJSON(imageKeyCommandOutput{
		PID:      pid,
		Root:     root,
		WxID:     filepath.Base(root),
		ImageKey: img,
	})
}

func runBootstrap(args []string) {
	f := parseFlags(args)
	cfgPath := f.config
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if err := ensureStoredSudoPassword(); err != nil {
		fail("prepare stored sudo credential: %v", err)
	}
	var existingCfg wxcliConfig
	existingReady := false
	printedHeader := false
	if cfg, ok := configReady(cfgPath); ok {
		existingCfg = cfg
		existingReady = true
		fmt.Println("=== wxkey bootstrap ===")
		printedHeader = true
		fmt.Printf("[OK] key config already exists: %s\n", cfgPath)
		fmt.Printf("     wxid=%s db_root=%s keys=%d\n", cfg.WxID, cfg.DBRoot, len(cfg.Keys))
		fmt.Println("     sudo credential is stored in macOS Keychain; wechat-cli can refresh keys without SIP.")
		if configHasImageKey(cfg) {
			return
		}
		fmt.Println("[INFO] image_key is missing; continuing bootstrap to refresh image decoding key.")
	}

	if !printedHeader {
		fmt.Println("=== wxkey bootstrap ===")
	}
	if existingReady {
		fmt.Println("[INFO] Goal: refresh image_key in existing config with SIP enabled.")
		if f.root == "" {
			f.root = existingCfg.DBRoot
		}
	} else {
		fmt.Println("[INFO] Goal: prepare ~/.config/wxcli/config.json with SIP enabled.")
	}
	fmt.Println("[INFO] Admin password is stored once in macOS Keychain for unattended future setup/refresh.")

	if _, err := os.Stat(wechatAppPath); err != nil {
		fail("WeChat app not found at %s: %v", wechatAppPath, err)
	}

	setupFlags := f
	var cleanup func()
	sig := inspectWeChatSignature()
	if sig.Err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] WeChat signature check failed: %v\n", sig.Err)
		if sig.Raw != "" {
			fmt.Fprintf(os.Stderr, "       codesign output: %s\n", sig.Raw)
		}
	} else if sig.Runtime && !sig.AdHoc {
		if envTrue("WXKEY_BOOTSTRAP_ORIGINAL_WECHAT") {
			fmt.Println("[INFO] WeChat has official Hardened Runtime; applying explicit original-app resign route.")
			if err := runSelfPassthrough("resign-wechat"); err != nil {
				fail("resign-wechat failed: %v", err)
			}
		} else {
			fmt.Println("[INFO] WeChat has official Hardened Runtime; using wechat-cli shadow copy for no-SIP bootstrap.")
			pid, done, err := prepareShadowWeChat()
			if err != nil {
				fail("prepare shadow WeChat: %v", err)
			}
			setupFlags.pid = pid
			cleanup = done
		}
	} else if sig.AdHoc {
		fmt.Println("[OK]   WeChat is already ad-hoc signed.")
	} else {
		fmt.Println("[INFO] WeChat signature state is not recognized; trying setup directly.")
	}
	if cleanup != nil {
		defer cleanup()
	}

	if err := ensureWeChatReady(setupFlags.root, setupFlags.pid, 90*time.Second); err != nil {
		fail("%v", err)
	}

	if existingReady {
		fmt.Println("[INFO] Extracting image_key and updating config...")
		res, err := runImageKeyCaptured(setupFlags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[wxkey] image_key refresh failed during bootstrap.\n")
			fmt.Fprintf(os.Stderr, "        Open an image in WeChat so a *_t.dat sample exists, then rerun `wxkey bootstrap`.\n")
			fail("%v", err)
		}
		if res.ImageKey == nil || res.ImageKey.Key == "" {
			fail("image-key command returned no image_key")
		}
		if err := writeImageKeyToConfig(cfgPath, res.ImageKey.Key, res.ImageKey.XORKey); err != nil {
			fail("write image_key config: %v", err)
		}
		fmt.Println("[OK]   image_key config updated")
		fmt.Printf("       config: %s\n", cfgPath)
		fmt.Printf("       wxid: %s\n", existingCfg.WxID)
		fmt.Printf("       db_root: %s\n", existingCfg.DBRoot)
		fmt.Println("")
		fmt.Println("Done. wechat-cli can now decode local WeChat V4 image .dat into readable image paths.")
		return
	}

	fmt.Printf("[INFO] Extracting keys and writing config (timeout %s)...\n", setupTimeout().Round(time.Second))
	res, err := runSetupCaptured(setupFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[wxkey] setup failed during bootstrap.\n")
		fmt.Fprintf(os.Stderr, "        If WeChat just reopened, wait until it is fully logged in, open one chat, then rerun `wxkey bootstrap`.\n")
		fail("%v", err)
	}

	fmt.Println("[OK]   key config written")
	fmt.Printf("       config: %s\n", res.ConfigPath)
	fmt.Printf("       wxid: %s\n", res.WxID)
	fmt.Printf("       db_root: %s\n", res.Root)
	fmt.Printf("       keys: %d\n", len(res.Results))
	fmt.Println("")
	fmt.Println("Done. Start wechat-cli now; future key refresh uses stored sudo while SIP stays enabled.")
}

// --- helpers ---

func defaultConfigPath() string {
	return filepath.Join(effectiveUserHome(), ".config", "wxcli", "config.json")
}

func configReady(path string) (wxcliConfig, bool) {
	var cfg wxcliConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, false
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, false
	}
	return cfg, cfg.DBRoot != "" && len(cfg.Keys) > 0
}

func configHasImageKey(cfg wxcliConfig) bool {
	return strings.TrimSpace(cfg.ImageKey) != "" && cfg.ImageXORKey != nil
}

func readWxcliConfig(path string) (wxcliConfig, bool) {
	var cfg wxcliConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, false
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, false
	}
	return cfg, true
}

func sameAccountConfig(cfg wxcliConfig, wxid, root string) bool {
	return cfg.WxID == wxid && filepath.Clean(cfg.DBRoot) == filepath.Clean(root)
}

func runSelfPassthrough(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func shadowWeChatPath() string {
	if p := strings.TrimSpace(os.Getenv("WXKEY_SHADOW_WECHAT_APP")); p != "" {
		return p
	}
	return filepath.Join(effectiveUserHome(), "Library", "Application Support", "wx-mcp", "WeChat-shadow.app")
}

func prepareShadowWeChat() (int, func(), error) {
	shadowPath := shadowWeChatPath()
	hadWeChatRunning := false
	if pids, _ := wechatPIDs(); len(pids) > 0 {
		hadWeChatRunning = true
	}

	fmt.Println("[INFO] Preparing wechat-cli WeChat shadow copy...")
	if err := exec.Command("/usr/bin/killall", "WeChat").Run(); err != nil {
		// killall exits non-zero when WeChat is not running. That is fine here.
	}
	time.Sleep(2 * time.Second)

	if err := os.RemoveAll(shadowPath); err != nil {
		return 0, nil, fmt.Errorf("remove stale shadow copy %s: %w", shadowPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(shadowPath), 0o755); err != nil {
		return 0, nil, fmt.Errorf("mkdir shadow parent: %w", err)
	}
	if out, err := exec.Command("/bin/cp", "-R", wechatAppPath, shadowPath).CombinedOutput(); err != nil {
		return 0, nil, fmt.Errorf("copy WeChat to shadow path: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--deep", "--sign", "-", shadowPath).CombinedOutput(); err != nil {
		return 0, nil, fmt.Errorf("codesign shadow WeChat failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	sig := inspectAppSignature(shadowPath)
	if sig.Err != nil {
		return 0, nil, fmt.Errorf("inspect shadow WeChat signature: %w\n%s", sig.Err, sig.Raw)
	}
	if !sig.AdHoc {
		return 0, nil, fmt.Errorf("shadow WeChat is not ad-hoc signed after codesign:\n%s", sig.Raw)
	}

	fmt.Println("[INFO] Opening wechat-cli WeChat shadow copy...")
	if err := exec.Command("/usr/bin/open", "-n", shadowPath).Run(); err != nil {
		return 0, nil, fmt.Errorf("open shadow WeChat: %w", err)
	}
	pid, err := waitForWeChatPIDUnderApp(shadowPath, 90*time.Second)
	if err != nil {
		return 0, nil, err
	}

	cleanup := func() {
		if envTrue("WXKEY_KEEP_SHADOW_WECHAT") {
			return
		}
		_ = exec.Command("/bin/kill", "-TERM", strconv.Itoa(pid)).Run()
		time.Sleep(1 * time.Second)
		if hadWeChatRunning && !envTrue("WXKEY_NO_REOPEN_ORIGINAL_WECHAT") {
			_ = exec.Command("/usr/bin/open", wechatAppPath).Run()
		}
	}
	return pid, cleanup, nil
}

func waitForWeChatPIDUnderApp(appPath string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		pids, err := wechatPIDs()
		if err != nil {
			return 0, err
		}
		sort.Sort(sort.Reverse(sort.IntSlice(pids)))
		for _, pid := range pids {
			procPath, err := commandPathForPID(pid)
			if err != nil {
				continue
			}
			if pathInsideApp(procPath, appPath) {
				fmt.Printf("[OK]   shadow WeChat PID: %d\n", pid)
				return pid, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("shadow WeChat did not start from %s; open WeChat, finish login, open one chat, then rerun `wxkey bootstrap`", appPath)
		}
		time.Sleep(2 * time.Second)
	}
}

func commandPathForPID(pid int) (string, error) {
	out, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func pathInsideApp(procPath, appPath string) bool {
	procPath = filepath.Clean(procPath)
	appPath = filepath.Clean(appPath)
	rel, err := filepath.Rel(appPath, procPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func ensureWeChatReady(root string, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if pid == 0 {
		if pids, _ := wechatPIDs(); len(pids) == 0 {
			fmt.Println("[INFO] Opening WeChat...")
			_ = exec.Command("/usr/bin/open", wechatAppPath).Run()
		}
	} else if !pidAlive(pid) {
		fmt.Println("[INFO] Opening WeChat...")
		_ = exec.Command("/usr/bin/open", wechatAppPath).Run()
	}
	for {
		readyPID := false
		if pid > 0 {
			readyPID = pidAlive(pid)
		} else if _, err := pickWeChatPID(); err == nil {
			readyPID = true
		}
		if readyPID {
			if root != "" {
				if st, statErr := os.Stat(root); statErr == nil && st.IsDir() {
					return nil
				}
			} else if _, err := pickAccountRoot(); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("WeChat is not ready yet; open WeChat, finish login, open one chat, then rerun `wxkey bootstrap`")
		}
		time.Sleep(2 * time.Second)
	}
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return exec.Command("/bin/kill", "-0", strconv.Itoa(pid)).Run() == nil
}

func runSetupCaptured(f scanFlags) (*setupOutput, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"setup"}
	if f.pid > 0 {
		args = append(args, "--pid", strconv.Itoa(f.pid))
	}
	if f.root != "" {
		args = append(args, "--root", f.root)
	}
	if f.config != "" {
		args = append(args, "--config", f.config)
	}
	out, stderr, err := runChildCaptured(setupCommandTimeout(), exe, args...)
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg != "" {
			return nil, fmt.Errorf("setup command failed: %w\n%s", err, msg)
		}
		return nil, fmt.Errorf("setup command failed: %w", err)
	}
	payload := string(out)
	if i := strings.IndexByte(payload, '{'); i >= 0 {
		payload = payload[i:]
	}
	var res setupOutput
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		return nil, fmt.Errorf("parse setup output: %w (stdout %d bytes)", err, len(out))
	}
	return &res, nil
}

func runImageKeyCaptured(f scanFlags) (*imageKeyCommandOutput, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"image-key", "--quiet"}
	if f.pid > 0 {
		args = append(args, "--pid", strconv.Itoa(f.pid))
	}
	if f.root != "" {
		args = append(args, "--root", f.root)
	}
	out, stderr, err := runChildCaptured(75*time.Second, exe, args...)
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg != "" {
			return nil, fmt.Errorf("image-key command failed: %w\n%s", err, msg)
		}
		return nil, fmt.Errorf("image-key command failed: %w", err)
	}
	payload := string(out)
	if i := strings.IndexByte(payload, '{'); i >= 0 {
		payload = payload[i:]
	}
	var res imageKeyCommandOutput
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		return nil, fmt.Errorf("parse image-key output: %w (stdout %d bytes)", err, len(out))
	}
	return &res, nil
}

func setupTimeout() time.Duration {
	for _, name := range []string{"WXKEY_SETUP_TIMEOUT", "WXKEY_SCAN_TIMEOUT"} {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err == nil {
			return d
		}
		if sec, secErr := strconv.Atoi(raw); secErr == nil {
			return time.Duration(sec) * time.Second
		}
	}
	return defaultSetupTimeout
}

func setupCommandTimeout() time.Duration {
	scanTimeout := setupTimeout()
	if scanTimeout <= 0 {
		return 0
	}
	return scanTimeout + 30*time.Second
}

func runChildCaptured(timeout time.Duration, exe string, args ...string) ([]byte, string, error) {
	cmd := exec.Command(exe, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	if timeout <= 0 {
		err := <-done
		return stdout.Bytes(), stderr.String(), err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return stdout.Bytes(), stderr.String(), err
	case <-timer.C:
		killProcessGroup(cmd.Process.Pid)
		err := <-done
		if err == nil {
			err = fmt.Errorf("command exited after timeout")
		}
		return stdout.Bytes(), stderr.String(), fmt.Errorf("timed out after %s: %w", timeout.Round(time.Second), err)
	}
}

func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	time.Sleep(750 * time.Millisecond)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

func writeImageKeyToConfig(path, key string, xorKey *int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg wxcliConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.ImageKey = strings.TrimSpace(key)
	cfg.ImageXORKey = xorKey
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	chownToInvokingUser(path)
	chownToDirOwner(path)
	return nil
}

func effectiveUserHome() string {
	// reExecElevated forwards the invoking user's HOME explicitly when it
	// spawns the elevated (root) child via sudo. Trust that first —
	// stat /dev/console and SUDO_USER are both unreliable in non-sudo paths
	// (e.g. GUI prompts under fast user switching / locked screen /
	// headless sessions).
	if h := strings.TrimSpace(os.Getenv("WXKEY_ORIG_HOME")); h != "" {
		return h
	}
	if u := strings.TrimSpace(os.Getenv("SUDO_USER")); u != "" && u != "root" {
		return filepath.Join("/Users", u)
	}
	if os.Geteuid() == 0 {
		if out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output(); err == nil {
			u := strings.TrimSpace(string(out))
			if u != "" && u != "root" && u != "loginwindow" {
				return filepath.Join("/Users", u)
			}
		}
	}
	home, _ := os.UserHomeDir()
	return home
}

func wechatPIDs() ([]int, error) {
	out, err := exec.Command("/usr/bin/pgrep", "-x", "WeChat").Output()
	if err != nil {
		// pgrep returns exit 1 when no match - treat as empty list, not error.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && n > 0 {
			pids = append(pids, n)
		}
	}
	return pids, nil
}

func pickWeChatPID() (int, error) {
	pids, err := wechatPIDs()
	if err != nil {
		return 0, err
	}
	if len(pids) == 0 {
		return 0, fmt.Errorf("WeChat process not running")
	}
	// pick highest pid (most recent main process)
	max := pids[0]
	for _, p := range pids[1:] {
		if p > max {
			max = p
		}
	}
	return max, nil
}

// pickAccountRoot finds an active WeChat account directory under one of the
// known WeChat 4.x storage roots. Returns the directory whose db_storage
// has the most recently-modified file (i.e., the live account).
func pickAccountRoot() (string, error) {
	home := effectiveUserHome()
	roots := []string{
		filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "xwechat_files"),
	}
	// WeChat 4.0.5+: Application Support/com.tencent.xinWeChat/<version>/<wxid>/
	asRoot := filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat")
	if entries, err := os.ReadDir(asRoot); err == nil {
		for _, e := range entries {
			if e.IsDir() && (strings.Contains(e.Name(), "b") || strings.Count(e.Name(), ".") >= 2) {
				roots = append(roots, filepath.Join(asRoot, e.Name()))
			}
		}
	}

	type cand struct {
		path  string
		mtime int64
	}
	var cands []cand
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isBoringDir(name) {
				continue
			}
			account := filepath.Join(root, name)
			dbStore := filepath.Join(account, "db_storage")
			if st, err := os.Stat(dbStore); err == nil && st.IsDir() {
				cands = append(cands, cand{account, st.ModTime().Unix()})
			}
		}
	}
	if len(cands) == 0 {
		return "", buildNoAccountDirError(roots)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mtime > cands[j].mtime })
	return cands[0].path, nil
}

func isBoringDir(name string) bool {
	switch strings.ToLower(name) {
	case "xwechat_files", "all_users", "backup", "wmpf", "app_data":
		return true
	}
	return false
}

func collapseResults(results map[string]scan.Result) []scan.Result {
	out := make([]scan.Result, 0, len(results))
	for _, r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DBRel < out[j].DBRel })
	return out
}

func progressFn(quiet bool) scan.ProgressFn {
	return offsetProgressFn(quiet, 0)
}

func offsetProgressFn(quiet bool, elapsedOffset time.Duration) scan.ProgressFn {
	if quiet {
		return nil
	}
	last := time.Now()
	return func(s scan.Stats) {
		if time.Since(last) < 500*time.Millisecond {
			return
		}
		last = time.Now()
		s.Elapsed += elapsedOffset
		fmt.Fprintf(os.Stderr, "[wxkey] scanned %.0f MB / %d regions, %d hits, %d verified, found=%d\n",
			float64(s.BytesScanned)/1024/1024, s.Regions, s.HexMatches, s.Verifications, s.Found)
	}
}

func writeJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail("marshal json: %v", err)
	}
	fmt.Println(string(data))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[wxkey] ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func dieUsage(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n\n", args...)
	fmt.Fprint(os.Stderr, usage)
	os.Exit(2)
}

func logf(quiet bool, format string, args ...any) {
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format, args...)
}

func envTrue(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}

func isPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "task_for_pid") &&
		(strings.Contains(msg, "kr=5") || strings.Contains(msg, "kr=4"))
}

const sudoKeychainService = "r266.wx-mcp.sudo"

func sudoKeychainAccount() string {
	if u := strings.TrimSpace(os.Getenv("WXKEY_ORIG_USER")); u != "" && u != "root" {
		return u
	}
	if u := strings.TrimSpace(os.Getenv("SUDO_USER")); u != "" && u != "root" {
		return u
	}
	if cu, err := userpkg.Current(); err == nil {
		if cu.Username != "" && cu.Username != "root" {
			return cu.Username
		}
	}
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		return u
	}
	return "wx-mcp"
}

func ensureStoredSudoPassword() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if pw, err := readStoredSudoPassword(); err == nil {
		if err := sudoValidatePassword(pw); err == nil {
			return nil
		}
	}
	pw, err := promptSudoPasswordGUI()
	if err != nil {
		return err
	}
	if err := sudoValidatePassword(pw); err != nil {
		return fmt.Errorf("sudo password rejected: %w", err)
	}
	if err := storeSudoPassword(pw); err != nil {
		return err
	}
	return nil
}

func readStoredSudoPassword() (string, error) {
	cmd := exec.Command("/usr/bin/security", "find-generic-password",
		"-a", sudoKeychainAccount(),
		"-s", sudoKeychainService,
		"-w")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(out), "\r\n")
	if pw == "" {
		return "", fmt.Errorf("stored sudo password is empty")
	}
	return pw, nil
}

func storeSudoPassword(password string) error {
	script := fmt.Sprintf("add-generic-password -a %s -s %s -l %s -j %s -U -X %s\n",
		securityArgQuote(sudoKeychainAccount()),
		securityArgQuote(sudoKeychainService),
		securityArgQuote("wechat-cli sudo password"),
		securityArgQuote("Stored by wxkey for unattended no-SIP WeChat DB key refresh"),
		hex.EncodeToString([]byte(password)),
	)
	cmd := exec.Command("/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(script)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("store sudo password in Keychain: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func securityArgQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func promptSudoPasswordGUI() (string, error) {
	script := `display dialog "wechat-cli needs your Mac admin password once. It will be stored in your macOS Keychain so future WeChat key refreshes can run unattended without disabling SIP." default answer "" with hidden answer buttons {"Cancel", "Store"} default button "Store" cancel button "Cancel" with title "wechat-cli setup"`
	cmd := exec.Command("/usr/bin/osascript", "-e", script, "-e", "text returned of result")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("sudo password prompt cancelled or failed: %w", err)
	}
	pw := strings.TrimRight(string(out), "\r\n")
	if pw == "" {
		return "", fmt.Errorf("empty sudo password")
	}
	return pw, nil
}

func sudoValidatePassword(password string) error {
	cmd := exec.Command("sudo", "-S", "-p", "", "-v")
	cmd.Stdin = strings.NewReader(password + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func sudoCommandWithPassword(password string, args ...string) *exec.Cmd {
	cmd := exec.Command("sudo", append([]string{"-S", "-p", ""}, args...)...)
	cmd.Stdin = strings.NewReader(password + "\n")
	return cmd
}

// buildElevateFailHint composes an actionable hint when stored-sudo
// auto-elevation fails.
func buildElevateFailHint(reErr, origErr error) string {
	if strings.Contains(reErr.Error(), "scan deadline exceeded") || strings.Contains(reErr.Error(), "no keys found") {
		var b strings.Builder
		fmt.Fprintf(&b, "elevated key scan failed: %v\n", reErr)
		fmt.Fprintln(&b, "")
		fmt.Fprintln(&b, "       The stored-sudo/task_for_pid route worked, but wxkey did not find a")
		fmt.Fprintln(&b, "       usable DB key before the scan finished. Keep WeChat open, open one")
		fmt.Fprintln(&b, "       chat/page that needs decrypting, then rerun `wxkey setup` or")
		fmt.Fprintln(&b, "       `wxkey bootstrap`. Do not disable SIP.")
		return b.String()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auto-elevate via stored sudo credential failed: %v\n", reErr)
	fmt.Fprintf(&b, "       original permission error: %v\n", origErr)
	fmt.Fprintln(&b, "")
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != "" {
		fmt.Fprintln(&b, "       You appear to be on SSH. Run `wxkey bootstrap` once from the Mac's")
		fmt.Fprintln(&b, "       desktop session so wxkey can collect and store the sudo password in")
		fmt.Fprintln(&b, "       Keychain. Later setup runs can be unattended.")
	} else {
		fmt.Fprintln(&b, "       Re-run `wxkey bootstrap` once and enter the Mac admin password in the")
		fmt.Fprintln(&b, "       wechat-cli hidden prompt. wxkey will verify it and store it in Keychain.")
	}
	return b.String()
}

// buildNoAccountDirError lists each scanned root and the subdirectories
// observed, marking why each was skipped, so the user can see whether their
// account dir is missing entirely (WeChat not installed/logged in) or merely
// missing db_storage/ (logged in but never synced messages).
func buildNoAccountDirError(roots []string) error {
	var b strings.Builder
	fmt.Fprintln(&b, "no WeChat 4.x account directory with db_storage/ found.")
	for _, root := range roots {
		fmt.Fprintf(&b, "       scanned: %s\n", root)
		entries, err := os.ReadDir(root)
		if err != nil {
			fmt.Fprintf(&b, "         (read failed: %v)\n", err)
			continue
		}
		anyDir := false
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			anyDir = true
			name := e.Name()
			if isBoringDir(name) {
				fmt.Fprintf(&b, "         %s/   (skipped: not an account dir)\n", name)
				continue
			}
			dbStore := filepath.Join(root, name, "db_storage")
			if _, err := os.Stat(dbStore); err != nil {
				fmt.Fprintf(&b, "         %s/   (no db_storage/ subdirectory yet)\n", name)
			} else {
				fmt.Fprintf(&b, "         %s/   (has db_storage but not picked — please file a bug)\n", name)
			}
		}
		if !anyDir {
			fmt.Fprintln(&b, "         (empty)")
		}
	}
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "       Hint: open WeChat 4.x, finish login, then send or receive at least one")
	fmt.Fprintln(&b, "       message. WeChat creates db_storage/ only after the first DB write. Then")
	fmt.Fprintln(&b, "       re-run `wxkey bootstrap`.")
	return fmt.Errorf("%s", b.String())
}

const wechatAppPath = "/Applications/WeChat.app"

type wechatSignatureStatus struct {
	Raw     string
	AdHoc   bool
	Runtime bool
	Err     error
}

func classifyWeChatSignature(raw string) wechatSignatureStatus {
	low := strings.ToLower(raw)
	return wechatSignatureStatus{
		Raw:     strings.TrimSpace(raw),
		AdHoc:   strings.Contains(low, "signature=adhoc") || strings.Contains(low, "(adhoc)"),
		Runtime: strings.Contains(low, "(runtime)") || strings.Contains(low, "flags=0x10000"),
	}
}

func inspectWeChatSignature() wechatSignatureStatus {
	return inspectAppSignature(wechatAppPath)
}

func inspectAppSignature(appPath string) wechatSignatureStatus {
	out, err := exec.Command("/usr/bin/codesign", "-dv", appPath).CombinedOutput()
	st := classifyWeChatSignature(string(out))
	st.Err = err
	return st
}

func printPermissionAdvice(quiet bool, original error) {
	if quiet {
		fmt.Fprintln(os.Stderr, "wxkey: task_for_pid denied. Run `wxkey doctor` for details or `wxkey resign-wechat` to use the no-SIP setup route.")
		return
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "[FAIL] task_for_pid 被拒, 暂时无法读取 WeChat 进程内存拿 key.")
	if original != nil {
		fmt.Fprintf(os.Stderr, "       原始错误: %v\n", original)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "       wechat-cli 的运行时解密不需要关闭 SIP; 取 key 只需要 no-SIP 重签 + 已存储的 sudo 凭据.")

	if disabled, raw := sipDisabled(); raw != "" {
		if disabled {
			fmt.Fprintln(os.Stderr, "       SIP: 已关闭. 如果仍失败, 多半是未以管理员运行、WeChat 未登录、或 TCC/签名限制.")
		} else {
			fmt.Fprintf(os.Stderr, "       SIP: 已启用 (%s). 这是支持状态; 不要进 Recovery 关 SIP.\n", raw)
		}
	}

	sig := inspectWeChatSignature()
	if sig.Err != nil {
		fmt.Fprintf(os.Stderr, "       WeChat 签名检测失败: %v\n", sig.Err)
		if sig.Raw != "" {
			fmt.Fprintf(os.Stderr, "       codesign 输出: %s\n", sig.Raw)
		}
	} else if sig.AdHoc {
		fmt.Fprintln(os.Stderr, "       WeChat 签名: ad-hoc, 已是推荐状态. 请先跑 `wxkey bootstrap` 存储 sudo 凭据")
	} else if sig.Runtime {
		fmt.Fprintln(os.Stderr, "       WeChat 签名: 官方 Hardened Runtime. 推荐执行一次:")
		fmt.Fprintln(os.Stderr, "         ./wxkey resign-wechat")
		fmt.Fprintln(os.Stderr, "       然后等 WeChat 完全登录并打开一个聊天, 再跑:")
		fmt.Fprintln(os.Stderr, "         wxkey setup")
	} else {
		fmt.Fprintln(os.Stderr, "       WeChat 签名: 未识别. 可先跑 `wxkey doctor` 查看详情.")
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "       不支持通过关闭 SIP 作为安装路径; 修复 no-SIP sudo/Keychain 路径.")
}

// sipDisabled parses `csrutil status`. Returns disabled=true only if csrutil
// runs cleanly AND output explicitly says disabled. Indeterminate cases
// (csrutil missing / output unparseable) return (false, "") so the caller
// knows to skip the soft block — we'd rather let the real task_for_pid
// syscall fail loudly than risk a false-positive prompt to disable SIP.
func sipDisabled() (disabled bool, raw string) {
	out, err := exec.Command("/usr/bin/csrutil", "status").CombinedOutput()
	if err != nil {
		return false, ""
	}
	raw = strings.TrimSpace(string(out))
	low := strings.ToLower(raw)
	if strings.Contains(low, "disabled") {
		return true, raw
	}
	if strings.Contains(low, "enabled") {
		return false, raw
	}
	return false, ""
}

// reExecElevated re-launches this binary under sudo with administrator
// privileges, blocking until it exits, and forwards stdout/stderr. It also
// forwards the invoking user's HOME and USER so the elevated (root) child
// can locate `~/Library/Containers/com.tencent.xinWeChat/...` belonging to
// the desktop user — `stat /dev/console` alone is unreliable (e.g. fast
// user switching, screen locked, headless sessions all break it).
func reExecElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	pw, err := readStoredSudoPassword()
	if err != nil {
		if err := ensureStoredSudoPassword(); err != nil {
			return err
		}
		pw, err = readStoredSudoPassword()
		if err != nil {
			return err
		}
	}
	origHome, _ := os.UserHomeDir()
	origUser := os.Getenv("USER")
	if origUser == "" {
		if cu, err := userpkg.Current(); err == nil {
			origUser = cu.Username
		}
	}
	args := []string{"env",
		"WXKEY_ELEVATED=1",
		"WXKEY_ORIG_HOME=" + origHome,
		"WXKEY_ORIG_USER=" + origUser,
	}
	for _, name := range []string{"WXKEY_SETUP_TIMEOUT", "WXKEY_SCAN_TIMEOUT"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			args = append(args, name+"="+value)
		}
	}
	args = append(args, exe)
	args = append(args, os.Args[1:]...)
	cmd := sudoCommandWithPassword(pw, args...)
	cmd.Stdout = os.Stdout
	var stderr strings.Builder
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	if err := cmd.Run(); err != nil {
		if tail := tailLines(stderr.String(), 8); tail != "" {
			return fmt.Errorf("%w\n%s", err, tail)
		}
		return err
	}
	return nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 || (len(lines) == 1 && strings.TrimSpace(lines[0]) == "") {
		return ""
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func runResignWeChat() {
	if os.Geteuid() != 0 && !envTrue("WXKEY_NO_ELEVATE") && !envTrue("WXKEY_ELEVATED") {
		fmt.Fprintln(os.Stderr, "[wxkey] re-launching resign-wechat via stored sudo credential...")
		if err := reExecElevated(); err != nil {
			fail("re-elevate resign-wechat: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		fail("resign-wechat requires administrator privileges; run `wxkey bootstrap` once to store sudo credentials")
	}

	fmt.Println("=== wxkey resign-wechat ===")
	if _, err := os.Stat(wechatAppPath); err != nil {
		fail("WeChat app not found at %s: %v", wechatAppPath, err)
	}

	fmt.Println("[1/4] Quitting WeChat if it is running...")
	_ = exec.Command("/usr/bin/killall", "WeChat").Run()
	time.Sleep(2 * time.Second)

	fmt.Println("[2/4] Ad-hoc signing /Applications/WeChat.app...")
	out, err := runCodesignWeChat()
	if err != nil && strings.Contains(string(out), "signature in use") {
		plugin := filepath.Join(wechatAppPath, "Contents", "Frameworks", "vlc_plugins", "librtp_mpeg4_plugin.dylib")
		if _, statErr := os.Stat(plugin); statErr == nil {
			fmt.Println("      codesign reported signature in use; removing nested plugin signature and retrying...")
			rmOut, rmErr := exec.Command("/usr/bin/codesign", "--remove-signature", plugin).CombinedOutput()
			if rmErr != nil {
				fail("remove nested signature failed: %v\n%s", rmErr, strings.TrimSpace(string(rmOut)))
			}
			out, err = runCodesignWeChat()
		}
	}
	if err != nil {
		fail("codesign WeChat failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	fmt.Println("[3/4] Verifying signature state...")
	sig := inspectWeChatSignature()
	if sig.Err != nil {
		fail("inspect WeChat signature after resign failed: %v\n%s", sig.Err, sig.Raw)
	}
	if !sig.AdHoc {
		fail("WeChat signature is still not ad-hoc after codesign:\n%s", sig.Raw)
	}
	fmt.Println("      WeChat signature is ad-hoc.")

	fmt.Println("[4/4] Reopening WeChat...")
	if err := exec.Command("/usr/bin/open", wechatAppPath).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] open WeChat failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "       Ask the user to open WeChat manually and wait for login; then the agent should run `wxkey setup`.")
		return
	}

	fmt.Println("")
	fmt.Println("Done. After WeChat is fully logged in and you have opened at least one chat, run:")
	fmt.Println("  wxkey setup")
}

func runCodesignWeChat() ([]byte, error) {
	if os.Geteuid() == 0 {
		return exec.Command("/usr/bin/codesign", "--force", "--deep", "--sign", "-", wechatAppPath).CombinedOutput()
	}
	pw, err := readStoredSudoPassword()
	if err != nil {
		return nil, err
	}
	cmd := sudoCommandWithPassword(pw, "/usr/bin/codesign", "--force", "--deep", "--sign", "-", wechatAppPath)
	return cmd.CombinedOutput()
}

// startOrphanWatchdog runs only in elevated children spawned via sudo.
// reExecElevated chains user → sudo → root wxkey. If anyone above
// dies (parent CC kill, user cancels admin prompt, TaskStop on the unprivileged
// wxkey), the root child gets reparented to launchd (PPID=1). Without this,
// it keeps holding task_for_pid + scanning, can't be killed by the user, and
// blocks every subsequent setup invocation.
func startOrphanWatchdog() {
	if os.Getenv("WXKEY_ELEVATED") != "1" {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if os.Getppid() == 1 {
				fmt.Fprintln(os.Stderr, "[wxkey] elevated parent died (PPID=1), exiting to avoid leaking root scan")
				os.Exit(130)
			}
		}
	}()
}

// runDoctor is a read-only health check. By default it compares the cached key
// config against local DB salts, so partial-coverage diagnosis does not trigger
// another slow memory scan. Pass --scan for the live task_for_pid/key check.
// Does not write any config — safe to run any time.
func runDoctor(args []string) {
	f := parseFlags(args)
	logf := func(format string, a ...any) {
		if !f.quiet {
			fmt.Printf(format, a...)
		}
	}

	logf("=== wxkey doctor ===\n")

	if disabled, raw := sipDisabled(); !disabled && raw != "" {
		logf("[INFO] SIP 已启用: %s\n", raw)
		logf("       这不是硬性失败; 推荐路线是 ad-hoc 重签 WeChat 后用管理员权限取 key.\n")
	} else if disabled {
		logf("[OK]   SIP 已关闭\n")
	} else {
		logf("[INFO] csrutil 不可用, 跳过 SIP 预检\n")
	}

	sig := inspectWeChatSignature()
	if sig.Err != nil {
		logf("[WARN] WeChat 签名检测失败: %v\n", sig.Err)
		if sig.Raw != "" {
			logf("       codesign 输出: %s\n", sig.Raw)
		}
	} else if sig.AdHoc {
		logf("[OK]   WeChat 签名: ad-hoc (推荐的 no-SIP 取 key 状态)\n")
	} else if sig.Runtime {
		logf("[WARN] WeChat 签名: 官方 Hardened Runtime\n")
		logf("       若 task_for_pid 被拒, 跑 `wxkey bootstrap` 存储 sudo 凭据并重签 WeChat, 不要关闭 SIP.\n")
	} else {
		logf("[INFO] WeChat 签名: 未识别\n")
		if sig.Raw != "" {
			logf("       %s\n", sig.Raw)
		}
	}

	pids, _ := wechatPIDs()
	if len(pids) == 0 {
		logf("[FAIL] WeChat 进程未在运行\n")
		logf("       请先启动 WeChat 并登录账号，再重跑 doctor\n")
		os.Exit(1)
	}
	pid := pids[0]
	for _, p := range pids[1:] {
		if p > pid {
			pid = p
		}
	}
	if f.pid > 0 {
		pid = f.pid
	}
	logf("[OK]   WeChat 进程: PID %d\n", pid)

	root := f.root
	if root == "" {
		r, err := pickAccountRoot()
		if err != nil {
			logf("[FAIL] WeChat 账号目录未找到: %v\n", err)
			logf("       请确认 WeChat 已登录\n")
			os.Exit(1)
		}
		root = r
	}
	wxid := filepath.Base(root)
	logf("[OK]   WeChat 账号: %s\n", wxid)
	logf("       db_root: %s\n", root)

	dbs, saltIdx, err := dbfiles.Collect(root)
	if err != nil {
		logf("[FAIL] DB 枚举失败: %v\n", err)
		os.Exit(1)
	}
	logf("[OK]   DB 文件: %d 个 (unique salts: %d)\n", len(dbs), len(saltIdx))

	if dylib := findBundledDylib(); dylib != "" {
		logf("[OK]   libWCDB.dylib: %s\n", dylib)
	} else {
		logf("[WARN] libWCDB.dylib 未找到 — wechat-cli 启动时会失败\n")
		logf("       放到 wechat-cli 旁边或 ~/.config/wxcli/lib/\n")
	}

	cfgPath := f.config
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	cfg, cfgOK := configReady(cfgPath)
	if cfgOK {
		logf("[OK]   key config: %s\n", cfgPath)
		logf("       wxid=%s db_root=%s cached_keys=%d\n", cfg.WxID, cfg.DBRoot, len(cfg.Keys))
		if cfg.DBRoot != "" && cfg.DBRoot != root {
			logf("[WARN] key config db_root 与当前账号目录不同; cached coverage 可能不适用\n")
		}
		foundSalts := cachedFoundSalts(cfg.Keys, saltIdx)
		if len(foundSalts) == len(saltIdx) {
			logf("[OK]   Cached key 覆盖率: %d/%d (100%%) — 当前 DB salts 都有缓存 key\n",
				len(foundSalts), len(saltIdx))
		} else {
			coverage := float64(len(foundSalts)) / float64(len(saltIdx)) * 100
			logf("[WARN] Cached key 覆盖率: %d/%d (%.0f%%) — %d 个 DB salt 没有缓存 key\n",
				len(foundSalts), len(saltIdx), coverage, len(saltIdx)-len(foundSalts))
			printMissingDBs(logf, dbs, saltIdx, foundSalts)
		}
	} else {
		logf("[WARN] key config 不存在或为空: %s\n", cfgPath)
		logf("       Agent 应先跑 `wxkey bootstrap`; 若已存 sudo 凭据, 可跑 `wxkey setup` 写 config.\n")
	}

	if !f.liveScan {
		logf("\n[INFO] 默认跳过实际内存 scan，避免重复等待。需要验证 task_for_pid/当前 heap 覆盖率时再跑 `wxkey doctor --scan`。\n")
		return
	}

	if os.Geteuid() != 0 {
		logf("\n[INFO] 未以 root 运行，跳过实际 scan\n")
		logf("       完整 live-scan 诊断请先跑: wxkey bootstrap; 然后重试 wxkey doctor --scan\n")
		return
	}

	logf("\n[INFO] 跑实际内存 scan (~2 分钟，验证 task_for_pid + key 覆盖率)...\n")
	results, stats, err := scan.RunWithOptions(int32(pid), dbs, saltIdx,
		scan.Options{IncludeBareHex: true}, progressFn(f.quiet))
	if err != nil {
		logf("[FAIL] Memory scan 失败: %v\n", err)
		if isPermissionErr(err) {
			printPermissionAdvice(f.quiet, err)
		}
		os.Exit(1)
	}

	logf("[OK]   task_for_pid + mach_vm_read 工作正常\n")
	logf("       %d regions, %d MB scanned, %d wrapped + %d bare-hex matches, %d verifies\n",
		stats.Regions, stats.BytesScanned/1024/1024, stats.HexMatches, stats.BareHexMatches, stats.Verifications)
	logf("       elapsed: %s\n", stats.Elapsed.Round(time.Second))

	foundSalts := make(map[string]bool, len(results))
	for s := range results {
		foundSalts[s] = true
	}

	if len(results) == len(saltIdx) {
		logf("[OK]   Key 覆盖率: %d/%d (100%%) — 所有 DB 都拿到了 key\n",
			len(results), len(saltIdx))
		logf("\n=== 全部就绪 ===\n")
		logf("Agent 跑 `wxkey setup` 写 config, 然后启动 wechat-cli\n")
		return
	}

	coverage := float64(len(results)) / float64(len(saltIdx)) * 100
	logf("[WARN] Key 覆盖率: %d/%d (%.0f%%) — %d 个 DB 没拿到 key\n",
		len(results), len(saltIdx), coverage, len(saltIdx)-len(results))
	printMissingDBs(logf, dbs, saltIdx, foundSalts)
	logf("\n=== 部分覆盖 ===\n")
	logf("Agent 下一步: 提示用户只在 WeChat 里打开缺的聊天/朋友圈/收藏，触发 WCDB 加载那些 DB key，然后由 agent 重跑 `wxkey setup`\n")
	logf("也可以暂时接受部分覆盖: 已拿到 key 的 DB 可继续支持大部分 wechat-cli 功能\n")
}

func cachedFoundSalts(keys map[string]string, saltIdx map[string][]int) map[string]bool {
	found := make(map[string]bool)
	for salt := range saltIdx {
		if _, ok := keys[hex.EncodeToString([]byte(salt))]; ok {
			found[salt] = true
		}
	}
	return found
}

func printMissingDBs(logf func(string, ...any), dbs []dbfiles.DB, saltIdx map[string][]int, foundSalts map[string]bool) {
	logf("\n       缺 key 的 DB (最常见原因: WeChat 里还没打开过这个聊天/页面):\n")
	var missing []string
	for salt, idxs := range saltIdx {
		if foundSalts[salt] {
			continue
		}
		for _, i := range idxs {
			missing = append(missing, dbs[i].Rel)
		}
	}
	sort.Strings(missing)
	for _, p := range missing {
		logf("         - %s\n", p)
	}
}

// findBundledDylib hunts libWCDB.dylib in the same locations wechat-cli does.
// Used by `wxkey doctor` for human reporting (not for actually loading the
// dylib — wxkey itself doesn't link against WCDB).
func findBundledDylib() string {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			dir := filepath.Dir(exe)
			candidates = append(candidates,
				filepath.Join(dir, "lib", "libWCDB.dylib"),
				filepath.Join(dir, "libWCDB.dylib"),
				filepath.Join(dir, "..", "wx-mcp", "lib", "libWCDB.dylib"),
			)
		}
	}
	home := effectiveUserHome()
	candidates = append(candidates,
		filepath.Join(home, ".config", "wxcli", "lib", "libWCDB.dylib"),
	)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// chownToDirOwner makes a freshly-written file owned by the same user as its
// parent directory. wxkey runs `setup` as root via stored sudo, so the
// config file lands as root:wheel and the unprivileged caller (wechat-cli / shell)
// then can't read it on the next start, looping forever into wxkey setup.
// No-op when not running as root.
func chownToDirOwner(path string) {
	if os.Geteuid() != 0 {
		return
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = os.Chown(path, int(sys.Uid), int(sys.Gid))
}

func chownToInvokingUser(path string) {
	if os.Geteuid() != 0 {
		return
	}
	home := effectiveUserHome()
	info, err := os.Stat(home)
	if err != nil {
		return
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = os.Chown(path, int(sys.Uid), int(sys.Gid))
}
