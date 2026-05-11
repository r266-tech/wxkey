// wxkey extracts WeChat 4.x WCDB master keys from the live WeChat process on
// macOS. Pure Go (purego + Mach VM syscalls). Passively scans WeChat's heap
// for the SQL literal `x'<hex>'` that WCDB constructs when forwarding keys to
// sqlite3_key_v2, then verifies each candidate via SQLCipher 4 page-1 HMAC.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
  wxkey scan       [--pid N] [--root /path/to/xwechat_files/<wxid>] [--quiet]
  wxkey setup      [--pid N] [--root ...] [--config ~/.config/wxcli/config.json]
  wxkey doctor     [--pid N] [--root ...] [--quiet]
  wxkey resign-wechat
  wxkey list-pids
  wxkey -h | --help

Subcommands:
  bootstrap   One-command first-run setup for humans/agents: checks existing
              config, ad-hoc re-signs WeChat when needed, runs setup, and only
              prints a summary (not key material).
  scan        Scan WeChat memory and print JSON: {pid, root, stats, results[]}.
              results[] entries map a DB salt to its 64-hex master key.
  setup       Like scan, but also writes ~/.config/wxcli/config.json so wx-mcp
              can pick up the key on next start. Picks the most populated DB
              under root to publish (typically contact.db or message db).
  doctor      Read-only health check: WeChat process, account dir, DB count,
              libWCDB.dylib presence, task_for_pid permission, key coverage
              (which DBs have keys in heap vs which are missing). Auto-elevates
              for the actual memory scan. Run this first if mcp/wxkey behaves
              unexpectedly — it tells you what's missing without writing config.
  resign-wechat
              Apply the recommended no-SIP route: quit WeChat, ad-hoc re-sign
              /Applications/WeChat.app, then reopen it. Run once after each
              WeChat update if task_for_pid is denied.
  list-pids   Print one WeChat PID per line (or empty if not running).

Notes:
  - WeChat must be running and have opened at least one DB this session.
  - wx-mcp runtime DB decryption does not require SIP-disabled. First-time key
    extraction only needs a readable WeChat task port: ad-hoc-signed WeChat +
    admin privileges is the recommended route; SIP-disabled is only a fallback.
  - wxkey will re-launch itself via osascript if the direct attach fails (set
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
	PID     int           `json:"pid"`
	Root    string        `json:"scan_root"`
	WxID    string        `json:"wxid"`
	Stats   scan.Stats    `json:"stats"`
	Results []scan.Result `json:"results"`
}

type setupOutput struct {
	scanOutput
	ConfigPath string `json:"config_path,omitempty"`
}

// wxcliConfig is the on-disk schema written to ~/.config/wxcli/config.json
// after a successful `wxkey setup`. The "keys" map carries one per-DB
// SQLCipher 4 enc_key (post-PBKDF2) per file salt. wx-mcp passes them to
// sqlite3_key_v2 as 96-hex `x'<key><salt>'` SQL literals (raw-key path),
// avoiding the 256000-round PBKDF2 on every DB open.
//
// "key" (legacy) is the user-supplied master password — kept on
// re-runs only if it was already there, so older wx-mcp builds keep working
// until they ship the new code.
type wxcliConfig struct {
	SchemaVersion int               `json:"schema_version"`
	WxID          string            `json:"wxid"`
	DBRoot        string            `json:"db_root"`
	Keys          map[string]string `json:"keys"`
	KeyEpoch      int64             `json:"key_epoch"`
	Key           string            `json:"key,omitempty"` // legacy master password (preserved if present)
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

	// WCDB v4 stores enc_keys in WeChat heap as bare 64-hex ASCII strings,
	// not as `x'...'` SQL literals. setup must always enable bare-hex scanning
	// or it finds zero keys. The flag remains overridable for `scan` alone
	// (debugging — the wrapped-only pass is faster but useless for wx-mcp).
	includeBareHex := f.includeBareHex || doSetup
	results, stats, err := scan.RunWithOptions(int32(pid), dbs, saltIdx,
		scan.Options{IncludeBareHex: includeBareHex},
		progressFn(f.quiet))
	if err != nil {
		// Auto-elevate on permission failure.
		if isPermissionErr(err) && !envTrue("WXKEY_NO_ELEVATE") && !envTrue("WXKEY_ELEVATED") {
			logf(f.quiet, "[wxkey] task_for_pid denied; re-launching via osascript admin...\n")
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

	wxid := filepath.Base(root)

	out := scanOutput{
		PID:     pid,
		Root:    root,
		WxID:    wxid,
		Stats:   stats,
		Results: collapseResults(results),
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

	// Preserve any existing legacy "key" field so older wx-mcp builds keep
	// working until V upgrades. We don't carry over old "keys" map — the
	// fresh scan supersedes it.
	var legacyKey string
	if existing, err := os.ReadFile(cfgPath); err == nil {
		var prior wxcliConfig
		if json.Unmarshal(existing, &prior) == nil {
			legacyKey = prior.Key
		}
	}

	keysMap := make(map[string]string, len(out.Results))
	for _, r := range out.Results {
		keysMap[r.SaltHex] = r.KeyHex
	}

	cfg := wxcliConfig{
		SchemaVersion: 2,
		WxID:          wxid,
		DBRoot:        root,
		Keys:          keysMap,
		KeyEpoch:      time.Now().Unix(),
		Key:           legacyKey,
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append(data, '\n')
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		fail("write config: %v", err)
	}
	chownToInvokingUser(cfgPath)
	chownToDirOwner(cfgPath)
	if len(out.Results) < len(saltIdx) {
		fmt.Fprintf(os.Stderr, "[wxkey] WARNING: 部分 key 缺失 (%d/%d). 跑 `sudo wxkey doctor` 看哪些 DB 没拿到 key, 通常是因为还没在 WeChat 里打开过那个聊天。\n",
			len(out.Results), len(saltIdx))
	}
	writeJSON(setupOutput{scanOutput: out, ConfigPath: cfgPath})
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

func runBootstrap(args []string) {
	f := parseFlags(args)
	cfgPath := f.config
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if cfg, ok := configReady(cfgPath); ok {
		fmt.Println("=== wxkey bootstrap ===")
		fmt.Printf("[OK] key config already exists: %s\n", cfgPath)
		fmt.Printf("     wxid=%s db_root=%s keys=%d\n", cfg.WxID, cfg.DBRoot, len(cfg.Keys))
		fmt.Println("     wx-mcp can start now; no SIP change needed.")
		return
	}

	fmt.Println("=== wxkey bootstrap ===")
	fmt.Println("[INFO] Goal: prepare ~/.config/wxcli/config.json without requiring SIP-disabled.")

	if _, err := os.Stat(wechatAppPath); err != nil {
		fail("WeChat app not found at %s: %v", wechatAppPath, err)
	}

	sig := inspectWeChatSignature()
	if sig.Err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] WeChat signature check failed: %v\n", sig.Err)
		if sig.Raw != "" {
			fmt.Fprintf(os.Stderr, "       codesign output: %s\n", sig.Raw)
		}
	} else if sig.Runtime && !sig.AdHoc {
		fmt.Println("[INFO] WeChat has official Hardened Runtime; applying recommended no-SIP resign route.")
		if err := runSelfPassthrough("resign-wechat"); err != nil {
			fail("resign-wechat failed: %v", err)
		}
	} else if sig.AdHoc {
		fmt.Println("[OK]   WeChat is already ad-hoc signed.")
	} else {
		fmt.Println("[INFO] WeChat signature state is not recognized; trying setup directly.")
	}

	if err := ensureWeChatReady(f.root, 90*time.Second); err != nil {
		fail("%v", err)
	}

	fmt.Println("[INFO] Extracting keys and writing config...")
	res, err := runSetupCaptured(f)
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
	fmt.Println("Done. Register/start wx-mcp now; runtime DB decryption does not require SIP-disabled.")
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

func ensureWeChatReady(root string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if pids, _ := wechatPIDs(); len(pids) == 0 {
		fmt.Println("[INFO] Opening WeChat...")
		_ = exec.Command("/usr/bin/open", wechatAppPath).Run()
	}
	for {
		if _, err := pickWeChatPID(); err == nil {
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

func runSetupCaptured(f scanFlags) (*setupOutput, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"setup", "--quiet"}
	if f.pid > 0 {
		args = append(args, "--pid", strconv.Itoa(f.pid))
	}
	if f.root != "" {
		args = append(args, "--root", f.root)
	}
	if f.config != "" {
		args = append(args, "--config", f.config)
	}
	cmd := exec.Command(exe, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
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

func effectiveUserHome() string {
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
	if quiet {
		return nil
	}
	last := time.Now()
	return func(s scan.Stats) {
		if time.Since(last) < 500*time.Millisecond {
			return
		}
		last = time.Now()
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

// buildElevateFailHint composes an actionable hint when osascript-based
// auto-elevation fails (e.g. user cancelled the password dialog, SSH session
// with no GUI, or the dialog never surfaced because wxkey was launched from
// a non-interactive AI agent shell).
func buildElevateFailHint(reErr, origErr error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "auto-elevate via osascript failed: %v\n", reErr)
	fmt.Fprintf(&b, "       original permission error: %v\n", origErr)
	fmt.Fprintln(&b, "")
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != "" {
		fmt.Fprintln(&b, "       You appear to be on SSH. osascript needs a desktop GUI session to")
		fmt.Fprintln(&b, "       show the macOS password prompt. Options:")
		fmt.Fprintln(&b, "         a) Run `wxkey bootstrap` on the Mac's local desktop (no sudo).")
		fmt.Fprintln(&b, "         b) Over SSH, run `sudo wxkey bootstrap` in your interactive shell")
		fmt.Fprintln(&b, "            (sudo needs a real tty; AI agents / pipes will not work).")
	} else {
		fmt.Fprintln(&b, "       The macOS password prompt may have been cancelled or never surfaced.")
		fmt.Fprintln(&b, "       Re-run `wxkey bootstrap` directly on the Mac's desktop (do NOT add")
		fmt.Fprintln(&b, "       sudo, and do NOT pipe it through an AI agent / non-interactive shell;")
		fmt.Fprintln(&b, "       both prevent the password dialog from working). When the macOS dialog")
		fmt.Fprintln(&b, "       appears, type your admin password to grant task_for_pid access.")
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
	out, err := exec.Command("/usr/bin/codesign", "-dv", wechatAppPath).CombinedOutput()
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
	fmt.Fprintln(os.Stderr, "       wx-mcp 的运行时解密不需要关闭 SIP; 只有首次取 key 需要读取 WeChat 进程内存.")

	if disabled, raw := sipDisabled(); raw != "" {
		if disabled {
			fmt.Fprintln(os.Stderr, "       SIP: 已关闭. 如果仍失败, 多半是未以管理员运行、WeChat 未登录、或 TCC/签名限制.")
		} else {
			fmt.Fprintf(os.Stderr, "       SIP: 已启用 (%s). 这不是唯一解; 推荐重签 WeChat, 不必进 Recovery 关 SIP.\n", raw)
		}
	}

	sig := inspectWeChatSignature()
	if sig.Err != nil {
		fmt.Fprintf(os.Stderr, "       WeChat 签名检测失败: %v\n", sig.Err)
		if sig.Raw != "" {
			fmt.Fprintf(os.Stderr, "       codesign 输出: %s\n", sig.Raw)
		}
	} else if sig.AdHoc {
		fmt.Fprintln(os.Stderr, "       WeChat 签名: ad-hoc, 已是推荐状态. 请确认用管理员权限运行: sudo wxkey setup")
	} else if sig.Runtime {
		fmt.Fprintln(os.Stderr, "       WeChat 签名: 官方 Hardened Runtime. 推荐执行一次:")
		fmt.Fprintln(os.Stderr, "         ./wxkey resign-wechat")
		fmt.Fprintln(os.Stderr, "       然后等 WeChat 完全登录并打开一个聊天, 再跑:")
		fmt.Fprintln(os.Stderr, "         sudo wxkey setup")
	} else {
		fmt.Fprintln(os.Stderr, "       WeChat 签名: 未识别. 可先跑 `wxkey doctor` 查看详情.")
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "       兜底方案仍然可用: Recovery Mode 里执行 `csrutil disable`, 但不再作为默认推荐.")
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

// reExecElevated re-launches this binary under osascript with administrator
// privileges, blocking until it exits, and forwards stdout/stderr.
func reExecElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := strings.Join(quoteArgs(append([]string{exe}, os.Args[1:]...)), " ")
	cmd := fmt.Sprintf("WXKEY_ELEVATED=1 %s", args)
	script := fmt.Sprintf(`do shell script %q with administrator privileges`,
		cmd+" 2>&1") // capture stderr too so we can surface it
	osa := exec.Command("/usr/bin/osascript", "-e", script)
	osa.Stdout = os.Stdout
	osa.Stderr = os.Stderr
	return osa.Run()
}

func runResignWeChat() {
	if os.Geteuid() != 0 && !envTrue("WXKEY_NO_ELEVATE") && !envTrue("WXKEY_ELEVATED") {
		fmt.Fprintln(os.Stderr, "[wxkey] re-launching resign-wechat via osascript admin...")
		if err := reExecElevated(); err != nil {
			fail("re-elevate resign-wechat: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		fail("resign-wechat requires administrator privileges; run `sudo wxkey resign-wechat`")
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
		fmt.Fprintln(os.Stderr, "       Open WeChat manually, wait for login, then run `sudo wxkey setup`.")
		return
	}

	fmt.Println("")
	fmt.Println("Done. After WeChat is fully logged in and you have opened at least one chat, run:")
	fmt.Println("  sudo wxkey setup")
}

func runCodesignWeChat() ([]byte, error) {
	return exec.Command("/usr/bin/codesign", "--force", "--deep", "--sign", "-", wechatAppPath).CombinedOutput()
}

func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return out
}

// startOrphanWatchdog runs only in elevated children spawned via osascript.
// reExecElevated chains user → osascript → sh → root wxkey. If anyone above
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

// runDoctor is a read-only health check. It prints what's working, what's
// missing, and (when run as root) the actual key coverage from a live scan.
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
		logf("       若 task_for_pid 被拒, 跑 `wxkey resign-wechat` 后重试, 通常无需关闭 SIP.\n")
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
		logf("[WARN] libWCDB.dylib 未找到 — wx-mcp 启动时会失败\n")
		logf("       放到 wx-mcp 旁边的 lib/ 目录或 ~/.config/wxcli/lib/\n")
	}

	if os.Geteuid() != 0 {
		logf("\n[INFO] 未以 root 运行，跳过实际 scan\n")
		logf("       完整诊断请跑: sudo wxkey doctor\n")
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
		logf("跑 `sudo wxkey setup` 写 config, 然后启动 wx-mcp\n")
		return
	}

	coverage := float64(len(results)) / float64(len(saltIdx)) * 100
	logf("[WARN] Key 覆盖率: %d/%d (%.0f%%) — %d 个 DB 没拿到 key\n",
		len(results), len(saltIdx), coverage, len(saltIdx)-len(results))
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
	logf("\n=== 部分覆盖 ===\n")
	logf("方案 1: 在 WeChat 里打开缺的聊天/朋友圈/收藏，触发 WCDB 加载那些 DB key，然后重跑\n")
	logf("方案 2: 直接 `sudo wxkey setup`，部分覆盖也能跑大部分 wx-mcp 功能\n")
}

// findBundledDylib hunts libWCDB.dylib in the same locations wx-mcp does.
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
// parent directory. wxkey runs `setup` as root via osascript admin, so the
// config file lands as root:wheel and the unprivileged caller (wx-mcp / shell)
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
