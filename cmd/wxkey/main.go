// wxkey extracts WeChat 4.x WCDB master keys from the live WeChat process on
// macOS. Pure Go (purego + Mach VM syscalls). Replaces the WeFlow xkey_helper
// dependency by passively scanning WeChat's heap for the SQL literal
// `x'<hex>'` that WCDB constructs when forwarding keys to sqlite3_key_v2,
// then verifying each candidate via SQLCipher 4 page-1 HMAC.
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
  wxkey scan       [--pid N] [--root /path/to/xwechat_files/<wxid>] [--quiet]
  wxkey setup      [--pid N] [--root ...] [--config ~/.config/wxcli/config.json]
  wxkey doctor     [--pid N] [--root ...] [--quiet]
  wxkey list-pids
  wxkey -h | --help

Subcommands:
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
  list-pids   Print one WeChat PID per line (or empty if not running).

Notes:
  - WeChat must be running and have opened at least one DB this session.
  - task_for_pid requires SIP-disabled + admin grant. wxkey will re-launch
    itself via osascript if the direct attach fails (set WXKEY_NO_ELEVATE=1
    to disable that auto-relaunch).
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
	case "scan":
		runScan(os.Args[2:], false)
	case "setup":
		runScan(os.Args[2:], true)
	case "doctor":
		runDoctor(os.Args[2:])
	case "list-pids":
		runListPids()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

type scanFlags struct {
	pid           int
	root          string
	quiet         bool
	config        string
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
	PID     int          `json:"pid"`
	Root    string       `json:"scan_root"`
	WxID    string       `json:"wxid"`
	Stats   scan.Stats   `json:"stats"`
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
// re-runs only if it was already there (set via the WeFlow path) so older
// wx-mcp builds keep working until they ship the new code.
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
	requireSIPDisabled(f.quiet)
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
				fail("re-elevate: %v (original error: %v)", reErr, err)
			}
			return // child handled it
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
		home, _ := os.UserHomeDir()
		cfgPath = filepath.Join(home, ".config", "wxcli", "config.json")
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		fail("mkdir config dir: %v", err)
	}

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

// --- helpers ---

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
	home, _ := os.UserHomeDir()
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
		return "", fmt.Errorf("no WeChat account directory found under known roots")
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

// requireSIPDisabled is a soft pre-flight check called at the entry of any
// command that needs task_for_pid (scan / setup / doctor). When SIP is on,
// it prints a Chinese-language error explaining why and how to fix, then
// exits non-zero before we ever touch the kernel. Set WXKEY_SKIP_SIP_CHECK=1
// to bypass (e.g. if you signed wxkey with a debugger entitlement).
func requireSIPDisabled(quiet bool) {
	if os.Getenv("WXKEY_SKIP_SIP_CHECK") == "1" {
		return
	}
	disabled, raw := sipDisabled()
	if disabled {
		return
	}
	if raw == "" {
		// csrutil unavailable or unparseable — let downstream syscall error speak.
		return
	}
	if quiet {
		fmt.Fprintf(os.Stderr, "wxkey: SIP enabled, task_for_pid will fail. Disable SIP via Recovery Mode → `csrutil disable`. Raw: %s\n", raw)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "[FAIL] SIP (System Integrity Protection) 当前为启用状态")
	fmt.Fprintln(os.Stderr, "       wxkey 需要 task_for_pid 读微信进程内存, SIP 启用时 macOS 内核硬性拒绝.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "       关闭步骤 (Apple Silicon):")
	fmt.Fprintln(os.Stderr, "         1. 关机, 长按电源键进 Recovery Mode")
	fmt.Fprintln(os.Stderr, "         2. 顶部菜单 Utilities → Terminal")
	fmt.Fprintln(os.Stderr, "         3. 跑: csrutil disable")
	fmt.Fprintln(os.Stderr, "         4. 重启回常规系统")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "       关完再跑: ./wxkey doctor  验证")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "       csrutil 原始输出: %s\n", raw)
	fmt.Fprintln(os.Stderr, "       (若你已自签 debugger entitlement, 设 WXKEY_SKIP_SIP_CHECK=1 跳过本预检)")
	os.Exit(2)
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
		logf("[FAIL] SIP 启用 — wxkey 需要 SIP 关闭才能扫内存\n")
		logf("       关法: Recovery Mode → Terminal → csrutil disable → 重启\n")
		logf("       原始: %s\n", raw)
		os.Exit(1)
	} else if disabled {
		logf("[OK]   SIP 已关闭\n")
	} else {
		logf("[INFO] csrutil 不可用, 跳过 SIP 预检\n")
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
			logf("       task_for_pid 被拒。SIP 可能阻挡，或者你不是以 sudo 运行\n")
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
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "cc-workspace", "mcp-servers", "wx-mcp", "lib", "libWCDB.dylib"),
			filepath.Join(home, ".config", "wxcli", "lib", "libWCDB.dylib"),
		)
	}
	candidates = append(candidates,
		"/Applications/WeFlow.app/Contents/Resources/resources/wcdb/macos/universal/libWCDB.dylib")
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
