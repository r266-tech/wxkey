package main

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/r266-tech/wxkey/internal/machvm"
)

type imageKeyOutput struct {
	Key            string        `json:"key"`
	XORKey         *int          `json:"xor_key,omitempty"`
	TemplateFile   string        `json:"template_file"`
	TemplateSource string        `json:"template_source"`
	Regions        int           `json:"regions"`
	BytesScanned   uint64        `json:"bytes_scanned"`
	Candidates     int           `json:"candidates"`
	Elapsed        time.Duration `json:"elapsed_ns"`
}

type imageKeyTemplate struct {
	path      string
	source    string
	encrypted []byte
	xorKey    *int
}

func scanImageKey(pid int, root string, quiet bool) (*imageKeyOutput, error) {
	tpl, err := findImageKeyTemplate(root)
	if err != nil {
		return nil, err
	}
	if img, err := deriveImageKeyFromDisk(root, tpl, quiet); err == nil {
		return img, nil
	} else {
		logf(quiet, "[wxkey] disk image_key derivation failed; falling back to memory scan: %v\n", err)
	}
	if pid == 0 {
		p, err := pickWeChatPID()
		if err != nil {
			return nil, err
		}
		pid = p
	}
	start := time.Now()
	proc, err := machvm.Attach(int32(pid))
	if err != nil {
		return nil, err
	}
	defer proc.Detach()

	type reg struct{ addr, size uint64 }
	var regions []reg
	if err := proc.Regions(func(r machvm.Region) bool {
		if !r.IsReadable() || r.IsExecutable() || !r.IsWritable() {
			return true
		}
		if r.Size == 0 || r.Size > scanImageKeyMaxRegionSize {
			return true
		}
		regions = append(regions, reg{r.Address, r.Size})
		return true
	}); err != nil {
		return nil, fmt.Errorf("enumerate regions: %w", err)
	}

	const chunkSize = 8 * 1024 * 1024
	const overlap = 96
	chunk := make([]byte, chunkSize+overlap)
	var carry []byte
	seen := map[string]bool{}
	out := &imageKeyOutput{
		TemplateFile:   tpl.path,
		TemplateSource: "memory_" + tpl.source,
		Regions:        len(regions),
	}
	if tpl.xorKey != nil {
		out.XORKey = intPtr(*tpl.xorKey)
	}
	for _, r := range regions {
		off := uint64(0)
		carry = carry[:0]
		for off < r.size {
			n := uint64(chunkSize)
			if n > r.size-off {
				n = r.size - off
			}
			if len(carry) > 0 {
				copy(chunk, carry)
			}
			read, rerr := proc.Read(r.addr+off, chunk[len(carry):len(carry)+int(n)])
			if rerr != nil || read == 0 {
				off += n
				carry = carry[:0]
				continue
			}
			view := chunk[:len(carry)+read]
			out.BytesScanned += uint64(read)
			for _, candidate := range imageKeyCandidates(view) {
				if seen[candidate] {
					continue
				}
				seen[candidate] = true
				out.Candidates++
				if validateImageKeyCandidate([]byte(candidate), tpl.encrypted) {
					out.Key = candidate
					out.Elapsed = time.Since(start)
					logf(quiet, "[wxkey] image_key found from %s after %d candidates\n", filepath.Base(tpl.path), out.Candidates)
					return out, nil
				}
			}
			if read > overlap {
				carry = append(carry[:0], view[len(view)-overlap:]...)
			} else {
				carry = append(carry[:0], view...)
			}
			off += n
			if time.Since(start) > scanImageKeyTimeout {
				out.Elapsed = time.Since(start)
				return nil, fmt.Errorf("image_key not found within %s after %d candidates using template %s", scanImageKeyTimeout, out.Candidates, tpl.path)
			}
		}
	}
	out.Elapsed = time.Since(start)
	return nil, fmt.Errorf("image_key not found after %d candidates using template %s", out.Candidates, tpl.path)
}

const scanImageKeyMaxRegionSize = 500 * 1024 * 1024
const scanImageKeyTimeout = 60 * time.Second

func imageKeyCandidates(buf []byte) []string {
	var out []string
	for i := 0; i < len(buf); {
		if !isAlphaNum(buf[i]) {
			i++
			continue
		}
		start := i
		for i < len(buf) && isAlphaNum(buf[i]) {
			i++
		}
		run := buf[start:i]
		switch {
		case len(run) >= 16 && len(run) <= 64:
			out = append(out, string(run))
		case len(run) > 64:
			out = append(out, string(run[:64]), string(run[:32]), string(run[:16]))
		}
	}
	return out
}

func isAlphaNum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func findImageKeyTemplate(root string) (*imageKeyTemplate, error) {
	searchRoot := filepath.Join(root, "msg", "attach")
	if st, err := os.Stat(searchRoot); err != nil || !st.IsDir() {
		searchRoot = root
	}
	var bestThumb *imageKeyTemplate
	var fallback *imageKeyTemplate
	deadline := time.Now().Add(10 * time.Second)
	err := filepath.Walk(searchRoot, func(path string, info os.FileInfo, err error) error {
		if time.Now().After(deadline) {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		if info == nil || info.IsDir() {
			return nil
		}
		name := strings.ToLower(info.Name())
		if !strings.HasSuffix(name, ".dat") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || !isWechatV4ImageDAT(data) || len(data) < 15+aes.BlockSize {
			return nil
		}
		tpl := &imageKeyTemplate{
			path:      path,
			source:    "fallback",
			encrypted: append([]byte{}, data[15:15+aes.BlockSize]...),
			xorKey:    deriveImageXORKeyFromData(data),
		}
		if strings.HasSuffix(name, "_t.dat") {
			tpl.source = "t.dat"
			bestThumb = tpl
			return errImageKeyTemplateFound
		}
		if fallback == nil {
			fallback = tpl
		}
		return nil
	})
	if err != nil && err != errImageKeyTemplateFound {
		return nil, err
	}
	if bestThumb != nil {
		return bestThumb, nil
	}
	if fallback == nil {
		return nil, fmt.Errorf("no WeChat V4 image .dat validation sample found; open a chat image in WeChat so *_t.dat is generated")
	}
	return fallback, nil
}

var errImageKeyTemplateFound = fs.SkipAll

func deriveImageKeyFromDisk(root string, tpl *imageKeyTemplate, quiet bool) (*imageKeyOutput, error) {
	start := time.Now()
	dirs := kvcommDirCandidates(root)
	codes, err := collectKVCommCodes(dirs)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("no kvcomm key_<uin>_*.statistic files found")
	}
	wxids := imageKeyWxidCandidates(root)
	if len(wxids) == 0 {
		return nil, fmt.Errorf("cannot infer wxid from root %s", root)
	}
	attempts := 0
	for _, wxid := range wxids {
		for _, code := range codes {
			attempts++
			key := deriveImageKeyFromKVCode(code, wxid)
			if validateImageKeyCandidate([]byte(key), tpl.encrypted) {
				xorKey := int(code & 0xff)
				logf(quiet, "[wxkey] image_key derived from kvcomm for wxid=%s using %s after %d candidates\n",
					wxid, filepath.Base(tpl.path), attempts)
				return &imageKeyOutput{
					Key:            key,
					XORKey:         intPtr(xorKey),
					TemplateFile:   tpl.path,
					TemplateSource: "kvcomm_" + tpl.source,
					Candidates:     attempts,
					Elapsed:        time.Since(start),
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("no kvcomm-derived image_key verified (%d codes, %d wxid candidates, template %s)",
		len(codes), len(wxids), tpl.path)
}

func kvcommDirCandidates(root string) []string {
	root = filepath.Clean(root)
	var candidates []string
	parts := splitPathParts(root)
	for idx, part := range parts {
		if part != "xwechat_files" {
			continue
		}
		documentsRoot := joinPathParts(parts[:idx])
		candidates = append(candidates,
			filepath.Join(documentsRoot, "app_data", "net", "kvcomm"),
			filepath.Join(documentsRoot, "xwechat", "net", "kvcomm"),
			filepath.Join(documentsRoot, "app_data", "ilink", "kvcomm"),
			filepath.Join(documentsRoot, "app_data", "roam", "ilink", "kvcomm"),
		)
		if matches, _ := filepath.Glob(filepath.Join(documentsRoot, "app_data", "radium", "ilink", "*", "kvcomm")); len(matches) > 0 {
			candidates = append(candidates, matches...)
		}
		if idx >= 1 {
			containerRoot := joinPathParts(parts[:idx-1])
			candidates = append(candidates,
				filepath.Join(containerRoot, "Library", "Application Support", "com.tencent.xinWeChat", "xwechat", "net", "kvcomm"),
				filepath.Join(containerRoot, "Library", "Application Support", "com.tencent.xinWeChat", "net", "kvcomm"),
			)
		}
		break
	}
	if home := effectiveUserHome(); home != "" {
		candidates = append(candidates,
			filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm"),
			filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "ilink", "kvcomm"),
		)
	}
	var out []string
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			out = append(out, candidate)
		}
	}
	return out
}

func collectKVCommCodes(dirs []string) ([]uint32, error) {
	codes := map[uint32]bool{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			rest, ok := strings.CutPrefix(name, "key_")
			if !ok {
				continue
			}
			codeText, _, ok := strings.Cut(rest, "_")
			if !ok {
				continue
			}
			code, err := strconv.ParseUint(codeText, 10, 32)
			if err != nil {
				continue
			}
			codes[uint32(code)] = true
		}
	}
	out := make([]uint32, 0, len(codes))
	for code := range codes {
		out = append(out, code)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func imageKeyWxidCandidates(root string) []string {
	leaf := filepath.Base(filepath.Clean(root))
	if leaf == "db_storage" {
		leaf = filepath.Base(filepath.Dir(filepath.Clean(root)))
	}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		for _, existing := range out {
			if existing == v {
				return
			}
		}
		out = append(out, v)
	}
	add(leaf)
	add(normalizeImageWxid(leaf))
	return out
}

func normalizeImageWxid(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "wxid_") {
		rest := strings.TrimPrefix(raw, "wxid_")
		head, _, _ := strings.Cut(rest, "_")
		if head != "" {
			return "wxid_" + head
		}
	}
	if idx := strings.LastIndex(raw, "_"); idx > 0 {
		suffix := raw[idx+1:]
		if len(suffix) == 4 && isHexString(suffix) {
			return raw[:idx]
		}
	}
	return raw
}

func deriveImageKeyFromKVCode(code uint32, wxid string) string {
	sum := md5.Sum([]byte(fmt.Sprintf("%d%s", code, wxid)))
	return fmt.Sprintf("%x", sum)[:aes.BlockSize]
}

func splitPathParts(path string) []string {
	return strings.Split(filepath.Clean(path), string(os.PathSeparator))
}

func joinPathParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if parts[0] == "" {
		return string(os.PathSeparator) + filepath.Join(parts[1:]...)
	}
	return filepath.Join(parts...)
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func deriveImageXORKeyFromData(data []byte) *int {
	if !isWechatV4ImageDAT(data) || len(data) < 17 {
		return nil
	}
	xorSize := binary.LittleEndian.Uint32(data[10:14])
	if xorSize < 2 {
		return nil
	}
	fileData := data[15:]
	if uint32(len(fileData)) < xorSize {
		return nil
	}
	tail := fileData[uint32(len(fileData))-xorSize:]
	if len(tail) < 2 {
		return nil
	}
	k0 := int(tail[len(tail)-2] ^ 0xff)
	k1 := int(tail[len(tail)-1] ^ 0xd9)
	if k0 != k1 {
		return nil
	}
	return intPtr(k0)
}

func intPtr(v int) *int {
	return &v
}

func isWechatV4ImageDAT(data []byte) bool {
	return len(data) >= 15 &&
		data[0] == 0x07 &&
		data[1] == 0x08 &&
		data[2] == 0x56 &&
		(data[3] == 0x31 || data[3] == 0x32) &&
		data[4] == 0x08 &&
		data[5] == 0x07 &&
		binary.LittleEndian.Uint32(data[6:10]) > 0
}

func validateImageKeyCandidate(candidate, encrypted []byte) bool {
	if len(candidate) < aes.BlockSize || len(encrypted) < aes.BlockSize {
		return false
	}
	block, err := aes.NewCipher(candidate[:aes.BlockSize])
	if err != nil {
		return false
	}
	decoded := make([]byte, aes.BlockSize)
	block.Decrypt(decoded, encrypted[:aes.BlockSize])
	return bytes.HasPrefix(decoded, []byte{0xff, 0xd8, 0xff}) ||
		bytes.HasPrefix(decoded, []byte{0x89, 0x50, 0x4e, 0x47}) ||
		bytes.HasPrefix(decoded, []byte("wxgf"))
}
