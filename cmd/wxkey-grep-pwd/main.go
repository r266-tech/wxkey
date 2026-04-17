// Diagnostic: search WeChat process memory for the literal known master
// password string in any of these forms:
//   - bare 64-char ASCII hex
//   - x'<64hex>' SQL literal (no salt)
//   - x'<64hex+32hex>' SQL literal (with salt) — for completeness
//   - raw 32 bytes (binary)
// Reports counts of each. Tells us if Plan C (passive bare-hex scan for
// master password) is viable, or if we need Plan B (active ptrace hook).
//
// Usage:
//   sudo go run ./cmd/wxkey-grep-pwd -- <pid> <64-hex-master-password>
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/r266-tech/wxkey/internal/machvm"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: wxkey-grep-pwd <pid> <64-hex-password>")
		os.Exit(2)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad pid:", err)
		os.Exit(2)
	}
	pwHex := strings.ToLower(strings.TrimSpace(os.Args[2]))
	if len(pwHex) != 64 {
		fmt.Fprintln(os.Stderr, "password hex must be exactly 64 chars (32 bytes)")
		os.Exit(2)
	}
	pwBytes, err := hex.DecodeString(pwHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex:", err)
		os.Exit(2)
	}

	// Things to search for.
	bareLower := []byte(pwHex)
	bareUpper := []byte(strings.ToUpper(pwHex))
	wrapped64 := []byte("x'" + pwHex + "'")
	wrapped64U := []byte("x'" + strings.ToUpper(pwHex) + "'")
	rawBin := pwBytes

	type counter struct {
		label   string
		needle  []byte
		hits    int
		samples []uint64
	}
	cs := []*counter{
		{label: "bare 64-hex (lowercase)", needle: bareLower},
		{label: "bare 64-hex (uppercase)", needle: bareUpper},
		{label: "x'<64hex>' wrapped (lower)", needle: wrapped64},
		{label: "x'<64hex>' wrapped (upper)", needle: wrapped64U},
		{label: "raw 32 binary bytes", needle: rawBin},
	}

	proc, err := machvm.Attach(int32(pid))
	if err != nil {
		fmt.Fprintln(os.Stderr, "attach:", err)
		os.Exit(1)
	}
	defer proc.Detach()

	type reg struct{ addr, size uint64 }
	var regs []reg
	if err := proc.Regions(func(r machvm.Region) bool {
		if !r.IsReadable() || r.IsExecutable() {
			return true
		}
		if !r.IsWritable() {
			return true
		}
		if r.Size == 0 || r.Size > 500*1024*1024 {
			return true
		}
		regs = append(regs, reg{r.Address, r.Size})
		return true
	}); err != nil {
		fmt.Fprintln(os.Stderr, "regions:", err)
		os.Exit(1)
	}

	const chunk = 8 * 1024 * 1024
	const overlap = 256
	buf := make([]byte, chunk+overlap)
	var carry []byte
	var totalScanned uint64

	for _, r := range regs {
		off := uint64(0)
		carry = carry[:0]
		for off < r.size {
			n := uint64(chunk)
			if n > r.size-off {
				n = r.size - off
			}
			copy(buf, carry)
			read, _ := proc.Read(r.addr+off, buf[len(carry):len(carry)+int(n)])
			off += n
			totalScanned += uint64(read)
			view := buf[:len(carry)+read]

			for _, c := range cs {
				idx := 0
				for idx < len(view) {
					p := bytes.Index(view[idx:], c.needle)
					if p < 0 {
						break
					}
					c.hits++
					if len(c.samples) < 5 {
						c.samples = append(c.samples, r.addr+off-n+uint64(idx+p))
					}
					idx += p + 1
				}
			}

			if read > overlap {
				carry = append(carry[:0], view[len(view)-overlap:]...)
			} else {
				carry = append(carry[:0], view...)
			}
		}
	}

	fmt.Printf("scanned %d regions, %.0f MB\n\n", len(regs), float64(totalScanned)/1024/1024)
	for _, c := range cs {
		fmt.Printf("%-32s : %d hit(s)", c.label, c.hits)
		if c.hits > 0 {
			parts := make([]string, len(c.samples))
			for i, a := range c.samples {
				parts[i] = fmt.Sprintf("%#x", a)
			}
			fmt.Printf("  samples: %s", strings.Join(parts, ", "))
		}
		fmt.Println()
	}
}
