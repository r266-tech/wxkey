package machvm

import (
	"os"
	"testing"
	"unsafe"
)

// TestAttachSelf checks the bindings are loaded correctly by attaching to our
// own pid (always permitted) and walking a few regions.
func TestAttachSelf(t *testing.T) {
	pid := int32(os.Getpid())
	p, err := Attach(pid)
	if err != nil {
		t.Fatalf("self attach: %v", err)
	}
	defer p.Detach()

	count := 0
	var totalSize uint64
	err = p.Regions(func(r Region) bool {
		count++
		totalSize += r.Size
		if count > 1000 {
			return false
		}
		return true
	})
	if err != nil {
		t.Fatalf("Regions: %v", err)
	}
	if count == 0 {
		t.Fatal("expected at least one region in self process")
	}
	t.Logf("self regions: %d, total size: %.1f MB", count, float64(totalSize)/1024/1024)
}

// TestReadSelf reads a known buffer in our own process and checks the bytes
// match.
func TestReadSelf(t *testing.T) {
	p, err := Attach(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("self attach: %v", err)
	}
	defer p.Detach()

	src := []byte("WXKEY-MACHVM-TEST-PATTERN-123456")
	buf := make([]byte, len(src))
	n, err := p.Read(uint64(uintptr(unsafe.Pointer(&src[0]))), buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(src) {
		t.Fatalf("short read: got %d want %d", n, len(src))
	}
	if string(buf) != string(src) {
		t.Fatalf("data mismatch: got %q want %q", buf, src)
	}
}
