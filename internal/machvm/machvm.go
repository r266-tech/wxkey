// Package machvm wraps the Mach VM syscalls used to enumerate and read another
// process's memory on macOS. Implemented via purego (no cgo).
//
// task_for_pid is gated by the kernel: the caller needs either root, SIP
// disabled + a user-approved task port grant, or the
// com.apple.security.cs.debugger entitlement. wxkey relies on the second path
// (admin re-launch via osascript) when the direct call returns KERN_FAILURE.
package machvm

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	KERN_SUCCESS = 0

	VM_REGION_BASIC_INFO_64       = 9
	VM_REGION_BASIC_INFO_COUNT_64 = 9 // count of 32-bit ints in the info struct (36 bytes / 4)

	VM_PROT_READ    = 0x1
	VM_PROT_WRITE   = 0x2
	VM_PROT_EXECUTE = 0x4
)

var (
	mu     sync.Mutex
	loaded bool

	machTaskSelf        func() uint32
	taskForPid          func(task uint32, pid int32, targetTask *uint32) int32
	machVmRegion        func(task uint32, addr *uint64, size *uint64, flavor int32, info unsafe.Pointer, count *uint32, objectName *uint32) int32
	machVmReadOverwrite func(task uint32, addr uint64, size uint64, data unsafe.Pointer, outSize *uint64) int32
	machPortDeallocate  func(task uint32, port uint32) int32
)

func ensureLoaded() error {
	mu.Lock()
	defer mu.Unlock()
	if loaded {
		return nil
	}
	h, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("dlopen libSystem: %w", err)
	}
	purego.RegisterLibFunc(&machTaskSelf, h, "mach_task_self")
	purego.RegisterLibFunc(&taskForPid, h, "task_for_pid")
	purego.RegisterLibFunc(&machVmRegion, h, "mach_vm_region")
	purego.RegisterLibFunc(&machVmReadOverwrite, h, "mach_vm_read_overwrite")
	purego.RegisterLibFunc(&machPortDeallocate, h, "mach_port_deallocate")
	loaded = true
	return nil
}

// Region is a single VM region in the target process.
type Region struct {
	Address    uint64
	Size       uint64
	Protection int32 // VM_PROT_READ|WRITE|EXECUTE bitmask
}

func (r Region) IsReadable() bool   { return r.Protection&VM_PROT_READ != 0 }
func (r Region) IsWritable() bool   { return r.Protection&VM_PROT_WRITE != 0 }
func (r Region) IsExecutable() bool { return r.Protection&VM_PROT_EXECUTE != 0 }

// Process holds a Mach task port for a target PID. Always Detach() when done
// so we don't leak send rights.
type Process struct {
	pid  int32
	task uint32
	self uint32
}

// PID returns the underlying process id.
func (p *Process) PID() int32 { return p.pid }

// Attach acquires the Mach task port for pid. Returns a wrapped error
// describing the kr code on failure (most commonly KERN_FAILURE = 5 = "not
// permitted"; KERN_INVALID_ARGUMENT = 4 = "no such process").
func Attach(pid int32) (*Process, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	self := machTaskSelf()
	var task uint32
	if kr := taskForPid(self, pid, &task); kr != KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid pid=%d kr=%d (need root, debugger entitlement, or SIP-disabled + user grant)", pid, kr)
	}
	return &Process{pid: pid, task: task, self: self}, nil
}

// Detach releases the task port. Safe to call multiple times.
func (p *Process) Detach() {
	if p == nil || p.task == 0 {
		return
	}
	machPortDeallocate(p.self, p.task)
	p.task = 0
}

// Regions enumerates every VM region in the target process, calling fn for
// each. fn returning false stops iteration. Object-name ports are deallocated
// internally so callers don't have to.
func (p *Process) Regions(fn func(Region) bool) error {
	if p == nil || p.task == 0 {
		return fmt.Errorf("machvm.Regions: detached process")
	}
	var addr uint64
	info := make([]byte, 64) // VM_REGION_BASIC_INFO_64 is 36 bytes; round up
	for {
		var size uint64
		count := uint32(VM_REGION_BASIC_INFO_COUNT_64)
		var objectName uint32
		kr := machVmRegion(p.task, &addr, &size, VM_REGION_BASIC_INFO_64,
			unsafe.Pointer(&info[0]), &count, &objectName)
		if kr != KERN_SUCCESS {
			return nil // exhausted address space
		}
		protection := int32(binary.LittleEndian.Uint32(info[:4]))
		if objectName != 0 {
			machPortDeallocate(p.self, objectName)
		}
		if size == 0 {
			return nil
		}
		if !fn(Region{Address: addr, Size: size, Protection: protection}) {
			return nil
		}
		next := addr + size
		if next <= addr {
			return nil
		}
		addr = next
	}
}

// Read copies up to len(dst) bytes from the target at addr into dst. Returns
// the number of bytes actually read; mach_vm_read_overwrite may short-read at
// region boundaries.
func (p *Process) Read(addr uint64, dst []byte) (int, error) {
	if p == nil || p.task == 0 {
		return 0, fmt.Errorf("machvm.Read: detached process")
	}
	if len(dst) == 0 {
		return 0, nil
	}
	var outSize uint64
	kr := machVmReadOverwrite(p.task, addr, uint64(len(dst)), unsafe.Pointer(&dst[0]), &outSize)
	if kr != KERN_SUCCESS {
		return 0, fmt.Errorf("mach_vm_read_overwrite addr=%#x size=%d kr=%d", addr, len(dst), kr)
	}
	return int(outSize), nil
}
