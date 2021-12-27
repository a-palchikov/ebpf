package ebpf

import (
	"strings"

	"github.com/Gui774ume/ebpf/asm"
)

// ProgramOptions control loading a program into the kernel.
type ProgramOptions struct {
	// Controls the detail emitted by the kernel verifier. Set to non-zero
	// to enable logging.
	LogLevel uint32
	// Controls the output buffer size for the verifier. Defaults to
	// DefaultVerifierLogSize.
	LogSize int
}

// ProgramSpec defines a Program
type ProgramSpec struct {
	// Name is passed to the kernel as a debug aid. Must only contain
	// alpha numeric and '_' characters.
	Name          string
	SectionName   string
	Type          ProgType
	AttachType    AttachType
	Instructions  asm.Instructions
	License       string
	KernelVersion uint32
}

// Copy returns a copy of the spec.
func (ps *ProgramSpec) Copy() *ProgramSpec {
	if ps == nil {
		return nil
	}

	cpy := *ps
	cpy.Instructions = make(asm.Instructions, len(ps.Instructions))
	copy(cpy.Instructions, ps.Instructions)
	return &cpy
}

// Program represents BPF program loaded into the kernel.
//
// It is not safe to close a Program which is used by other goroutines.
type Program struct {
	// Contains the output of the kernel verifier if enabled,
	// otherwise it is empty.
	VerifierLog string
	// ProgramSpec - Pointer to the ProgramSpec
	ProgramSpec *ProgramSpec

	bpfProg
	name               string
	abi                ProgramABI
	attachedCgroupPath string
	attachedType       AttachType
}

// ABI gets the ABI of the Program
func (bpf *Program) ABI() ProgramABI {
	return bpf.abi
}

// IsKRetProbe returns true if the program is a kretprobe
func (bpf *Program) IsKRetProbe() bool {
	return strings.HasPrefix(bpf.ProgramSpec.SectionName, "kretprobe/")
}

// IsKProbe returns true if the program is a kprobe
func (bpf *Program) IsKProbe() bool {
	return strings.HasPrefix(bpf.ProgramSpec.SectionName, "kprobe/")
}

// IsUProbe returns true if the program is a uprobe
func (bpf *Program) IsUProbe() bool {
	return strings.HasPrefix(bpf.ProgramSpec.SectionName, "uprobe/")
}

// IsCgroupProgram returns true if the program is a cgroup program
func (bpf *Program) IsCgroupProgram() bool {
	switch bpf.ProgramSpec.Type {
	case CGroupSKB:
		fallthrough
	case CGroupSock:
		fallthrough
	case SockOps:
		fallthrough
	case CGroupDevice:
		fallthrough
	case CGroupSockAddr:
		fallthrough
	case CGroupSysctl:
		fallthrough
	case CGroupSockopt:
		return true
	default:
		return false
	}
	return false
}

// SanitizeName replaces all invalid characters in name.
//
// Use this to automatically generate valid names for maps and
// programs at run time.
//
// Passing a negative value for replacement will delete characters
// instead of replacing them.
func SanitizeName(name string, replacement rune) string {
	return strings.Map(func(char rune) rune {
		if invalidBPFObjNameChar(char) {
			return replacement
		}
		return char
	}, name)
}
