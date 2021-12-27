package ebpf

import "github.com/Gui774ume/ebpf/asm"

// Editor modifies eBPF instructions.
type Editor struct {
	instructions     *asm.Instructions
	ReferenceOffsets map[string][]int
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *asm.Instructions) *Editor {
	refs := insns.ReferenceOffsets()
	return &Editor{insns, refs}
}
