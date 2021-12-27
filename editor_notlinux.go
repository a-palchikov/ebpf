//go:build !linux

package ebpf

import "github.com/Gui774ume/ebpf/asm"

func (ed *Editor) RewriteMap(symbol string, m *Map) error {
	return errNotImplemented
}

func (ed *Editor) RewriteConstant(symbol string, value uint64) error {
	return errNotImplemented
}

func (ed *Editor) Link(sections ...asm.Instructions) error {
	return errNotImplemented
}
