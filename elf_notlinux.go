//go:build !linux

package ebpf

import (
	"io"
)

// LoadCollectionSpecFromReader parses an io.ReaderAt that represents an ELF layout
// into a CollectionSpec.
func LoadCollectionSpecFromReader(code io.ReaderAt) (*CollectionSpec, error) {
	return nil, errNotImplemented
}
