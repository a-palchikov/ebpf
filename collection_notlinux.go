//go:build !linux

package ebpf

import "os"

func NewCollectionWithOptions(spec *CollectionSpec, opts CollectionOptions) (*Collection, error) {
	return nil, errNotImplemented
}

func (coll *Collection) Pin(dirName string, fileMode os.FileMode) error {
	return errNotImplemented
}

func LoadPinnedCollection(dirName string) (*Collection, error) {
	return nil, errNotImplemented
}

func LoadPinnedCollectionExplicit(dirName string, maps map[string]*MapABI, progs map[string]*ProgramABI) (*Collection, error) {
	return nil, errNotImplemented
}
