//go:build !linux

package ebpf

func NewMap(spec *MapSpec) (*Map, error) {
	return nil, errNotImplemented
}

func (m *Map) Put(key, value interface{}) error {
	return errNotImplemented
}

func (m *Map) GetBytes(key interface{}) ([]byte, error) {
	return nil, errNotImplemented
}

func (m *Map) Delete(key interface{}) error {
	return errNotImplemented
}

func (m *Map) Close() error {
	return errNotImplemented
}

type bpfMap struct{}
