//go:build !linux

package ebpf

// Check verifies that a Map conforms to the ABI.
func (abi *MapABI) Check(m *Map) error {
	return nil
}
