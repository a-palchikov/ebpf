package ebpf

import "fmt"

// MapSpec defines a Map.
type MapSpec struct {
	// Name is passed to the kernel as a debug aid. Must only contain
	// alpha numeric and '_' characters.
	Name       string
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	// InnerMap is used as a template for ArrayOfMaps and HashOfMaps
	InnerMap *MapSpec
}

func (ms *MapSpec) String() string {
	return fmt.Sprintf("%s(keySize=%d, valueSize=%d, maxEntries=%d, flags=%d)", ms.Type, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags)
}

// Copy returns a copy of the spec.
func (ms *MapSpec) Copy() *MapSpec {
	if ms == nil {
		return nil
	}

	cpy := *ms
	cpy.InnerMap = ms.InnerMap.Copy()
	return &cpy
}

// Map represents a Map file descriptor.
//
// It is not safe to close a map which is used by other goroutines.
//
// Methods which take interface{} arguments by default encode
// them using binary.Read/Write in the machine's native endianness.
//
// Implement Marshaler on the arguments if you need custom encoding.
type Map struct {
	// MapSpec - pointer to the MapSpec
	MapSpec *MapSpec

	bpfMap
	abi MapABI
	// Per CPU maps return values larger than the size in the spec
	fullValueSize int
}
