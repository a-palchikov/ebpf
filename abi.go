package ebpf

import "github.com/pkg/errors"

// CollectionABI describes the interface of an eBPF collection.
type CollectionABI struct {
	Maps     map[string]*MapABI
	Programs map[string]*ProgramABI
}

// CheckSpec verifies that all maps and programs mentioned
// in the ABI are present in the spec.
func (abi *CollectionABI) CheckSpec(cs *CollectionSpec) error {
	for name := range abi.Maps {
		if cs.Maps[name] == nil {
			return errors.Errorf("missing map %s", name)
		}
	}

	for name := range abi.Programs {
		if cs.Programs[name] == nil {
			return errors.Errorf("missing program %s", name)
		}
	}

	return nil
}

// Check verifies that all items in a collection conform to this ABI.
func (abi *CollectionABI) Check(coll *Collection) error {
	for name, mapABI := range abi.Maps {
		m := coll.Maps[name]
		if m == nil {
			return errors.Errorf("missing map %s", name)
		}
		if err := mapABI.Check(m); err != nil {
			return errors.Wrapf(err, "map %s", name)
		}
	}

	for name, progABI := range abi.Programs {
		p := coll.Programs[name]
		if p == nil {
			return errors.Errorf("missing program %s", name)
		}
		if err := progABI.Check(p); err != nil {
			return errors.Wrapf(err, "program %s", name)
		}
	}

	return nil
}

// MapABI describes a Map.
//
// Members which have the zero value of their type
// are not checked.
type MapABI struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	InnerMap   *MapABI
}

// ProgramABI describes a Program.
//
// Members which have the zero value of their type
// are not checked.
type ProgramABI struct {
	Type ProgType
}

// Check verifies that a Program conforms to the ABI.
func (abi *ProgramABI) Check(prog *Program) error {
	if abi.Type != Unrecognized && prog.abi.Type != abi.Type {
		return errors.Errorf("expected program type %s, have %s", abi.Type, prog.abi.Type)
	}

	return nil
}
