package ebpf

import (
	"os"

	"github.com/pkg/errors"
)

// CollectionOptions control loading a collection into the kernel.
type CollectionOptions struct {
	Programs ProgramOptions
}

// CollectionSpec describes a collection.
type CollectionSpec struct {
	Maps     map[string]*MapSpec
	Programs map[string]*ProgramSpec
}

// Copy returns a recursive copy of the spec.
func (cs *CollectionSpec) Copy() *CollectionSpec {
	if cs == nil {
		return nil
	}

	cpy := CollectionSpec{
		Maps:     make(map[string]*MapSpec, len(cs.Maps)),
		Programs: make(map[string]*ProgramSpec, len(cs.Programs)),
	}

	for name, spec := range cs.Maps {
		cpy.Maps[name] = spec.Copy()
	}

	for name, spec := range cs.Programs {
		cpy.Programs[name] = spec.Copy()
	}

	return &cpy
}

// LoadCollectionSpec parse an object file and convert it to a collection
func LoadCollectionSpec(file string) (*CollectionSpec, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return LoadCollectionSpecFromReader(f)
}

// Collection is a collection of Programs and Maps associated
// with their symbols
type Collection struct {
	Programs map[string]*Program
	Maps     map[string]*Map
}

// NewCollection creates a Collection from a specification.
//
// Only maps referenced by at least one of the programs are initialized.
func NewCollection(spec *CollectionSpec) (*Collection, error) {
	return NewCollectionWithOptions(spec, CollectionOptions{})
}

// LoadCollection parses an object file and converts it to a collection.
func LoadCollection(file string) (*Collection, error) {
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		return nil, err
	}
	return NewCollection(spec)
}

// EnableKprobes enables all kprobes/kretprobes included in the collection.
//
// For kretprobes, you can configure the maximum number of instances
// of the function that can be probed simultaneously with maxactive.
// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
// For kprobes, maxactive is ignored.
func (coll *Collection) EnableKprobes(maxactive int) error {
	for name, prog := range coll.Programs {
		if prog.IsKProbe() || prog.IsKRetProbe() {
			if err := coll.EnableKprobe(name, maxactive); err != nil {
				return errors.Wrapf(err, "couldn't enable kprobe %s", name)
			}
		}
	}
	return nil
}

// EnableKprobe enables the kprobe selected by its section name.
//
// For kretprobes, you can configure the maximum number of instances
// of the function that can be probed simultaneously with maxactive.
// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
// For kprobes, maxactive is ignored.
func (coll *Collection) EnableKprobe(secName string, maxactive int) error {
	// Check if section exists
	prog, ok := coll.Programs[secName]
	if !ok {
		return errors.Wrapf(
			errors.New("section not found"),
			"couldn't enable kprobe %s",
			secName,
		)
	}
	if prog.IsKProbe() || prog.IsKRetProbe() {
		return prog.EnableKprobe(maxactive)
	}
	return errors.Wrapf(
		errors.New("not a kprobe"),
		"couldn't enable program %s",
		secName,
	)
}

// EnableTracepoints enables all tracepoints included in the collection.
func (coll *Collection) EnableTracepoints() error {
	for name, prog := range coll.Programs {
		if prog.ProgramSpec.Type == TracePoint {
			if err := coll.EnableTracepoint(name); err != nil {
				return errors.Wrapf(err, "couldn't enable tracepoint %s", name)
			}
		}
	}
	return nil
}

// EnableTracepoint enables the tracepoint selected by its section name.
func (coll *Collection) EnableTracepoint(secName string) error {
	// Check if section exists
	prog, ok := coll.Programs[secName]
	if !ok {
		return errors.Wrapf(
			errors.New("section not found"),
			"couldn't enable tracepoint %s",
			secName,
		)
	}
	if prog.ProgramSpec.Type == TracePoint {
		return prog.EnableTracepoint()
	}
	return errors.Wrapf(
		errors.New("not a tracepoint"),
		"couldn't enable program %s",
		secName,
	)
}

// AttachCgroupProgram attaches a program to a cgroup
func (coll *Collection) AttachCgroupProgram(secName string, cgroupPath string) error {
	prog, ok := coll.Programs[secName]
	if !ok {
		return errors.Wrapf(
			errors.New("section not found"),
			"couldn't attach program %s",
			secName,
		)
	}
	if prog.IsCgroupProgram() {
		return prog.AttachCgroup(cgroupPath)
	}
	return errors.Wrapf(
		errors.New("not a cgroup program"),
		"couldn't attach program %s",
		secName,
	)
}

// Close frees all maps and programs associated with the collection.
//
// The collection mustn't be used afterwards.
func (coll *Collection) Close() []error {
	errs := []error{}
	for secName, prog := range coll.Programs {
		if errTmp := prog.Close(); errTmp != nil {
			errs = append(errs, errors.Wrapf(errTmp, "couldn't close program %s", secName))
		}
	}
	for secName, m := range coll.Maps {
		if errTmp := m.Close(); errTmp != nil {
			errs = append(errs, errors.Wrapf(errTmp, "couldn't close map %s", secName))
		}
	}
	return errs
}

// DetachMap removes the named map from the Collection.
//
// This means that a later call to Close() will not affect this map.
//
// Returns nil if no map of that name exists.
func (coll *Collection) DetachMap(name string) *Map {
	m := coll.Maps[name]
	delete(coll.Maps, name)
	return m
}

// DetachProgram removes the named program from the Collection.
//
// This means that a later call to Close() will not affect this program.
//
// Returns nil if no program of that name exists.
func (coll *Collection) DetachProgram(name string) *Program {
	p := coll.Programs[name]
	delete(coll.Programs, name)
	return p
}
