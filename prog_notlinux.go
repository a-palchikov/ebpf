//go:build !linux

package ebpf

import "time"

func NewProgram(spec *ProgramSpec) (*Program, error) {
	return nil, errNotImplemented
}

func NewProgramWithOptions(spec *ProgramSpec, opts ProgramOptions) (*Program, error) {
	return nil, errNotImplemented
}

func (bpf *Program) EnableKprobe(maxactive int) error {
	return errNotImplemented
}

func (bpf *Program) EnableTracepoint() error {
	return errNotImplemented
}

func (bpf *Program) AttachCgroup(cgroupPath string) error {
	return errNotImplemented
}

func (bpf *Program) String() string {
	return "<invalid>"
}

func (bpf *Program) FD() int {
	return -1
}

func (bpf *Program) Clone() (*Program, error) {
	return nil, errNotImplemented
}

func (bpf *Program) Pin(fileName string) error {
	return errNotImplemented
}

func (bpf *Program) Close() error {
	return errNotImplemented
}

func (bpf *Program) Test(in []byte) (uint32, []byte, error) {
	return 0, nil, errNotImplemented
}

func (bpf *Program) Benchmark(in []byte, repeat int) (uint32, time.Duration, error) {
	return 0, 0, errNotImplemented
}

func LoadPinnedProgram(fileName string) (*Program, error) {
	return nil, errNotImplemented
}

func LoadPinnedProgramExplicit(fileName string, abi *ProgramABI) (*Program, error) {
	return nil, errNotImplemented
}

type bpfProg struct{}
