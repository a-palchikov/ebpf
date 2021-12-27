package ebpf

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/ebpf/asm"
)

// Errors returned by the implementation
var (
	ErrNotSupported = errors.New("ebpf: not supported by kernel")
)

const (
	// Number of bytes to pad the output buffer for BPF_PROG_TEST_RUN.
	// This is currently the maximum of spare space allocated for SKB
	// and XDP programs, and equal to XDP_PACKET_HEADROOM + NET_IP_ALIGN.
	outputPad = 256 + 2
)

// DefaultVerifierLogSize is the default number of bytes allocated for the
// verifier log.
const DefaultVerifierLogSize = 64 * 1024

type bpfProg struct {
	fd                 *bpfFD
	efd                *bpfFD
	efds               map[string]*bpfFD
}

// NewProgram creates a new Program.
//
// Loading a program for the first time will perform
// feature detection by loading small, temporary programs.
func NewProgram(spec *ProgramSpec) (*Program, error) {
	return NewProgramWithOptions(spec, ProgramOptions{})
}

// NewProgramWithOptions creates a new Program.
//
// Loading a program for the first time will perform
// feature detection by loading small, temporary programs.
func NewProgramWithOptions(spec *ProgramSpec, opts ProgramOptions) (*Program, error) {
	attr, err := convertProgramSpec(spec, haveObjName.Result())
	if err != nil {
		return nil, err
	}

	logSize := DefaultVerifierLogSize
	if opts.LogSize > 0 {
		logSize = opts.LogSize
	}

	var logBuf []byte
	if opts.LogLevel > 0 {
		logBuf = make([]byte, logSize)
		attr.logLevel = opts.LogLevel
		attr.logSize = uint32(len(logBuf))
		attr.logBuf = newPtr(unsafe.Pointer(&logBuf[0]))
	}

	fd, err := bpfProgLoad(attr)
	if err == nil {
		prog := newProgram(fd, spec.Name, &ProgramABI{spec.Type})
		prog.VerifierLog = convertCString(logBuf)
		prog.ProgramSpec = spec
		return prog, nil
	}

	truncated := errors.Cause(err) == unix.ENOSPC
	if opts.LogLevel == 0 {
		// Re-run with the verifier enabled to get better error messages.
		logBuf = make([]byte, logSize)
		attr.logLevel = 1
		attr.logSize = uint32(len(logBuf))
		attr.logBuf = newPtr(unsafe.Pointer(&logBuf[0]))

		_, nerr := bpfProgLoad(attr)
		truncated = errors.Cause(nerr) == unix.ENOSPC
	}

	logs := convertCString(logBuf)
	if truncated {
		logs += "\n(truncated...)"
	}

	return nil, &loadError{err, logs}
}

func newProgram(fd *bpfFD, name string, abi *ProgramABI) *Program {
	return &Program{
		name:    name,
		bpfProg: bpfProg{fd: fd},
		abi:     *abi,
	}
}

func convertProgramSpec(spec *ProgramSpec, includeName bool) (*bpfProgLoadAttr, error) {
	if len(spec.Instructions) == 0 {
		return nil, errors.New("Instructions cannot be empty")
	}

	if len(spec.License) == 0 {
		return nil, errors.New("License cannot be empty")
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(spec.Instructions)*asm.InstructionSize))
	err := spec.Instructions.Marshal(buf, nativeEndian)
	if err != nil {
		return nil, err
	}

	bytecode := buf.Bytes()
	insCount := uint32(len(bytecode) / asm.InstructionSize)
	lic := []byte(spec.License)
	attr := &bpfProgLoadAttr{
		progType:           spec.Type,
		expectedAttachType: spec.AttachType,
		insCount:           insCount,
		instructions:       newPtr(unsafe.Pointer(&bytecode[0])),
		license:            newPtr(unsafe.Pointer(&lic[0])),
		kernelVersion:      spec.KernelVersion,
	}

	name, err := newBPFObjName(spec.Name)
	if err != nil {
		return nil, err
	}

	if includeName {
		attr.progName = name
	}

	return attr, nil
}

// EnableKprobe enables the program if it is a kprobe.
//
// For kretprobes, you can configure the maximum number of instances
// of the function that can be probed simultaneously with maxactive.
// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
// For kprobes, maxactive is ignored.
func (bpf *Program) EnableKprobe(maxactive int) error {
	var probeType, funcName, maxactiveStr string
	if bpf.IsKRetProbe() {
		probeType = "r"
		funcName = strings.TrimPrefix(bpf.ProgramSpec.SectionName, "kretprobe/")
		if maxactive > 0 {
			maxactiveStr = fmt.Sprintf("%d", maxactive)
		}
	} else if bpf.IsKProbe() {
		probeType = "p"
		funcName = strings.TrimPrefix(bpf.ProgramSpec.SectionName, "kprobe/")
	} else {
		return errors.Wrapf(
			errors.New("not a kprobe"),
			"couldn't enable program %s",
			bpf.ProgramSpec.SectionName,
		)
	}
	eventName := probeType + funcName
	kprobeID, err := writeKprobeEvent(probeType, eventName, funcName, maxactiveStr)
	// fallback without maxactive
	if err == errKprobeIDNotExist {
		kprobeID, err = writeKprobeEvent(probeType, eventName, funcName, "")
	}
	if err != nil {
		return errors.Wrapf(err, "couldn't enable kprobe %s", bpf.ProgramSpec.SectionName)
	}
	bpf.efd, err = perfEventOpenTracepoint(kprobeID, bpf.FD())
	if err != nil {
		return errors.Wrapf(err, "couldn't enable kprobe %s", bpf.ProgramSpec.SectionName)
	}
	return nil
}

// EnableTracepoint enables the program if it is a tracepoint.
func (bpf *Program) EnableTracepoint() error {
	if bpf.ProgramSpec.Type != TracePoint {
		return errors.Wrapf(
			errors.New("not a tracepoint"),
			"couldn't enable program %s",
			bpf.ProgramSpec.SectionName,
		)
	}
	tracepointGroup := strings.SplitN(bpf.ProgramSpec.SectionName, "/", 3)
	if len(tracepointGroup) != 3 {
		return errors.Wrapf(
			errors.New("expected tracepoint/category/name"),
			"invalid section name %s",
			bpf.ProgramSpec.SectionName,
		)
	}
	category := tracepointGroup[1]
	name := tracepointGroup[2]
	tracepointID, err := writeTracepointEvent(category, name)
	if err != nil {
		return errors.Wrapf(err, "couldn's enable tracepoint %s", bpf.ProgramSpec.SectionName)
	}
	bpf.efd, err = perfEventOpenTracepoint(tracepointID, bpf.FD())
	if err != nil {
		return errors.Wrapf(err, "couldn't enable tracepoint %s", bpf.ProgramSpec.SectionName)
	}
	return nil
}

// AttachCgroup attaches the program to a cgroup
func (bpf *Program) AttachCgroup(cgroupPath string) error {
	if !bpf.IsCgroupProgram() {
		return errors.Wrapf(
			errors.New("not a cgroup program"),
			"couldn't attach program %s",
			bpf.ProgramSpec.SectionName,
		)
	}
	f, err := os.Open(cgroupPath)
	if err != nil {
		return errors.Wrapf(err, "error opening cgroup %s", cgroupPath)
	}
	defer f.Close()

	ret, err := bpfProgAttach(bpf.FD(), int(f.Fd()), bpf.ProgramSpec.AttachType)
	if ret < 0 {
		return errors.Wrapf(err, "failed to attach prog to cgroup %s", cgroupPath)
	}
	bpf.attachedCgroupPath = cgroupPath
	bpf.attachedType = bpf.ProgramSpec.AttachType
	return nil
}

func (bpf *Program) String() string {
	if bpf.name != "" {
		return fmt.Sprintf("%s(%s)#%s", bpf.abi.Type, bpf.name, bpf.fd)
	}
	return fmt.Sprintf("%s#%s", bpf.abi.Type, bpf.fd)
}

// FD gets the file descriptor of the Program.
//
// It is invalid to call this function after Close has been called.
func (bpf *Program) FD() int {
	fd, err := bpf.fd.value()
	if err != nil {
		// Best effort: -1 is the number most likely to be an
		// invalid file descriptor.
		return -1
	}

	return int(fd)
}

// Clone creates a duplicate of the Program.
//
// Closing the duplicate does not affect the original, and vice versa.
//
// Cloning a nil Program returns nil.
func (bpf *Program) Clone() (*Program, error) {
	if bpf == nil {
		return nil, nil
	}

	dup, err := bpf.fd.dup()
	if err != nil {
		return nil, errors.Wrap(err, "can't clone program")
	}

	return newProgram(dup, bpf.name, &bpf.abi), nil
}

// Pin persists the Program past the lifetime of the process that created it
//
// This requires bpffs to be mounted above fileName. See http://cilium.readthedocs.io/en/doc-1.0/kubernetes/install/#mounting-the-bpf-fs-optional
func (bpf *Program) Pin(fileName string) error {
	return errors.Wrap(bpfPinObject(fileName, bpf.fd), "can't pin program")
}

// Close unloads the program from the kernel.
func (bpf *Program) Close() error {
	var err, errTmp error
	if bpf == nil {
		return nil
	}
	if bpf.efd != nil {
		err = errors.Wrap(bpf.efd.close(), "couldn't close efd")
	}
	for _, efd := range bpf.efds {
		if errTmp = efd.close(); errTmp != nil {
			if err == nil {
				err = errTmp
			} else {
				err = errors.Wrapf(errTmp, "%v: couldn't close efd", err)
			}
		}
	}

	// Per program type cleanup
	switch bpf.ProgramSpec.Type {
	case Kprobe:
		if errTmp = bpf.disableProbe(); errTmp != nil {
			if err == nil {
				err = errTmp
			} else {
				err = errors.Wrapf(errTmp, "%v: couldn't cleanup %s", err, bpf.ProgramSpec.SectionName)
			}
		}
		break
	}

	// Detach program
	if bpf.IsCgroupProgram() {
		if errTmp = bpf.detachCgroup(); errTmp != nil {
			if err == nil {
				err = errTmp
			} else {
				err = errors.Wrapf(errTmp, "%v: couldn't detach %s", err, bpf.ProgramSpec.SectionName)
			}
		}
	}

	if bpf.fd != nil {
		if errTmp = errors.Wrap(bpf.fd.close(), "couldn't close fd"); errTmp != nil {
			if err == nil {
				err = errTmp
			} else {
				err = errors.Wrap(errTmp, err.Error())
			}
		}
	}
	return err
}

// disableProbe disables the program if it is a kprobe, kretprobe or uprobe
func (bpf *Program) disableProbe() error {
	if bpf.IsKRetProbe() {
		funcName := strings.TrimPrefix(bpf.ProgramSpec.SectionName, "kretprobe/")
		if err := disableKprobe("r" + funcName); err != nil {
			return errors.Wrap(err, "couldn't disable kretprobe")
		}
	} else if bpf.IsKProbe() {
		funcName := strings.TrimPrefix(bpf.ProgramSpec.SectionName, "kprobe/")
		if err := disableKprobe("p" + funcName); err != nil {
			return errors.Wrap(err, "couldn't disable kprobe")
		}
	} else if bpf.IsUProbe() {
		var err, errTmp error
		for eventName := range bpf.efds {
			if errTmp = disableUprobe(eventName); errTmp != nil {
				if err == nil {
					err = errTmp
				} else {
					err = errors.Wrapf(errTmp, "%v: couldn't disable uprobe", err)
				}
			}
		}
		return err
	}
	return nil
}

// detachCgroup detaches a cgroup program from its cgroup
func (bpf *Program) detachCgroup() error {
	if !bpf.IsCgroupProgram() || bpf.attachedCgroupPath == "" || bpf.attachedType == AttachNone {
		return nil
	}
	f, err := os.Open(bpf.attachedCgroupPath)
	if err != nil {
		return errors.Wrapf(err, "error opening cgroup %s", bpf.attachedCgroupPath)
	}
	defer f.Close()

	ret, err := bpfProgDetach(bpf.FD(), int(f.Fd()), bpf.attachedType)
	if ret < 0 {
		return errors.Wrapf(err, "got %v", ret)
	}
	return nil
}

// Test runs the Program in the kernel with the given input and returns the
// value returned by the eBPF program. outLen may be zero.
//
// Note: the kernel expects at least 14 bytes input for an ethernet header for
// XDP and SKB programs.
//
// This function requires at least Linux 4.12.
func (bpf *Program) Test(in []byte) (uint32, []byte, error) {
	ret, out, _, err := bpf.testRun(in, 1)
	return ret, out, err
}

// Benchmark runs the Program with the given input for a number of times
// and returns the time taken per iteration.
//
// The returned value is the return value of the last execution of
// the program.
//
// This function requires at least Linux 4.12.
func (bpf *Program) Benchmark(in []byte, repeat int) (uint32, time.Duration, error) {
	ret, _, total, err := bpf.testRun(in, repeat)
	return ret, total, err
}

var noProgTestRun = featureTest{
	Fn: func() bool {
		prog, err := NewProgram(&ProgramSpec{
			Type: SocketFilter,
			Instructions: asm.Instructions{
				asm.LoadImm(asm.R0, 0, asm.DWord),
				asm.Return(),
			},
			License: "MIT",
		})
		if err != nil {
			// This may be because we lack sufficient permissions, etc.
			return false
		}
		defer prog.Close()

		fd, err := prog.fd.value()
		if err != nil {
			return false
		}

		// Programs require at least 14 bytes input
		in := make([]byte, 14)
		attr := bpfProgTestRunAttr{
			fd:         fd,
			dataSizeIn: uint32(len(in)),
			dataIn:     newPtr(unsafe.Pointer(&in[0])),
		}

		_, err = bpfCall(_ProgTestRun, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		return errors.Cause(err) == unix.EINVAL
	},
}

func (bpf *Program) testRun(in []byte, repeat int) (uint32, []byte, time.Duration, error) {
	if uint(repeat) > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("repeat is too high")
	}

	if len(in) == 0 {
		return 0, nil, 0, fmt.Errorf("missing input")
	}

	if uint(len(in)) > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("input is too long")
	}

	if noProgTestRun.Result() {
		return 0, nil, 0, ErrNotSupported
	}

	// Older kernels ignore the dataSizeOut argument when copying to user space.
	// Combined with things like bpf_xdp_adjust_head() we don't really know what the final
	// size will be. Hence we allocate an output buffer which we hope will always be large
	// enough, and panic if the kernel wrote past the end of the allocation.
	// See https://patchwork.ozlabs.org/cover/1006822/
	out := make([]byte, len(in)+outputPad)

	fd, err := bpf.fd.value()
	if err != nil {
		return 0, nil, 0, err
	}

	attr := bpfProgTestRunAttr{
		fd:          fd,
		dataSizeIn:  uint32(len(in)),
		dataSizeOut: uint32(len(out)),
		dataIn:      newPtr(unsafe.Pointer(&in[0])),
		dataOut:     newPtr(unsafe.Pointer(&out[0])),
		repeat:      uint32(repeat),
	}

	_, err = bpfCall(_ProgTestRun, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return 0, nil, 0, errors.Wrap(err, "can't run test")
	}

	if int(attr.dataSizeOut) > cap(out) {
		// Houston, we have a problem. The program created more data than we allocated,
		// and the kernel wrote past the end of our buffer.
		panic("kernel wrote past end of output buffer")
	}
	out = out[:int(attr.dataSizeOut)]

	total := time.Duration(attr.duration) * time.Nanosecond
	return attr.retval, out, total, nil
}

func unmarshalProgram(buf []byte) (*Program, error) {
	if len(buf) != 4 {
		return nil, errors.New("program id requires 4 byte value")
	}

	// Looking up an entry in a nested map or prog array returns an id,
	// not an fd.
	id := nativeEndian.Uint32(buf)
	fd, err := bpfGetProgramFDByID(id)
	if err != nil {
		return nil, err
	}

	abi, err := newProgramABIFromFd(fd)
	if err != nil {
		_ = fd.close()
		return nil, err
	}

	return newProgram(fd, "", abi), nil
}

// MarshalBinary implements BinaryMarshaler.
func (bpf *Program) MarshalBinary() ([]byte, error) {
	value, err := bpf.fd.value()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4)
	nativeEndian.PutUint32(buf, value)
	return buf, nil
}

// LoadPinnedProgram loads a Program from a BPF file.
//
// Requires at least Linux 4.13, use LoadPinnedProgramExplicit on
// earlier versions.
func LoadPinnedProgram(fileName string) (*Program, error) {
	fd, err := bpfGetObject(fileName)
	if err != nil {
		return nil, err
	}

	abi, err := newProgramABIFromFd(fd)
	if err != nil {
		_ = fd.close()
		return nil, err
	}

	return newProgram(fd, filepath.Base(fileName), abi), nil
}

// LoadPinnedProgramExplicit loads a program with explicit parameters.
func LoadPinnedProgramExplicit(fileName string, abi *ProgramABI) (*Program, error) {
	fd, err := bpfGetObject(fileName)
	if err != nil {
		return nil, err
	}

	return newProgram(fd, filepath.Base(fileName), abi), nil
}

type loadError struct {
	cause       error
	verifierLog string
}

func (le *loadError) Error() string {
	if le.verifierLog == "" {
		return fmt.Sprintf("failed to load program: %s", le.cause)
	}
	return fmt.Sprintf("failed to load program: %s: %s", le.cause, le.verifierLog)
}

func (le *loadError) Cause() error {
	return le.cause
}

var errKprobeIDNotExist error = errors.New("kprobe id file doesn't exist")

func writeKprobeEvent(probeType, eventName, funcName, maxactiveStr string) (int, error) {
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxactiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil {
		return -1, errors.Wrapf(err, "cannot write %q to kprobe_events", cmd)
	}
	kprobeIDFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	kprobeIDBytes, err := ioutil.ReadFile(kprobeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, errKprobeIDNotExist
		}
		return -1, errors.Wrap(err, "cannot read kprobe id")
	}
	kprobeID, err := strconv.Atoi(strings.TrimSpace(string(kprobeIDBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid kprobe id: %v")
	}

	return kprobeID, nil
}

func writeTracepointEvent(category, name string) (int, error) {
	tracepointIDFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", category, name)
	tracepointIDBytes, err := ioutil.ReadFile(tracepointIDFile)
	if err != nil {
		return -1, errors.Wrapf(err, "cannot read tracepoint id %q", tracepointIDFile)
	}
	tracepointID, err := strconv.Atoi(strings.TrimSpace(string(tracepointIDBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid tracepoint id")
	}
	return tracepointID, nil
}

func disableKprobe(eventName string) error {
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok && pathErr.Err == syscall.ENOENT {
			// This can happen when for example two modules
			// use the same elf object and both call `Close()`.
			// The second will encounter the error as the
			// probe already has been cleared by the first.
			return nil
		} else {
			return errors.Wrapf(err, "cannot write %q to kprobe_events: %v", cmd)
		}
	}
	return nil
}

func disableUprobe(eventName string) error {
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrapf(err, "cannot open uprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		return errors.Wrapf(err, "cannot write %q to uprobe_events: %v", cmd)
	}
	return nil
}
