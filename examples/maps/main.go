package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/Gui774ume/ebpf"
)

const ebpfBytecode = "probe.o"

// CIDRKey - CIDR key
type CIDRKey struct {
	Prefix uint32
	Data   [16]uint8
}

// GetUnsafePointer - Returns an unsafe Pointer to the data
func (k *CIDRKey) GetUnsafePointer(byteOrder binary.ByteOrder) (unsafe.Pointer, error) {
	keyB, err := InterfaceToBytes(k, byteOrder)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&keyB[0]), nil
}

// GetHostByteOrder - Returns the host byte order
func GetHostByteOrder() binary.ByteOrder {
	if IsBigEndian() {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// IsBigEndian - Returns true if the host byte order is BigEndian
func IsBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}

// InterfaceToBytes - Tranforms an interface into a C bytes array
func InterfaceToBytes(data interface{}, byteOrder binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, byteOrder, data); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

func main() {
	// Print sections
	spec, err := ebpf.LoadCollectionSpec(ebpfBytecode)
	if err != nil {
		panic(err)
	}
	fmt.Println("Maps:")
	for k, v := range spec.Maps {
		fmt.Printf("\t%s:\n", k)
		fmt.Printf("\t\tMapType:    %s\n", v.Type)
		fmt.Printf("\t\tKeySize:    %d\n", v.KeySize)
		fmt.Printf("\t\tValueSize:  %d\n", v.ValueSize)
		fmt.Printf("\t\tMaxEntries: %d\n", v.MaxEntries)
		fmt.Printf("\t\tFlags:      %d\n", v.Flags)
	}
	fmt.Println("\nPrograms:")
	for k, v := range spec.Programs {
		fmt.Printf("\t%s:\n", k)
		fmt.Printf("\t\tSectionName:   %s\n", v.SectionName)
		fmt.Printf("\t\tProgType:      %s\n", v.Type)
		fmt.Printf("\t\tLicense:       %s\n", v.License)
		fmt.Printf("\t\tKernelVersion: %d\n", v.KernelVersion)
		fmt.Printf("\t\tInstructions:\n")
		fmt.Printf("%.3s", v.Instructions)
	}
	fmt.Println("")

	// Load program and maps
	coll, err := ebpf.LoadCollection(ebpfBytecode)
	if err != nil {
		panic(err)
	}
	if err := coll.EnableKprobes(-1); err != nil {
		panic(err)
	}

	time.Sleep(3 * time.Second)

	// Dump map_test
	hashmap, ok := coll.Maps["map_test"]
	if !ok {
		panic(errors.New("couldn't find map"))
	}
	fmt.Println("Dumping map_test:")
	iterator := hashmap.Iterate()
	var key, value uint32
	for iterator.Next(&key, &value) {
		fmt.Printf("key: %v \tvalue:%v\n", key, value)
	}
	if err := iterator.Err(); err != nil {
		fmt.Println(err)
	}

	time.Sleep(3 * time.Second)

	// Prepare CIDR key
	cidr := "192.168.0.0/24"
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ip4 := ip.To4()
	prefix, _ := net.Mask.Size()
	cidrk := CIDRKey{
		Prefix: uint32(prefix),
	}
	copy(cidrk.Data[:], ip4)
	fmt.Println(cidrk)
	keyPtr, err := cidrk.GetUnsafePointer(GetHostByteOrder())
	if err != nil {
		panic(err)
	}
	valueB := uint64(14)
	valuePtr := unsafe.Pointer(&valueB)

	// Select routing_map in kernel
	lpmmap, ok := coll.Maps["routing_map"]
	if !ok {
		panic(errors.New("couldn't find map"))
	}
	// Update value. After this step the value printed in `trace_pipe` should change.
	if err := lpmmap.Put(keyPtr, valuePtr); err != nil {
		panic(err)
	}

	time.Sleep(10 * time.Second)

	// Close program and maps
	if errs := coll.Close(); len(errs) > 0 {
		fmt.Println(err)
	}
}
