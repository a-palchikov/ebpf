package main

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/Gui774ume/ebpf"
)

const ebpfBytecode = "probe.o"

func main() {
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

	coll, err := ebpf.LoadCollection(ebpfBytecode)
	if err != nil {
		panic(err)
	}
	if err := coll.EnableKprobes(-1); err != nil {
		panic(err)
	}

	time.Sleep(3 * time.Second)

	// Get Map
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
	if errs := coll.Close(); len(errs) > 0 {
		fmt.Println(err)
	}
}
