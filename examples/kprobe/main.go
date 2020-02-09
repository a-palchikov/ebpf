package main

import (
	"fmt"

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
}
