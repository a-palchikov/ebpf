package main

import (
	"fmt"
	"time"

	"github.com/Gui774ume/ebpf"
)

const ebpfBytecode = "probe.o"

func main() {
	spec, err := ebpf.LoadCollectionSpec(ebpfBytecode)
	if err != nil {
		panic(err)
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

	// Edit my_constant
	constSymbol := "my_constant_sym"
	for k, v := range spec.Programs {
		editor := ebpf.Edit(&v.Instructions)
		if err := editor.RewriteConstant(constSymbol, 42); err != nil {
			fmt.Printf("Couldn't rewrite symbol %s in program %s: %v\n", constSymbol, k, err)
		} else {
			fmt.Printf("Symbol %s in program %s edited\n", constSymbol, k)
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	if err := coll.EnableTracepoints(); err != nil {
		panic(err)
	}
	time.Sleep(5 * time.Second)
	if errs := coll.Close(); len(errs) > 0 {
		fmt.Println(err)
	}
}
