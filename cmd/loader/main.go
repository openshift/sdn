package main

import (
	"fmt"

	"github.com/openshift/sdn/pkg/network/node/bpf"
)

func main() {
	err := bpf.InitBPF("")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
}
