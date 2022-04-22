package bpf

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run -mod=vendor github.com/cilium/ebpf/cmd/bpf2go bpf bpf.c -- -I./include

func InitBPF(hostPrefix string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("could not load objects: %v", err)
	}
	defer objs.Close()

	err := objs.ProbabilityHalf.Pin(hostPrefix + "/sys/fs/bpf/probability_1_2")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("could not pin object: %v", err)
	}
	err = objs.ProbabilityThird.Pin(hostPrefix + "/sys/fs/bpf/probability_1_3")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("could not pin object: %v", err)
	}
	err = objs.ProbabilityFourth.Pin(hostPrefix + "/sys/fs/bpf/probability_1_4")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("could not pin object: %v", err)
	}

	return nil
}
