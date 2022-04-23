package bpf

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run -mod=vendor github.com/cilium/ebpf/cmd/bpf2go bpf bpf.c -- -I./include

func InitBPF(hostPrefix string) (map[string]*ebpf.Map, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("could not load objects: %v", err)
	}

	err := objs.ProbabilityHalf.Pin(hostPrefix + "/sys/fs/bpf/probability_1_2")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("could not pin object: %v", err)
	}
	err = objs.ProbabilityThird.Pin(hostPrefix + "/sys/fs/bpf/probability_1_3")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("could not pin object: %v", err)
	}
	err = objs.ProbabilityFourth.Pin(hostPrefix + "/sys/fs/bpf/probability_1_4")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("could not pin object: %v", err)
	}

	err = objs.CheckRejectMap.Pin(hostPrefix + "/sys/fs/bpf/check_reject_map")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("could not pin object: %v", err)
	}
	err = objs.CheckAcceptMap.Pin(hostPrefix + "/sys/fs/bpf/check_accept_map")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("could not pin object: %v", err)
	}

	return map[string]*ebpf.Map{
		"accept_map": objs.AcceptMap,
		"reject_map": objs.RejectMap,
	}, nil
}
