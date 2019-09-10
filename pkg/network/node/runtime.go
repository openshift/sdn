// +build linux

package node

import (
	"fmt"
	"time"

	kwait "k8s.io/apimachinery/pkg/util/wait"
	kubeletapi "k8s.io/cri-api/pkg/apis"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	kubeletremote "k8s.io/kubernetes/pkg/kubelet/remote"
)

const (
	runtimeEndpoint = "unix:///var/run/crio/crio.sock"
	// 2 minutes is the current default value used in kubelet
	runtimeRequestTimeout = 2 * time.Minute
)

func (node *OsdnNode) getRuntimeService() (kubeletapi.RuntimeService, error) {
	if node.runtimeService != nil {
		return node.runtimeService, nil
	}

	// Kubelet starts asynchronously and when we get an Update op, kubelet may not have created runtime endpoint.
	// So try couple of times before bailing out (~30 seconds timeout).
	err := kwait.ExponentialBackoff(
		kwait.Backoff{
			Duration: 100 * time.Millisecond,
			Factor:   1.2,
			Steps:    24,
		},
		func() (bool, error) {
			runtimeService, err := kubeletremote.NewRemoteRuntimeService(runtimeEndpoint, runtimeRequestTimeout)
			if err != nil {
				// Wait longer
				return false, nil
			}

			// Ensure the runtime is actually alive; gRPC may create the client but
			// it may not be responding to requests yet
			if _, err := runtimeService.ListPodSandbox(&kruntimeapi.PodSandboxFilter{}); err != nil {
				// Wait longer
				return false, nil
			}

			node.runtimeService = runtimeService
			return true, nil
		})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch runtime service: %v", err)
	}
	return node.runtimeService, nil
}

func (node *OsdnNode) getPodSandboxID(filter *kruntimeapi.PodSandboxFilter) (string, error) {
	runtimeService, err := node.getRuntimeService()
	if err != nil {
		return "", err
	}

	podSandboxList, err := runtimeService.ListPodSandbox(filter)
	if err != nil {
		return "", fmt.Errorf("failed to list pod sandboxes: %v", err)
	}
	if len(podSandboxList) == 0 {
		return "", fmt.Errorf("pod sandbox not found for filter: %v", filter)
	}
	return podSandboxList[0].Id, nil
}

func (node *OsdnNode) getPodSandboxes() (map[string]*kruntimeapi.PodSandbox, error) {
	runtimeService, err := node.getRuntimeService()
	if err != nil {
		return nil, err
	}

	podSandboxList, err := runtimeService.ListPodSandbox(&kruntimeapi.PodSandboxFilter{
		State: &kruntimeapi.PodSandboxStateValue{State: kruntimeapi.PodSandboxState_SANDBOX_READY},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pod sandboxes: %v", err)
	}

	podSandboxMap := make(map[string]*kruntimeapi.PodSandbox)
	for _, sandbox := range podSandboxList {
		podSandboxMap[sandbox.Id] = sandbox
	}
	return podSandboxMap, nil
}
