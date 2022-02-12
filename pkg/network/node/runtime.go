package node

import (
	"fmt"
	"time"

	"k8s.io/klog/v2"

	kubeletapi "k8s.io/cri-api/pkg/apis"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	kubeletremote "k8s.io/kubernetes/pkg/kubelet/cri/remote"
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

	var err error
	node.runtimeService, err = kubeletremote.NewRemoteRuntimeService(runtimeEndpoint, runtimeRequestTimeout)
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

func (node *OsdnNode) getSDNPodSandboxes() (map[string]*kruntimeapi.PodSandbox, error) {
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
		status, err := runtimeService.PodSandboxStatus(sandbox.Id)
		if err != nil {
			klog.Warningf("Could not get status of pod %s/%s: %v", sandbox.Metadata.Namespace, sandbox.Metadata.Name, err)
			continue
		}
		if status.Linux.Namespaces.Options.Network == kruntimeapi.NamespaceMode_NODE {
			klog.V(4).Infof("Ignoring pod %s/%s which is hostNetwork", sandbox.Metadata.Namespace, sandbox.Metadata.Name)
			continue
		}

		klog.V(4).Infof("Found existing pod %s/%s", sandbox.Metadata.Namespace, sandbox.Metadata.Name)
		podSandboxMap[sandbox.Id] = sandbox
	}
	return podSandboxMap, nil
}
