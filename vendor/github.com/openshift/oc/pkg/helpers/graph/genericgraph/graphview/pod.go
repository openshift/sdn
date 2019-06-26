package graphview

import (
	osgraph "github.com/openshift/oc/pkg/helpers/graph/genericgraph"
	kubegraph "github.com/openshift/oc/pkg/helpers/graph/kubegraph/nodes"
)

type Pod struct {
	Pod *kubegraph.PodNode
}

// AllPods returns all Pods and the set of covered NodeIDs
func AllPods(g osgraph.Graph, excludeNodeIDs IntSet) ([]Pod, IntSet) {
	covered := IntSet{}
	pods := []Pod{}

	for _, uncastNode := range g.NodesByKind(kubegraph.PodNodeKind) {
		if excludeNodeIDs.Has(uncastNode.ID()) {
			continue
		}

		pod, covers := NewPod(g, uncastNode.(*kubegraph.PodNode))
		covered.Insert(covers.List()...)
		pods = append(pods, pod)
	}

	return pods, covered
}

// NewPod returns the Pod and a set of all the NodeIDs covered by the Pod
func NewPod(g osgraph.Graph, podNode *kubegraph.PodNode) (Pod, IntSet) {
	covered := IntSet{}
	covered.Insert(podNode.ID())

	podView := Pod{}
	podView.Pod = podNode

	return podView, covered
}
