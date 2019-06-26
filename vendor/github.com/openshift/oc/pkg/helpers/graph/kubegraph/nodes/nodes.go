package nodes

import (
	"github.com/gonum/graph"

	kappsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	osgraph "github.com/openshift/oc/pkg/helpers/graph/genericgraph"
)

func EnsurePodNode(g osgraph.MutableUniqueGraph, pod *corev1.Pod) *PodNode {
	podNodeName := PodNodeName(pod)
	podNode := osgraph.EnsureUnique(g,
		podNodeName,
		func(node osgraph.Node) graph.Node {
			return &PodNode{node, pod}
		},
	).(*PodNode)

	podSpecNode := EnsurePodSpecNode(g, &pod.Spec, pod.Namespace, podNodeName)
	g.AddEdge(podNode, podSpecNode, osgraph.ContainsEdgeKind)

	return podNode
}

func EnsurePodSpecNode(g osgraph.MutableUniqueGraph, podSpec *corev1.PodSpec, namespace string, ownerName osgraph.UniqueName) *PodSpecNode {
	return osgraph.EnsureUnique(g,
		PodSpecNodeName(podSpec, ownerName),
		func(node osgraph.Node) graph.Node {
			return &PodSpecNode{node, podSpec, namespace, ownerName}
		},
	).(*PodSpecNode)
}

// EnsureServiceNode adds the provided service to the graph if it does not already exist.
func EnsureServiceNode(g osgraph.MutableUniqueGraph, svc *corev1.Service) *ServiceNode {
	return osgraph.EnsureUnique(g,
		ServiceNodeName(svc),
		func(node osgraph.Node) graph.Node {
			return &ServiceNode{node, svc, true}
		},
	).(*ServiceNode)
}

// FindOrCreateSyntheticServiceNode returns the existing service node or creates a synthetic node in its place
func FindOrCreateSyntheticServiceNode(g osgraph.MutableUniqueGraph, svc *corev1.Service) *ServiceNode {
	return osgraph.EnsureUnique(g,
		ServiceNodeName(svc),
		func(node osgraph.Node) graph.Node {
			return &ServiceNode{node, svc, false}
		},
	).(*ServiceNode)
}

func EnsureServiceAccountNode(g osgraph.MutableUniqueGraph, o *corev1.ServiceAccount) *ServiceAccountNode {
	return osgraph.EnsureUnique(g,
		ServiceAccountNodeName(o),
		func(node osgraph.Node) graph.Node {
			return &ServiceAccountNode{node, o, true}
		},
	).(*ServiceAccountNode)
}

func FindOrCreateSyntheticServiceAccountNode(g osgraph.MutableUniqueGraph, o *corev1.ServiceAccount) *ServiceAccountNode {
	return osgraph.EnsureUnique(g,
		ServiceAccountNodeName(o),
		func(node osgraph.Node) graph.Node {
			return &ServiceAccountNode{node, o, false}
		},
	).(*ServiceAccountNode)
}

func EnsureSecretNode(g osgraph.MutableUniqueGraph, o *corev1.Secret) *SecretNode {
	return osgraph.EnsureUnique(g,
		SecretNodeName(o),
		func(node osgraph.Node) graph.Node {
			return &SecretNode{
				Node:    node,
				Secret:  o,
				IsFound: true,
			}
		},
	).(*SecretNode)
}

func FindOrCreateSyntheticSecretNode(g osgraph.MutableUniqueGraph, o *corev1.Secret) *SecretNode {
	return osgraph.EnsureUnique(g,
		SecretNodeName(o),
		func(node osgraph.Node) graph.Node {
			return &SecretNode{
				Node:    node,
				Secret:  o,
				IsFound: false,
			}
		},
	).(*SecretNode)
}

// EnsureReplicationControllerNode adds a graph node for the ReplicationController if it does not already exist.
func EnsureReplicationControllerNode(g osgraph.MutableUniqueGraph, rc *corev1.ReplicationController) *ReplicationControllerNode {
	rcNodeName := ReplicationControllerNodeName(rc)
	rcNode := osgraph.EnsureUnique(g,
		rcNodeName,
		func(node osgraph.Node) graph.Node {
			return &ReplicationControllerNode{node, rc, true}
		},
	).(*ReplicationControllerNode)

	rcSpecNode := EnsureReplicationControllerSpecNode(g, &rc.Spec, rc.Namespace, rcNodeName)
	g.AddEdge(rcNode, rcSpecNode, osgraph.ContainsEdgeKind)

	return rcNode
}

// EnsureJobNode adds a graph node for the Job if it does not already exist.
func EnsureJobNode(g osgraph.MutableUniqueGraph, job *batchv1.Job) *JobNode {
	jobNodeName := JobNodeName(job)
	jobNode := osgraph.EnsureUnique(g,
		jobNodeName,
		func(node osgraph.Node) graph.Node {
			return &JobNode{node, job, true}
		},
	).(*JobNode)

	jobSpecNode := EnsureJobSpecNode(g, &job.Spec, job.Namespace, jobNodeName)
	g.AddEdge(jobNode, jobSpecNode, osgraph.ContainsEdgeKind)

	return jobNode
}

func EnsureJobSpecNode(g osgraph.MutableUniqueGraph, jobSpec *batchv1.JobSpec, namespace string, ownerName osgraph.UniqueName) *JobSpecNode {
	jobSpecName := JobSpecNodeName(jobSpec, ownerName)
	jobSpecNode := osgraph.EnsureUnique(g,
		jobSpecName,
		func(node osgraph.Node) graph.Node {
			return &JobSpecNode{node, jobSpec, namespace, ownerName}
		},
	).(*JobSpecNode)

	ptSpecNode := EnsurePodTemplateSpecNode(g, &jobSpec.Template, namespace, jobSpecName)
	g.AddEdge(jobSpecNode, ptSpecNode, osgraph.ContainsEdgeKind)

	return jobSpecNode
}

// EnsureReplicaSetNode adds a graph node for the ReplicaSet if it does not already exist.
func EnsureReplicaSetNode(g osgraph.MutableUniqueGraph, rs *kappsv1.ReplicaSet) *ReplicaSetNode {
	rsNodeName := ReplicaSetNodeName(rs)
	rsNode := osgraph.EnsureUnique(g,
		rsNodeName,
		func(node osgraph.Node) graph.Node {
			return &ReplicaSetNode{node, rs, true}
		},
	).(*ReplicaSetNode)

	rcSpecNode := EnsureReplicaSetSpecNode(g, &rs.Spec, rs.Namespace, rsNodeName)
	g.AddEdge(rsNode, rcSpecNode, osgraph.ContainsEdgeKind)

	return rsNode
}

func EnsureReplicaSetSpecNode(g osgraph.MutableUniqueGraph, rsSpec *kappsv1.ReplicaSetSpec, namespace string, ownerName osgraph.UniqueName) *ReplicaSetSpecNode {
	rsSpecName := ReplicaSetSpecNodeName(rsSpec, ownerName)
	rsSpecNode := osgraph.EnsureUnique(g,
		rsSpecName,
		func(node osgraph.Node) graph.Node {
			return &ReplicaSetSpecNode{node, rsSpec, namespace, ownerName}
		},
	).(*ReplicaSetSpecNode)

	ptSpecNode := EnsurePodTemplateSpecNode(g, &rsSpec.Template, namespace, rsSpecName)
	g.AddEdge(rsSpecNode, ptSpecNode, osgraph.ContainsEdgeKind)

	return rsSpecNode
}

func FindOrCreateSyntheticReplicationControllerNode(g osgraph.MutableUniqueGraph, rc *corev1.ReplicationController) *ReplicationControllerNode {
	return osgraph.EnsureUnique(g,
		ReplicationControllerNodeName(rc),
		func(node osgraph.Node) graph.Node {
			return &ReplicationControllerNode{node, rc, false}
		},
	).(*ReplicationControllerNode)
}

func FindOrCreateSyntheticDeploymentNode(g osgraph.MutableUniqueGraph, deployment *kappsv1.Deployment) *DeploymentNode {
	return osgraph.EnsureUnique(
		g,
		DeploymentNodeName(deployment),
		func(node osgraph.Node) graph.Node {
			return &DeploymentNode{Node: node, Deployment: deployment, IsFound: false}
		},
	).(*DeploymentNode)
}

func EnsureReplicationControllerSpecNode(g osgraph.MutableUniqueGraph, rcSpec *corev1.ReplicationControllerSpec, namespace string, ownerName osgraph.UniqueName) *ReplicationControllerSpecNode {
	rcSpecName := ReplicationControllerSpecNodeName(rcSpec, ownerName)
	rcSpecNode := osgraph.EnsureUnique(g,
		rcSpecName,
		func(node osgraph.Node) graph.Node {
			return &ReplicationControllerSpecNode{node, rcSpec, namespace, ownerName}
		},
	).(*ReplicationControllerSpecNode)

	if rcSpec.Template != nil {
		ptSpecNode := EnsurePodTemplateSpecNode(g, rcSpec.Template, namespace, rcSpecName)
		g.AddEdge(rcSpecNode, ptSpecNode, osgraph.ContainsEdgeKind)
	}

	return rcSpecNode
}

func EnsurePodTemplateSpecNode(g osgraph.MutableUniqueGraph, ptSpec *corev1.PodTemplateSpec, namespace string, ownerName osgraph.UniqueName) *PodTemplateSpecNode {
	ptSpecName := PodTemplateSpecNodeName(ptSpec, ownerName)
	ptSpecNode := osgraph.EnsureUnique(g,
		ptSpecName,
		func(node osgraph.Node) graph.Node {
			return &PodTemplateSpecNode{node, ptSpec, namespace, ownerName}
		},
	).(*PodTemplateSpecNode)

	podSpecNode := EnsurePodSpecNode(g, &ptSpec.Spec, namespace, ptSpecName)
	g.AddEdge(ptSpecNode, podSpecNode, osgraph.ContainsEdgeKind)

	return ptSpecNode
}

func EnsurePersistentVolumeClaimNode(g osgraph.MutableUniqueGraph, pvc *corev1.PersistentVolumeClaim) *PersistentVolumeClaimNode {
	return osgraph.EnsureUnique(g,
		PersistentVolumeClaimNodeName(pvc),
		func(node osgraph.Node) graph.Node {
			return &PersistentVolumeClaimNode{Node: node, PersistentVolumeClaim: pvc, IsFound: true}
		},
	).(*PersistentVolumeClaimNode)
}

func FindOrCreateSyntheticPVCNode(g osgraph.MutableUniqueGraph, pvc *corev1.PersistentVolumeClaim) *PersistentVolumeClaimNode {
	return osgraph.EnsureUnique(g,
		PersistentVolumeClaimNodeName(pvc),
		func(node osgraph.Node) graph.Node {
			return &PersistentVolumeClaimNode{Node: node, PersistentVolumeClaim: pvc, IsFound: false}
		},
	).(*PersistentVolumeClaimNode)
}

func EnsureHorizontalPodAutoscalerNode(g osgraph.MutableUniqueGraph, hpa *autoscalingv1.HorizontalPodAutoscaler) *HorizontalPodAutoscalerNode {
	return osgraph.EnsureUnique(g,
		HorizontalPodAutoscalerNodeName(hpa),
		func(node osgraph.Node) graph.Node {
			return &HorizontalPodAutoscalerNode{Node: node, HorizontalPodAutoscaler: hpa}
		},
	).(*HorizontalPodAutoscalerNode)
}

func EnsureStatefulSetNode(g osgraph.MutableUniqueGraph, statefulSet *kappsv1.StatefulSet) *StatefulSetNode {
	nodeName := StatefulSetNodeName(statefulSet)
	node := osgraph.EnsureUnique(g,
		nodeName,
		func(node osgraph.Node) graph.Node {
			return &StatefulSetNode{node, statefulSet, true}
		},
	).(*StatefulSetNode)

	specNode := EnsureStatefulSetSpecNode(g, &statefulSet.Spec, statefulSet.Namespace, nodeName)
	g.AddEdge(node, specNode, osgraph.ContainsEdgeKind)

	return node
}

func EnsureStatefulSetSpecNode(g osgraph.MutableUniqueGraph, spec *kappsv1.StatefulSetSpec, namespace string, ownerName osgraph.UniqueName) *StatefulSetSpecNode {
	specName := StatefulSetSpecNodeName(spec, ownerName)
	specNode := osgraph.EnsureUnique(g,
		specName,
		func(node osgraph.Node) graph.Node {
			return &StatefulSetSpecNode{node, spec, namespace, ownerName}
		},
	).(*StatefulSetSpecNode)

	ptSpecNode := EnsurePodTemplateSpecNode(g, &spec.Template, namespace, specName)
	g.AddEdge(specNode, ptSpecNode, osgraph.ContainsEdgeKind)

	return specNode
}

func EnsureDeploymentNode(g osgraph.MutableUniqueGraph, deployment *kappsv1.Deployment) *DeploymentNode {
	nodeName := DeploymentNodeName(deployment)
	node := osgraph.EnsureUnique(g,
		nodeName,
		func(node osgraph.Node) graph.Node {
			return &DeploymentNode{Node: node, Deployment: deployment, IsFound: true}
		},
	).(*DeploymentNode)

	specNode := EnsureDeploymentSpecNode(g, &deployment.Spec, deployment.Namespace, nodeName)
	g.AddEdge(node, specNode, osgraph.ContainsEdgeKind)

	return node
}

func EnsureDeploymentSpecNode(g osgraph.MutableUniqueGraph, spec *kappsv1.DeploymentSpec, namespace string, ownerName osgraph.UniqueName) *DeploymentSpecNode {
	specName := DeploymentSpecNodeName(spec, ownerName)
	specNode := osgraph.EnsureUnique(g,
		specName,
		func(node osgraph.Node) graph.Node {
			return &DeploymentSpecNode{node, spec, namespace, ownerName}
		},
	).(*DeploymentSpecNode)

	ptSpecNode := EnsurePodTemplateSpecNode(g, &spec.Template, namespace, specName)
	g.AddEdge(specNode, ptSpecNode, osgraph.ContainsEdgeKind)

	return specNode
}

// EnsureDaemonSetNode adds the provided daemon set to the graph if it does not exist
func EnsureDaemonSetNode(g osgraph.MutableUniqueGraph, ds *kappsv1.DaemonSet) *DaemonSetNode {
	dsName := DaemonSetNodeName(ds)
	dsNode := osgraph.EnsureUnique(
		g,
		dsName,
		func(node osgraph.Node) graph.Node {
			return &DaemonSetNode{Node: node, DaemonSet: ds, IsFound: true}
		},
	).(*DaemonSetNode)

	podTemplateSpecNode := EnsurePodTemplateSpecNode(g, &ds.Spec.Template, ds.Namespace, dsName)
	g.AddEdge(dsNode, podTemplateSpecNode, osgraph.ContainsEdgeKind)

	return dsNode
}

func FindOrCreateSyntheticDaemonSetNode(g osgraph.MutableUniqueGraph, ds *kappsv1.DaemonSet) *DaemonSetNode {
	return osgraph.EnsureUnique(
		g,
		DaemonSetNodeName(ds),
		func(node osgraph.Node) graph.Node {
			return &DaemonSetNode{Node: node, DaemonSet: ds, IsFound: false}
		},
	).(*DaemonSetNode)
}

func FindOrCreateSyntheticReplicaSetNode(g osgraph.MutableUniqueGraph, rs *kappsv1.ReplicaSet) *ReplicaSetNode {
	return osgraph.EnsureUnique(
		g,
		ReplicaSetNodeName(rs),
		func(node osgraph.Node) graph.Node {
			return &ReplicaSetNode{Node: node, ReplicaSet: rs, IsFound: false}
		},
	).(*ReplicaSetNode)
}
