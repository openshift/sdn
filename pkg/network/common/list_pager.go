package common

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"

	osdnv1 "github.com/openshift/api/network/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
)

func ListAllEgressNetworkPolicies(ctx context.Context, client osdnclient.Interface) ([]*osdnv1.EgressNetworkPolicy, error) {
	list := []*osdnv1.EgressNetworkPolicy{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.NetworkV1().EgressNetworkPolicies(metav1.NamespaceAll).List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*osdnv1.EgressNetworkPolicy))
		return nil
	})
	return list, err
}

func ListAllNamespaces(ctx context.Context, client kubernetes.Interface) ([]*corev1.Namespace, error) {
	list := []*corev1.Namespace{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.CoreV1().Namespaces().List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*corev1.Namespace))
		return nil
	})
	return list, err
}

func ListAllNetworkPolicies(ctx context.Context, client kubernetes.Interface) ([]*networkingv1.NetworkPolicy, error) {
	list := []*networkingv1.NetworkPolicy{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*networkingv1.NetworkPolicy))
		return nil
	})
	return list, err
}

func ListAllPods(ctx context.Context, client kubernetes.Interface) ([]*corev1.Pod, error) {
	list := []*corev1.Pod{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*corev1.Pod))
		return nil
	})
	return list, err
}

func ListAllServices(ctx context.Context, client kubernetes.Interface) ([]*corev1.Service, error) {
	list := []*corev1.Service{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*corev1.Service))
		return nil
	})
	return list, err
}

func ListServicesInNamespace(ctx context.Context, client kubernetes.Interface, namespace string) ([]*corev1.Service, error) {
	list := []*corev1.Service{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.CoreV1().Services(namespace).List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*corev1.Service))
		return nil
	})
	return list, err
}

func ListAllHostSubnets(ctx context.Context, client osdnclient.Interface) ([]*osdnv1.HostSubnet, error) {
	list := []*osdnv1.HostSubnet{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.NetworkV1().HostSubnets().List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*osdnv1.HostSubnet))
		return nil
	})
	return list, err
}

func ListAllNetNamespaces(ctx context.Context, client osdnclient.Interface) ([]*osdnv1.NetNamespace, error) {
	list := []*osdnv1.NetNamespace{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.NetworkV1().NetNamespaces().List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		list = append(list, obj.(*osdnv1.NetNamespace))
		return nil
	})
	return list, err
}

func ListPodsInNodeAndNamespace(ctx context.Context, client kubernetes.Interface, node, namespace string) ([]*corev1.Pod, error) {
	fieldSelector := fields.Set{"spec.nodeName": node}.AsSelector()
	opts := metav1.ListOptions{
		LabelSelector: labels.Everything().String(),
		FieldSelector: fieldSelector.String(),
	}
	list := []*corev1.Pod{}
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return client.CoreV1().Pods(namespace).List(ctx, opts)
	}).EachListItem(ctx, opts, func(obj runtime.Object) error {
		list = append(list, obj.(*corev1.Pod))
		return nil
	})
	return list, err
}
