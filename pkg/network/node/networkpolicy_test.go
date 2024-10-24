package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubernetes/pkg/util/async"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/util/ovs"
)

func newTestNPP() (*networkPolicyPlugin, ovs.Interface, *atomic.Value, chan struct{}) {
	kubeClient := fake.NewSimpleClientset()
	ovsif := ovs.NewFake("br0")
	ovsif.AddBridge()

	np := NewNetworkPolicyPlugin().(*networkPolicyPlugin)
	np.node = &OsdnNode{
		kClient:       kubeClient,
		kubeInformers: informers.NewSharedInformerFactory(kubeClient, time.Hour),

		oc: &ovsController{
			ovs: ovsif,
		},
	}
	np.vnids = newNodeVNIDMap(np, nil)

	synced := new(atomic.Value)
	stopCh := make(chan struct{})
	np.runner = async.NewBoundedFrequencyRunner("networkpolicy_test", func() {
		np.syncFlows()
		synced.Store(true)
	}, 10*time.Millisecond, time.Hour, 10)
	go np.runner.Loop(stopCh)
	synced.Store(false)

	np.watchNamespaces()
	np.watchPods()
	np.watchNetworkPolicies()

	np.node.kubeInformers.Start(stopCh)

	return np, ovsif, synced, stopCh
}

func waitForEvent(np *networkPolicyPlugin, f func() bool) error {
	return utilwait.Poll(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		np.lock.Lock()
		defer np.lock.Unlock()
		return f(), nil
	})
}

func waitForSync(np *networkPolicyPlugin, synced *atomic.Value, event string) {
	err := waitForEvent(np, func() bool { return synced.Load().(bool) })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for %s: %v", event, err))
	}
}

func forceSync(np *networkPolicyPlugin, synced *atomic.Value) {
	synced.Store(false)
	np.runner.Run()
	waitForSync(np, synced, "forced sync")
}

func addNamespace(np *networkPolicyPlugin, name string, vnid uint32, labels map[string]string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
	_, err := np.node.kClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating namespace %q: %v", name, err))
	}
	err = waitForEvent(np, func() bool { return np.namespacesByName[name] != nil })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for namespace %q: %v", name, err))
	}

	np.vnids.handleAddOrUpdateNetNamespace(&osdnv1.NetNamespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		NetName: name,
		NetID:   vnid,
	}, nil, watch.Added)
	np.EnsureVNIDRules(vnid)
}

func delNamespace(np *networkPolicyPlugin, name string, vnid uint32) {
	// Hack to prevent it from calling syncNamespaceImmediately()
	if npns := np.namespaces[vnid]; npns != nil {
		npns.inUse = false
	}

	np.vnids.handleDeleteNetNamespace(&osdnv1.NetNamespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		NetName: name,
		NetID:   vnid,
	})

	err := np.node.kClient.CoreV1().Namespaces().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error deleting namespace %q: %v", name, err))
	}
	err = waitForEvent(np, func() bool { return np.namespacesByName[name] == nil })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for namespace %q: %v", name, err))
	}
}

func addNetworkPolicy(np *networkPolicyPlugin, policy *networkingv1.NetworkPolicy) {
	policy.ResourceVersion = "0"
	_, err := np.node.kClient.NetworkingV1().NetworkPolicies(policy.Namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(np, func() bool { return np.namespacesByName[policy.Namespace].policies[policy.UID] != nil })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

var resourceVersion = 1

func updateNetworkPolicy(np *networkPolicyPlugin, policy *networkingv1.NetworkPolicy) {
	policy.ResourceVersion = fmt.Sprintf("%d", resourceVersion)
	resourceVersion++
	_, err := np.node.kClient.NetworkingV1().NetworkPolicies(policy.Namespace).Update(context.TODO(), policy, metav1.UpdateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error updating policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(np, func() bool {
		return np.namespacesByName[policy.Namespace].policies[policy.UID].policy.ResourceVersion == policy.ResourceVersion
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

func delNetworkPolicy(np *networkPolicyPlugin, policy *networkingv1.NetworkPolicy) {
	err := np.node.kClient.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error deleting policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(np, func() bool { return np.namespacesByName[policy.Namespace].policies[policy.UID] == nil })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

func uid(npns *npNamespace, name string) ktypes.UID {
	return ktypes.UID(name + "-" + npns.name)
}

// Check some or all policies in npns. This requires that (a) npns has exactly nPolicies
// policies, and (b) every policy named in matches exists in npns and has exactly the indicated
// watches/flows. It does not require that matches lists every policy in npns; any extra
// policies in npns that aren't in matches will just be ignored (other than the fact that
// nPolicies must still be correct).
func assertPolicies(np *networkPolicyPlugin, npns *npNamespace, nPolicies int, matches map[string]*npPolicy) error {
	np.lock.Lock()
	defer np.lock.Unlock()

	var matched []string
	for _, npp := range npns.policies {
		match := matches[npp.policy.Name]
		if match == nil {
			continue
		}
		matched = append(matched, npp.policy.Name)
		if npp.watchesNamespaces != match.watchesNamespaces {
			return fmt.Errorf("policy %q in %q has incorrect watchesNamespaces %t", npp.policy.Name, npns.name, npp.watchesNamespaces)
		}
		if npp.watchesAllPods != match.watchesAllPods {
			return fmt.Errorf("policy %q in %q has incorrect watchesAllPods %t", npp.policy.Name, npns.name, npp.watchesAllPods)
		}
		if npp.watchesOwnPods != match.watchesOwnPods {
			return fmt.Errorf("policy %q in %q has incorrect watchesOwnPods %t", npp.policy.Name, npns.name, npp.watchesOwnPods)
		}

		nppFlows := sets.NewString(npp.ingressFlows...)
		matchFlows := sets.NewString()
		for _, flow := range match.ingressFlows {
			if !strings.HasSuffix(flow, ", ") {
				flow = flow + ", "
			}
			matchFlows.Insert(flow)
		}
		if !nppFlows.Equal(matchFlows) {
			return fmt.Errorf("policy %q in %q has incorrect ingress flows; expected %#v, got %#v", npp.policy.Name, npns.name, match.ingressFlows, npp.ingressFlows)
		}

		nppFlows = sets.NewString(npp.egressFlows...)
		matchFlows = sets.NewString()
		for _, flow := range match.egressFlows {
			if !strings.HasSuffix(flow, ", ") {
				flow = flow + ", "
			}
			matchFlows.Insert(flow)
		}
		if !nppFlows.Equal(matchFlows) {
			return fmt.Errorf("policy %q in %q has incorrect egress flows; expected %#v, got %#v", npp.policy.Name, npns.name, match.egressFlows, npp.egressFlows)
		}
	}

	if len(matches) != len(matched) {
		return fmt.Errorf("expected namespace %q to match %d policies but only found %d %v", npns.name, len(matches), len(matched), matched)
	}
	if len(npns.policies) != nPolicies {
		return fmt.Errorf("expected namespace %q to have %d policies but it has %d", npns.name, nPolicies, len(npns.policies))
	}

	return nil
}

func clientIP(npns *npNamespace) string {
	return fmt.Sprintf("10.%d.0.2", npns.vnid)
}

func serverIP(npns *npNamespace) string {
	return fmt.Sprintf("10.%d.0.3", npns.vnid)
}

func addPods(np *networkPolicyPlugin, npns *npNamespace) {
	client := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: npns.name,
			Name:      "client",
			UID:       uid(npns, "client"),
			Labels: map[string]string{
				"kind": "client",
			},
		},
		Status: corev1.PodStatus{
			PodIP: clientIP(npns),
		},
	}
	server := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: npns.name,
			Name:      "server",
			UID:       uid(npns, "server"),
			Labels: map[string]string{
				"kind": "server",
			},
		},
		Status: corev1.PodStatus{
			PodIP: serverIP(npns),
		},
	}

	_, err := np.node.kClient.CoreV1().Pods(npns.name).Create(context.TODO(), client, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating client pod: %v", err))
	}
	_, err = np.node.kClient.CoreV1().Pods(npns.name).Create(context.TODO(), server, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating server pod: %v", err))
	}
}

func addBadPods(np *networkPolicyPlugin, npns *npNamespace) {
	// HostNetwork pods should not show up in NetworkPolicies
	hostNetwork := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: npns.name,
			Name:      "hostNetwork",
			UID:       uid(npns, "hostNetwork"),
			Labels: map[string]string{
				"kind": "client",
			},
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
		},
		Status: corev1.PodStatus{
			PodIP: "1.2.3.4",
		},
	}
	// Pods that haven't yet received a PodIP should not show up
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: npns.name,
			Name:      "pending",
			UID:       uid(npns, "pending"),
			Labels: map[string]string{
				"kind": "client",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			PodIP: "",
		},
	}

	_, err := np.node.kClient.CoreV1().Pods(npns.name).Create(context.TODO(), hostNetwork, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating hostNetwork pod: %v", err))
	}
	_, err = np.node.kClient.CoreV1().Pods(npns.name).Create(context.TODO(), pending, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating pending pod: %v", err))
	}
}

func TestNetworkPolicy(t *testing.T) {
	np, _, synced, stopCh := newTestNPP()
	defer close(stopCh)

	// Create some Namespaces
	addNamespace(np, "default", 0, map[string]string{"default": "true"})
	addNamespace(np, "one", 1, map[string]string{"parity": "odd"})
	addNamespace(np, "two", 2, map[string]string{"parity": "even", "prime": "true"})
	addNamespace(np, "three", 3, map[string]string{"parity": "odd", "prime": "true"})
	addNamespace(np, "four", 4, map[string]string{"parity": "even"})
	addNamespace(np, "five", 5, map[string]string{"parity": "odd", "prime": "true"})

	// Add allow-from-self and allow-from-default policies to all
	for _, npns := range np.namespaces {
		synced.Store(false)
		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-self",
				UID:       uid(npns, "allow-from-self"),
				Namespace: npns.name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{},
					}},
				}},
			},
		})

		synced.Store(false)
		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-default",
				UID:       uid(npns, "allow-from-default"),
				Namespace: npns.name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"default": "true",
							},
						},
					}},
				}},
			},
		})
	}
	waitForSync(np, synced, "initialization")

	// Each namespace should now have 2 policies, each with a single flow
	for _, npns := range np.namespaces {
		err := assertPolicies(np, npns, 2, map[string]*npPolicy{
			"allow-from-self": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    false,
				ingressFlows: []string{
					fmt.Sprintf("reg0=%d", npns.vnid),
				},
			},
			"allow-from-default": {
				watchesNamespaces: true,
				watchesAllPods:    false,
				watchesOwnPods:    false,
				ingressFlows: []string{
					"reg0=0",
				},
			},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}

	// Add two pods to each namespace (except default)
	for _, npns := range np.namespaces {
		if npns.name == "default" {
			continue
		}

		addPods(np, npns)

		// There are no pod-selecting policies yet, so nothing should have changed
		err := assertPolicies(np, npns, 2, nil)
		if err != nil {
			t.Error(err.Error())
		}

		synced.Store(false)
		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-client-to-server",
				UID:       uid(npns, "allow-client-to-server"),
				Namespace: npns.name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kind": "server",
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kind": "client",
							},
						},
					}},
				}},
			},
		})
		waitForSync(np, synced, "networkpolicy sync")

		err = assertPolicies(np, npns, 3, map[string]*npPolicy{
			"allow-client-to-server": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    true,
				ingressFlows: []string{
					fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
				},
			},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}

	npns1 := np.namespaces[1]
	npns2 := np.namespaces[2]

	// Allow all pods in even-numbered namespaces to connect to any pod in namespace "one"
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-even",
			UID:       uid(npns1, "allow-from-even"),
			Namespace: "one",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "even",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "networkpolicy sync")

	err := assertPolicies(np, npns1, 4, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				"reg0=2",
				"reg0=4",
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow client pods in odd prime namespaces to connect to the server in namespace "one"
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-odd-primes",
			UID:       uid(npns1, "allow-from-odd-primes"),
			Namespace: "one",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "odd",
							"prime":  "true",
						},
					},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "networkpolicy sync")

	err = assertPolicies(np, npns1, 5, map[string]*npPolicy{
		"allow-from-odd-primes": {
			watchesNamespaces: true,
			watchesAllPods:    true,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns1), clientIP(np.namespaces[3])),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns1), clientIP(np.namespaces[5])),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow client pods in all namespaces to connect to the server in namespace "two"
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-all-clients",
			UID:       uid(npns1, "allow-from-all-clients"),
			Namespace: "two",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "networkpolicy sync")

	err = assertPolicies(np, npns2, 4, map[string]*npPolicy{
		"allow-from-all-clients": {
			watchesNamespaces: true,
			watchesAllPods:    true,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns2), clientIP(np.namespaces[1])),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns2), clientIP(np.namespaces[2])),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns2), clientIP(np.namespaces[3])),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns2), clientIP(np.namespaces[4])),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns2), clientIP(np.namespaces[5])),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// add some more namespaces
	addNamespace(np, "six", 6, map[string]string{"parity": "even"})
	addPods(np, np.namespaces[6])
	addNamespace(np, "seven", 7, map[string]string{"parity": "odd", "prime": "true"})
	addPods(np, np.namespaces[7])
	addNamespace(np, "eight", 8, map[string]string{"parity": "even"})
	addPods(np, np.namespaces[8])
	addNamespace(np, "nine", 9, map[string]string{"parity": "odd"})
	addPods(np, np.namespaces[9])

	// add some non-pod-network pods; this should not affect the generated flows.
	// (It should also not cause a sync but this is difficult to test since one of
	// the previous calls may have resulted in two calls to np.syncNamespace()
	// with the async runner triggering in between them, so there may still be
	// another sync waiting to occur at this point.)
	addBadPods(np, np.namespaces[4])
	addBadPods(np, np.namespaces[7])
	addBadPods(np, np.namespaces[9])

	// Now reassert the full set of matches for each namespace
	forceSync(np, synced)
	for vnid, npns := range np.namespaces {
		switch vnid {
		case 0:
			err := assertPolicies(np, npns, 2, map[string]*npPolicy{
				"allow-from-self": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						fmt.Sprintf("reg0=%d", vnid),
					},
				},
				"allow-from-default": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						"reg0=0",
					},
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 1:
			err := assertPolicies(np, npns, 5, map[string]*npPolicy{
				"allow-from-self": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						"reg0=1",
					},
				},
				"allow-from-default": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						"reg0=0",
					},
				},
				"allow-client-to-server": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    true,
					ingressFlows: []string{
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
					},
				},
				"allow-from-even": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						"reg0=2",
						"reg0=4",
						"reg0=6",
						"reg0=8",
					},
				},
				"allow-from-odd-primes": {
					watchesNamespaces: true,
					watchesAllPods:    true,
					watchesOwnPods:    true,
					ingressFlows: []string{
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[3])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[5])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[7])),
						// but NOT from namespace 9
					},
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 2:
			err := assertPolicies(np, npns, 4, map[string]*npPolicy{
				"allow-from-self": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						fmt.Sprintf("reg0=%d", vnid),
					},
				},
				"allow-from-default": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						"reg0=0",
					},
				},
				"allow-client-to-server": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    true,
					ingressFlows: []string{
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
					},
				},
				"allow-from-all-clients": {
					watchesNamespaces: true,
					watchesAllPods:    true,
					watchesOwnPods:    true,
					ingressFlows: []string{
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[1])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[2])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[3])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[4])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[5])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[6])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[7])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[8])),
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[9])),
					},
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 3, 4, 5:
			err := assertPolicies(np, npns, 3, map[string]*npPolicy{
				"allow-from-self": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						fmt.Sprintf("reg0=%d", vnid),
					},
				},
				"allow-from-default": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					ingressFlows: []string{
						"reg0=0",
					},
				},
				"allow-client-to-server": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    true,
					ingressFlows: []string{
						fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
					},
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 6, 7, 8, 9:
			err := assertPolicies(np, npns, 0, nil)
			if err != nil {
				t.Error(err.Error())
			}

		default:
			t.Errorf("Unexpected namespace %d / %s", vnid, npns.name)
		}
	}

	// If we delete a namespace, then stale policies may be left behind...
	forceSync(np, synced)
	delNamespace(np, "two", 2)
	err = assertPolicies(np, npns1, 5, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				"reg0=2",
				"reg0=4",
				"reg0=6",
				"reg0=8",
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// ...but they'll be cleaned up as soon as we add any new namespace
	synced.Store(false)
	addNamespace(np, "unrelated", 100, nil)
	waitForSync(np, synced, "namespace addition")
	err = assertPolicies(np, npns1, 5, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				"reg0=4",
				"reg0=6",
				"reg0=8",
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Deleting a policy in one namespace will not affect other namespaces
	npns4 := np.namespaces[4]
	synced.Store(false)
	delNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-default",
			UID:       uid(npns4, "allow-from-default"),
			Namespace: npns4.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"default": "true",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "namespace deletion")

	err = assertPolicies(np, npns4, 2, map[string]*npPolicy{
		"allow-from-self": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				fmt.Sprintf("reg0=%d", npns4.vnid),
			},
		},
		"allow-client-to-server": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns4), clientIP(npns4)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	err = assertPolicies(np, npns1, 5, map[string]*npPolicy{
		"allow-from-default": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				"reg0=0",
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Create the special namespace that indicates host network traffic
	addNamespace(np, "openshift-host-network", 200, map[string]string{"network.openshift.io/policy-group": "ingress"})
	// Create the namespace to add network policy for
	addNamespace(np, "host-network-target", 10, map[string]string{"foo": "bar"})
	npns := np.namespaces[10]
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-host-network-ns",
			UID:       uid(npns, "allow-from-host-network-ns"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"network.openshift.io/policy-group": "ingress",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "host-network NP addition")

	// make sure we add the right flows
	err = assertPolicies(np, npns, 1, map[string]*npPolicy{
		"allow-from-host-network-ns": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				"reg0=0", //make sure host network namespace is classified into vnid 0
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNetworkPolicyInMigrationMode(t *testing.T) {
	var err error
	np, _, synced, stopCh := newTestNPP()
	np.inMigrationMode = true
	_, clusterCIDR, _ := net.ParseCIDR("10.128.0.0/14")
	np.node.networkInfo = &common.ParsedClusterNetwork{
		ClusterNetworks: []common.ParsedClusterNetworkEntry{
			{
				ClusterCIDR:      clusterCIDR,
				HostSubnetLength: 9,
			},
		},
	}
	defer close(stopCh)

	// Create some Namespaces
	addNamespace(np, "default", 0, map[string]string{"default": "true"})
	addNamespace(np, "one", 1, map[string]string{"parity": "odd"})
	addNamespace(np, "two", 2, map[string]string{"parity": "even"})

	npns1 := np.namespaces[1]
	npns2 := np.namespaces[2]

	addPods(np, npns1)
	addPods(np, npns2)

	// Allow client pods in the same namespace to connect to the server in namespace "one"
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-samenamespace",
			UID:       uid(npns1, "allow-from-samenamespace"),
			Namespace: "one",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "networkpolicy sync")

	err = assertPolicies(np, npns1, 1, map[string]*npPolicy{
		"allow-from-samenamespace": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("reg0=%d", npns1.vnid),
				fmt.Sprintf("ip, nw_src=%s", clientIP(npns1)),
				fmt.Sprintf("ip, nw_src=%s", serverIP(npns1)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow client pods in even namespaces to connect to the server in namespace "one"
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-even",
			UID:       uid(npns1, "allow-from-even"),
			Namespace: "one",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "even",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "networkpolicy sync")

	err = assertPolicies(np, npns1, 2, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    true,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_dst=%s, reg0=%d", serverIP(npns1), npns2.vnid),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns1), clientIP(npns2)),
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns1), serverIP(npns2)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Create the special namespace that indicates host network traffic
	addNamespace(np, "openshift-host-network", 200, map[string]string{"network.openshift.io/policy-group": "ingress"})
	// Create the namespace to add network policy for
	addNamespace(np, "host-network-target", 10, map[string]string{"foo": "bar"})
	npns := np.namespaces[10]
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-host-network-ns",
			UID:       uid(npns, "allow-from-host-network-ns"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"network.openshift.io/policy-group": "ingress",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "host-network NP addition")

	// make sure we add the right flows
	err = assertPolicies(np, npns, 1, map[string]*npPolicy{
		"allow-from-host-network-ns": {
			watchesNamespaces: true,
			watchesAllPods:    true,
			watchesOwnPods:    false,
			ingressFlows: []string{
				"reg0=0", //make sure host network namespace is classified into vnid 0
				// allow the traffic from the second IP of the node subnet which is the onv-k mp0 interface IP
				"ip, nw_src=10.128.0.2/255.252.1.255",
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNetworkPolicy_ipBlock(t *testing.T) {
	np, _, synced, stopCh := newTestNPP()
	defer close(stopCh)

	// Create a default Namespace
	addNamespace(np, "default", 0, map[string]string{"default": "true"})
	npns := np.namespaces[0]
	addPods(np, npns)

	// Add a simple ipBlock policy
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-cidr",
			UID:       uid(npns, "allow-from-cidr"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{
						CIDR: "192.168.0.0/16",
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "simple ipBlock policy")

	err := assertPolicies(np, npns, 1, map[string]*npPolicy{
		"allow-from-cidr": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_src=192.168.0.0/16"),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add a mixed ipBlock/podSelector policy
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-cidr-and-pods",
			UID:       uid(npns, "allow-from-cidr-and-pods"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kind": "client",
							},
						},
					},
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "192.168.0.0/16",
						},
					},
				},
			}},
		},
	})
	waitForSync(np, synced, "mixed ipBlock/podSelector policy")

	err = assertPolicies(np, npns, 2, map[string]*npPolicy{
		"allow-from-cidr-and-pods": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_src=%s", clientIP(npns)),
				fmt.Sprintf("ip, nw_src=192.168.0.0/16"),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add a policy with multiple ipBlocks, including an "except" clause.
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-multiple-cidrs",
			UID:       uid(npns, "allow-from-multiple-cidrs"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.0.0/24",
							},
						},
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.1.0/24",
								Except: []string{
									"192.168.1.1/32",
								},
							},
						},
					},
				},
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.10.0/24",
							},
						},
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.20.0/24",
							},
						},
					},
				},
			},
		},
	})
	waitForSync(np, synced, "multiple ipBlock policy")

	err = assertPolicies(np, npns, 3, map[string]*npPolicy{
		"allow-from-multiple-cidrs": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_src=192.168.0.0/24"),

				// rule with except gets exploded to multiple flows
				fmt.Sprintf("ip, nw_src=192.168.1.128/25"),
				fmt.Sprintf("ip, nw_src=192.168.1.64/26"),
				fmt.Sprintf("ip, nw_src=192.168.1.32/27"),
				fmt.Sprintf("ip, nw_src=192.168.1.16/28"),
				fmt.Sprintf("ip, nw_src=192.168.1.8/29"),
				fmt.Sprintf("ip, nw_src=192.168.1.4/30"),
				fmt.Sprintf("ip, nw_src=192.168.1.2/31"),
				fmt.Sprintf("ip, nw_src=192.168.1.0/32"),

				fmt.Sprintf("ip, nw_src=192.168.10.0/24"),
				fmt.Sprintf("ip, nw_src=192.168.20.0/24"),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNetworkPolicy_egress(t *testing.T) {
	np, ovsif, synced, stopCh := newTestNPP()
	defer close(stopCh)

	// We'll be checking the output OVS flows in this test, so get the initial state...
	prevFlows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}

	// Create Namespaces
	synced.Store(false)
	addNamespace(np, "default", 0, map[string]string{"default": "true"})
	npns := np.namespaces[0]
	addPods(np, npns)
	addNamespace(np, "one", 1, map[string]string{"parity": "odd"})
	npns1 := np.namespaces[1]
	addPods(np, npns1)
	addNamespace(np, "two", 2, map[string]string{})
	npns2 := np.namespaces[2]
	addPods(np, npns2)
	addNamespace(np, "three", 3, map[string]string{})
	npns3 := np.namespaces[3]
	addPods(np, npns3)
	addNamespace(np, "four", 4, map[string]string{})
	npns4 := np.namespaces[4]
	addPods(np, npns4)
	waitForSync(np, synced, "initial namespaces")

	// All namespaces should get "default allow" rules to override the
	// "priority=0, actions=drop" rules at the end of tables 27 and 80
	flows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=0", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=0", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=1", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=1", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=2", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=2", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=3", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=3", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=4", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=4", "actions=output:NXM_NX_REG2[]"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
	prevFlows = flows

	// Add ingress/egress default-deny
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny",
			UID:       uid(npns, "default-deny"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  []networkingv1.NetworkPolicyEgressRule{},
		},
	})
	waitForSync(np, synced, "default-deny")

	err = assertPolicies(np, npns, 1, map[string]*npPolicy{
		"default-deny": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows:      []string{},
			egressFlows:       []string{},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// NS 0 now has default-deny, so its allow rules will be deleted
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=27", "reg0=0", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=80", "reg1=0", "actions=output:NXM_NX_REG2[]"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
	prevFlows = flows

	// Add a just-egress policy
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress",
			UID:       uid(npns, "egress"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "client",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "server",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "egress-only policy")

	err = assertPolicies(np, npns, 2, map[string]*npPolicy{
		"egress": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows:      []string{},
			egressFlows: []string{
				fmt.Sprintf("ip, nw_src=%s, ip, nw_dst=%s", clientIP(npns), serverIP(npns)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=0", "nw_src=10.0.0.2", "nw_dst=10.0.0.3", "actions=goto_table:30"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
	prevFlows = flows

	// Add a mixed-ingress-egress policy
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-egress",
			UID:       uid(npns, "ingress-egress"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "odd",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "mixed-ingress-egress policy")

	err = assertPolicies(np, npns, 3, map[string]*npPolicy{
		"ingress-egress": {
			watchesNamespaces: true,
			watchesAllPods:    true,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_src=%s", clientIP(npns)),
			},
			egressFlows: []string{
				// egress namespaceSelector rule does per-IP, not reg match
				fmt.Sprintf("ip, nw_dst=%s", clientIP(npns1)),
				fmt.Sprintf("ip, nw_dst=%s", serverIP(npns1)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=0", "nw_src=10.0.0.2", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=0", "nw_dst=10.1.0.2", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=0", "nw_dst=10.1.0.3", "actions=goto_table:30"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
	prevFlows = flows

	// Add NetworkPolicies to "two". In particular:
	//   - all pods are isolated for Ingress
	//   - Ingress is allowed to "server" only by the second policy
	//   - Egress is denied to some non-existent pod by the third policy.
	// The egress policy should have no effect.
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-ingress",
			UID:       uid(npns2, "default-deny-ingress"),
			Namespace: npns2.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
		},
	})
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-client-to-server",
			UID:       uid(npns2, "allow-client-to-server"),
			Namespace: npns2.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "irrelevant-egress",
			UID:       uid(npns2, "irrelevant-egress"),
			Namespace: npns2.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "nonexistent",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{},
		},
	})
	waitForSync(np, synced, "ns2 policies")

	err = assertPolicies(np, npns2, 3, map[string]*npPolicy{
		"default-deny-ingress": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			ingressFlows:      []string{},
			egressFlows:       []string{},
		},
		"allow-client-to-server": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns2), clientIP(npns2)),
			},
		},
		"irrelevant-egress": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows:      []string{},
			egressFlows:       []string{},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// No egress flows should change, because the egress policy is irrelevant.
	// The ingress default-allow should go away and be replaced with a narrow allow.
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:    flowRemoved,
			match:   []string{"table=80", "reg1=2", "actions=output:NXM_NX_REG2[]"},
			noMatch: []string{"reg0=2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=2", "ip", "nw_dst=10.2.0.3", "nw_src=10.2.0.2", "actions=output:NXM_NX_REG2[]"},
		},
		// (This gets reordered so we have to claim it got deleted and re-added)
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=27", "reg0=2", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=2", "actions=goto_table:30"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
	prevFlows = flows

	// Add NetworkPolicies to "three":
	//   - Ingress is allowed to "server" only by one policy
	//   - Egress is allowed to "server" only by a different policy
	// Make sure that this allows both ingress and egress...
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-ingress",
			UID:       uid(npns3, "server-ingress"),
			Namespace: npns3.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-egress",
			UID:       uid(npns3, "server-egress"),
			Namespace: npns3.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "ns3 policies")

	err = assertPolicies(np, npns3, 2, map[string]*npPolicy{
		"server-ingress": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows: []string{
				fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns3), clientIP(npns3)),
			},
		},
		"server-egress": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			ingressFlows:      []string{},
			egressFlows: []string{
				fmt.Sprintf("ip, nw_src=%s, ip, nw_dst=%s", serverIP(npns3), clientIP(npns3)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=3", "ip", "nw_src=10.3.0.3", "nw_dst=10.3.0.2", "actions=goto_table:30"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=27", "reg0=3", "ip", "nw_src=10.3.0.3", "actions=drop"},
			noMatch: []string{"nw_dst=10.3.0.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=3", "ip", "nw_dst=10.3.0.3", "nw_src=10.3.0.2", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=80", "reg1=3", "ip", "nw_dst=10.3.0.3", "actions=drop"},
			noMatch: []string{"nw_src=10.3.0.2"},
		},
		// (This gets reordered so we have to claim it got deleted and re-added)
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=27", "reg0=3", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=3", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=80", "reg1=3", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=3", "actions=output:NXM_NX_REG2[]"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	prevFlows = flows
	// Add NetworkPolicies to "four":
	//   - Egress is allowed to all pods in the namespace
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-egress",
			UID:       uid(npns4, "allow-egress"),
			Namespace: npns4.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{},
				}},
			}},
		},
	})
	waitForSync(np, synced, "ns4 policies")

	err = assertPolicies(np, npns4, 1, map[string]*npPolicy{
		"allow-egress": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			egressFlows: []string{"ip, nw_src=10.4.0.3, ip, nw_dst=10.4.0.2, ",
				"ip, nw_src=10.4.0.3, ip, nw_dst=10.4.0.3, "},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(prevFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=4", "ip", "nw_src=10.4.0.3", "ip", "nw_dst=10.4.0.2", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=4", "ip", "nw_dst=10.4.0.3", "ip", "nw_src=10.4.0.3", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=4", "ip", "nw_src=10.4.0.3", "actions=drop"},
		},
		// (This gets reordered so we have to claim it got deleted and re-added)
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=27", "reg0=4", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=80", "reg1=4", "actions=output:NXM_NX_REG2[]"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=27", "reg0=4", "actions=goto_table:30"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=4", "actions=output:NXM_NX_REG2[]"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

}

// Disabled (by initial "_") becaues it's really really slow in CI for some reason?
func _TestNetworkPolicyCache(t *testing.T) {
	const (
		initialNamespaces uint32 = 1000
		extraNamespaces   uint32 = 500
	)

	np, _, _, stopCh := newTestNPP()
	defer close(stopCh)

	start := time.Now()

	// Create initialNamespaces namespaces, each with deny-all, allow-from-self, and
	// allow-from-global-namespace policies
	for vnid := uint32(0); vnid < initialNamespaces; vnid++ {
		name := fmt.Sprintf("namespace-%d", vnid)
		addNamespace(np, name, vnid, map[string]string{
			"pod.network.openshift.io/legacy-netid": fmt.Sprintf("%d", vnid),
			"name":                                  name,
		})
		npns := np.namespaces[vnid]

		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-all",
				UID:       uid(npns, "deny-all"),
				Namespace: name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{},
			},
		})

		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-self",
				UID:       uid(npns, "allow-from-self"),
				Namespace: name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{},
					}},
				}},
			},
		})

		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-global-namespaces",
				UID:       uid(npns, "allow-from-global-namespaces"),
				Namespace: name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod.network.openshift.io/legacy-netid": "0",
							},
						},
					}},
				}},
			},
		})
	}

	// Create an additional NetworkPolicy in namespace-1 for each namespace
	// that comes after it, allowing access from only that one Namespace. (Ugh!)
	npns1 := np.namespaces[1]
	for vnid := uint32(2); vnid < initialNamespaces; vnid++ {
		name := fmt.Sprintf("namespace-%d", vnid)
		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-" + name,
				UID:       uid(npns1, name),
				Namespace: npns1.name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": name,
							},
						},
					}},
				}},
			},
		})
	}

	// Re-add all the namespaces; this simulates what happens on sdn startup.
	for vnid := uint32(0); vnid < initialNamespaces; vnid++ {
		name := fmt.Sprintf("namespace-%d", vnid)
		addNamespace(np, name, vnid, map[string]string{
			"pod.network.openshift.io/legacy-netid": fmt.Sprintf("%d", vnid),
			"name":                                  name,
		})
	}

	// Add more namespaces...
	for vnid := initialNamespaces; vnid < initialNamespaces+extraNamespaces; vnid++ {
		name := fmt.Sprintf("namespace-%d", vnid)
		addNamespace(np, name, vnid, map[string]string{
			"pod.network.openshift.io/legacy-netid": fmt.Sprintf("%d", vnid),
			"name":                                  name,
		})
	}

	// On my laptop this runs in 4s with the cache and 1m45s without
	elapsed := time.Since(start)
	if elapsed > time.Minute {
		t.Fatalf("Test took unexpectedly long (%v); cache is broken", elapsed)
	}

	// Deleting any namespace-selecting policy from any namespace will cause the cache
	// to shrink
	cacheSize := len(np.nsMatchCache)
	npns2 := np.namespaces[2]
	delNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-global-namespaces",
			UID:       uid(npns2, "allow-from-global-namespaces"),
			Namespace: npns2.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod.network.openshift.io/legacy-netid": "0",
						},
					},
				}},
			}},
		},
	})
	if len(np.nsMatchCache) != cacheSize-1 {
		t.Fatalf("Expected cache size to shrink from %d to %d, got %d", cacheSize, cacheSize-1, len(np.nsMatchCache))
	}
}

func _TestNetworkPolicy_MultiplePoliciesOneNamespace(t *testing.T) {
	np, _, synced, stopCh := newTestNPP()
	defer close(stopCh)

	// Create some Namespaces
	addNamespace(np, "default", 0, map[string]string{"default": "true"})

	// Add two pods to each namespace
	for _, npns := range np.namespaces {
		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-client-to-server-1",
				UID:       uid(npns, "allow-client-to-server-1"),
				Namespace: npns.name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kind": "server",
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kind": "client",
							},
						},
					}},
				}},
			},
		})
		addNetworkPolicy(np, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-client-to-server-2",
				UID:       uid(npns, "allow-client-to-server-2"),
				Namespace: npns.name,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kind": "server",
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kind": "client",
							},
						},
					}},
				}},
			},
		})
	}
	for _, npns := range np.namespaces {
		synced.Store(false)
		addPods(np, npns)
		waitForSync(np, synced, "pod addition")
		// both policies should be updated
		err := assertPolicies(np, npns, 2, map[string]*npPolicy{
			"allow-client-to-server-1": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    true,
				ingressFlows: []string{
					fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
				},
			},
			"allow-client-to-server-2": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    true,
				ingressFlows: []string{
					fmt.Sprintf("ip, nw_dst=%s, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
				},
			},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}
}

func TestNetworkPolicyPathological(t *testing.T) {
	np, ovsif, synced, stopCh := newTestNPP()
	defer close(stopCh)

	fakeRecorder := record.NewFakeRecorder(5)
	np.node.recorder = fakeRecorder

	origFlows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}

	// create a namespace
	synced.Store(false)
	addNamespace(np, "default", 0, nil)
	npns := np.namespaces[0]
	waitForSync(np, synced, "initialization")

	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-all",
			UID:       uid(npns, "deny-all"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
		},
	})
	waitForSync(np, synced, "default-deny")

	// Creating the namespace will have added "allow" flows, but the default-deny
	// policy will remove them, so there should be no change from the initial state
	flows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// add 200 pods
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("pod-%d", i)
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: npns.name,
				Name:      name,
				UID:       uid(npns, name),
				Labels: map[string]string{
					"friendly": "true",
				},
			},
			Status: corev1.PodStatus{
				PodIP: fmt.Sprintf("10.0.0.%d", i),
			},
		}
		if i%2 == 0 {
			pod.Labels["even"] = "true"
		}
		if i%10 == 0 {
			pod.Labels["ten"] = "true"
		}

		_, err := np.node.kClient.CoreV1().Pods(npns.name).Create(context.TODO(), pod, metav1.CreateOptions{})
		if err != nil {
			panic(fmt.Sprintf("Unexpected error creating pod: %v", err))
		}
	}
	forceSync(np, synced)

	// Still no changes, because they're all stuck behind the default-deny
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Now create a pathological NetworkPolicy
	synced.Store(false)
	addNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-friendly",
			UID:       uid(npns, "allow-friendly"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"friendly": "true",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"friendly": "true",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "pathological NP")

	// There should *still* be no changes, because the pathological policy should have
	// been ignored
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v\nOrig: %#v\nNew: %#v", err, origFlows, flows)
	}

	// Check that a single event was emitted
	var event string
	select {
	case event = <-fakeRecorder.Events:
		break
	default:
		break
	}
	if event == "" {
		t.Fatalf("no Event emitted after adding pathological NetworkPolicy")
	}
	if !strings.HasPrefix(event, "Warning NetworkPolicySize") || !strings.Contains(event, "ignored") {
		t.Fatalf("incorrect Event emitted after adding pathological NetworkPolicy: %s", event)
	}

	event = ""
	select {
	case event = <-fakeRecorder.Events:
		break
	default:
		break
	}
	if event != "" {
		t.Fatalf("too many Events emitted after adding pathological NetworkPolicy: %s", event)
	}

	// Changing pods (in a way that does not cause the policy to stop being
	// pathological) should not result in the policy being accepted, or another event
	// being emitted.
	synced.Store(false)
	err = np.node.kClient.CoreV1().Pods(npns.name).Delete(context.TODO(), "pod-1", metav1.DeleteOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error deleting pod: %v", err))
	}
	waitForSync(np, synced, "delete pod")

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v\nOrig: %#v\nNew: %#v", err, origFlows, flows)
	}

	event = ""
	select {
	case event = <-fakeRecorder.Events:
		break
	default:
		break
	}
	if event != "" {
		t.Fatalf("unexpected Event emitted after deleting pod: %s", event)
	}

	// Changing the policy in a way that doesn't make it stop being pathological
	// should not result in the policy being accepted, but will result in another
	// event being emitted.
	synced.Store(false)
	updateNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-friendly",
			UID:       uid(npns, "allow-friendly"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"friendly": "true",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"friendly": "true",
							"even":     "true",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "updated pathological NP")

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v\nOrig: %#v\nNew: %#v", err, origFlows, flows)
	}

	event = ""
	select {
	case event = <-fakeRecorder.Events:
		break
	default:
		break
	}
	if event == "" {
		t.Fatalf("no Event emitted after modifying pathological NetworkPolicy")
	}
	if !strings.HasPrefix(event, "Warning NetworkPolicySize") || !strings.Contains(event, "ignored") {
		t.Fatalf("incorrect Event emitted after modifying pathological NetworkPolicy: %s", event)
	}

	// Changing the NP to be bad-but-not-quite-pathological should result in another
	// event, but it will be accepted now
	synced.Store(false)
	updateNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-friendly",
			UID:       uid(npns, "allow-friendly"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"friendly": "true",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"friendly": "true",
							"ten":      "true",
						},
					},
				}},
			}},
		},
	})
	waitForSync(np, synced, "updated pathological NP to less pathological")

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	// The target podSelector "friendly=true" matches all 199 remaining pods. The
	// source podSelector "ten=true" matches 20 pods.
	if len(flows) != 199*20 {
		t.Fatalf("Expected %d flows, got %d", 199*20, len(flows))
	}

	event = ""
	select {
	case event = <-fakeRecorder.Events:
		break
	default:
		break
	}
	if event == "" {
		t.Fatalf("no Event emitted after simplifying pathological NetworkPolicy")
	}
	if !strings.HasPrefix(event, "Warning NetworkPolicySize") || strings.Contains(event, "ignored") {
		t.Fatalf("incorrect Event emitted after simplifying pathological NetworkPolicy: %s", event)
	}

	// Changing the NP to something non-pathological should emit a non-warning event
	// and result in flow changes
	synced.Store(false)
	updateNetworkPolicy(np, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-friendly",
			UID:       uid(npns, "allow-friendly"),
			Namespace: npns.name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{},
				}},
			}},
		},
	})
	waitForSync(np, synced, "updated non-pathological NP")

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=80", "reg1=0", "actions=output:NXM_NX_REG2[]"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v\nOrig: %#v\nNew: %#v", err, origFlows, flows)
	}

	event = ""
	select {
	case event = <-fakeRecorder.Events:
		break
	default:
		break
	}
	if event == "" {
		t.Fatalf("no Event emitted after adding non-pathological NetworkPolicy")
	}
	if !strings.HasPrefix(event, "Normal NetworkPolicySize") {
		t.Fatalf("incorrect Event emitted after adding pathological NetworkPolicy: %s", event)
	}
}
