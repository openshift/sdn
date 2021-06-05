package node

import (
	"context"
	"fmt"
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
	"k8s.io/kubernetes/pkg/util/async"

	networkv1 "github.com/openshift/api/network/v1"
)

var synced atomic.Value

func newTestNPP() *networkPolicyPlugin {
	kubeClient := fake.NewSimpleClientset()
	np := &networkPolicyPlugin{
		node: &OsdnNode{
			kClient:       kubeClient,
			kubeInformers: informers.NewSharedInformerFactory(kubeClient, time.Hour),
		},

		namespaces:       make(map[uint32]*npNamespace),
		namespacesByName: make(map[string]*npNamespace),
		nsMatchCache:     make(map[string]*npCacheEntry),
	}
	np.vnids = newNodeVNIDMap(np, nil)

	np.runner = async.NewBoundedFrequencyRunner("networkpolicy_test", func() {
		np.lock.Lock()
		defer np.lock.Unlock()

		np.recalculate()
		for _, npns := range np.namespaces {
			npns.mustSync = false
		}

		synced.Store(true)
	}, 10*time.Millisecond, time.Hour, 10)
	go np.runner.Loop(utilwait.NeverStop)
	synced.Store(false)

	np.watchNamespaces()
	np.watchPods()
	np.watchNetworkPolicies()

	stopCh := make(chan struct{})
	np.node.kubeInformers.Start(stopCh)

	return np
}

func waitForEvent(np *networkPolicyPlugin, f func() bool) error {
	return utilwait.Poll(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		np.lock.Lock()
		defer np.lock.Unlock()
		return f(), nil
	})
}

func addNamespace(np *networkPolicyPlugin, name string, vnid uint32, labels map[string]string) {
	synced.Store(false)

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

	np.vnids.handleAddOrUpdateNetNamespace(&networkv1.NetNamespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		NetName: name,
		NetID:   vnid,
	}, nil, watch.Added)
	np.EnsureVNIDRules(vnid)
}

func delNamespace(np *networkPolicyPlugin, name string, vnid uint32) {
	synced.Store(false)

	// Hack to prevent it from calling syncNamespaceImmediately()
	if npns := np.namespaces[vnid]; npns != nil {
		npns.inUse = false
	}

	np.vnids.handleDeleteNetNamespace(&networkv1.NetNamespace{
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
	synced.Store(false)

	_, err := np.node.kClient.NetworkingV1().NetworkPolicies(policy.Namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(np, func() bool { return np.namespacesByName[policy.Namespace].policies[policy.UID] != nil })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

func delNetworkPolicy(np *networkPolicyPlugin, policy *networkingv1.NetworkPolicy) {
	synced.Store(false)

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

func assertPolicies(npns *npNamespace, nPolicies int, matches map[string]*npPolicy) error {
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

		nppFlows := sets.NewString(npp.flows...)
		matchFlows := sets.NewString()
		for _, flow := range match.flows {
			if !strings.HasSuffix(flow, ", ") {
				flow = flow + ", "
			}
			matchFlows.Insert(flow)
		}
		if !nppFlows.Equal(matchFlows) {
			return fmt.Errorf("policy %q in %q has incorrect flows; expected %#v, got %#v", npp.policy.Name, npns.name, match.flows, npp.flows)
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

func addPods(np *networkPolicyPlugin, npns *npNamespace, expectSync bool) {
	synced.Store(false)

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

	if expectSync {
		err = waitForEvent(np, func() bool { return synced.Load().(bool) })
		if err != nil {
			panic(fmt.Sprintf("Unexpected error waiting for pod sync: %v", err))
		}
	}
}

func addBadPods(np *networkPolicyPlugin, npns *npNamespace) {
	synced.Store(false)

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

	// This should not cause a resync
	err = waitForEvent(np, func() bool { return synced.Load().(bool) })
	if err == nil {
		panic("Did not get expected error! Unexpected sync occurred")
	}
}

func TestNetworkPolicy(t *testing.T) {
	np := newTestNPP()

	// Create some Namespaces
	addNamespace(np, "default", 0, map[string]string{"default": "true"})
	addNamespace(np, "one", 1, map[string]string{"parity": "odd"})
	addNamespace(np, "two", 2, map[string]string{"parity": "even", "prime": "true"})
	addNamespace(np, "three", 3, map[string]string{"parity": "odd", "prime": "true"})
	addNamespace(np, "four", 4, map[string]string{"parity": "even"})
	addNamespace(np, "five", 5, map[string]string{"parity": "odd", "prime": "true"})

	// Add allow-from-self and allow-from-default policies to all
	for _, npns := range np.namespaces {
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

	// Each namespace should now have 2 policies, each with a single flow
	for _, npns := range np.namespaces {
		err := assertPolicies(npns, 2, map[string]*npPolicy{
			"allow-from-self": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    false,
				flows: []string{
					fmt.Sprintf("reg0=%d", npns.vnid),
				},
			},
			"allow-from-default": {
				watchesNamespaces: true,
				watchesAllPods:    false,
				watchesOwnPods:    false,
				flows: []string{
					"reg0=0",
				},
			},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}

	// Add two pods to each namespace
	for _, npns := range np.namespaces {
		addPods(np, npns, false)

		// There are no pod-selecting policies yet, so nothing should have changed
		err := assertPolicies(npns, 2, nil)
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
		err = waitForEvent(np, func() bool { return synced.Load().(bool) })
		if err != nil {
			panic(fmt.Sprintf("Unexpected error waiting for networkpolicy sync: %v", err))
		}

		err = assertPolicies(npns, 3, map[string]*npPolicy{
			"allow-client-to-server": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    true,
				flows: []string{
					fmt.Sprintf("ip, nw_dst=%s, reg0=%d, ip, nw_src=%s", serverIP(npns), npns.vnid, clientIP(npns)),
				},
			},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}

	npns1 := np.namespaces[1]

	// Allow all pods in even-numbered namespaces to connect to any pod in namespace "one"
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

	err := assertPolicies(npns1, 4, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			flows: []string{
				"reg0=2",
				"reg0=4",
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow client pods in odd prime namespaces to connect to the server in namespace "one"
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

	err = assertPolicies(npns1, 5, map[string]*npPolicy{
		"allow-from-odd-primes": {
			watchesNamespaces: true,
			watchesAllPods:    true,
			watchesOwnPods:    true,
			flows: []string{
				fmt.Sprintf("ip, nw_dst=%s, reg0=3, ip, nw_src=%s", serverIP(npns1), clientIP(np.namespaces[3])),
				fmt.Sprintf("ip, nw_dst=%s, reg0=5, ip, nw_src=%s", serverIP(npns1), clientIP(np.namespaces[5])),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// add some more namespaces
	addNamespace(np, "six", 6, map[string]string{"parity": "even"})
	addPods(np, np.namespaces[6], true)
	addNamespace(np, "seven", 7, map[string]string{"parity": "odd", "prime": "true"})
	addPods(np, np.namespaces[7], true)
	addNamespace(np, "eight", 8, map[string]string{"parity": "even"})
	addPods(np, np.namespaces[8], true)
	addNamespace(np, "nine", 9, map[string]string{"parity": "odd"})
	addPods(np, np.namespaces[9], true)

	// add same non-pod-network pods; this should not affect the generated flows.
	addBadPods(np, np.namespaces[4])
	addBadPods(np, np.namespaces[7])
	addBadPods(np, np.namespaces[9])

	// Now reassert the full set of matches for each namespace
	for vnid, npns := range np.namespaces {
		switch vnid {
		case 1:
			err := assertPolicies(npns, 5, map[string]*npPolicy{
				"allow-from-self": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					flows: []string{
						"reg0=1",
					},
				},
				"allow-from-default": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					flows: []string{
						"reg0=0",
					},
				},
				"allow-client-to-server": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    true,
					flows: []string{
						fmt.Sprintf("ip, nw_dst=%s, reg0=1, ip, nw_src=%s", serverIP(npns), clientIP(npns)),
					},
				},
				"allow-from-even": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					flows: []string{
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
					flows: []string{
						fmt.Sprintf("ip, nw_dst=%s, reg0=3, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[3])),
						fmt.Sprintf("ip, nw_dst=%s, reg0=5, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[5])),
						fmt.Sprintf("ip, nw_dst=%s, reg0=7, ip, nw_src=%s", serverIP(npns), clientIP(np.namespaces[7])),
						// but NOT from reg0=9
					},
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 0, 2, 3, 4, 5:
			err := assertPolicies(npns, 3, map[string]*npPolicy{
				"allow-from-self": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					flows: []string{
						fmt.Sprintf("reg0=%d", vnid),
					},
				},
				"allow-from-default": {
					watchesNamespaces: true,
					watchesAllPods:    false,
					watchesOwnPods:    false,
					flows: []string{
						"reg0=0",
					},
				},
				"allow-client-to-server": {
					watchesNamespaces: false,
					watchesAllPods:    false,
					watchesOwnPods:    true,
					flows: []string{
						fmt.Sprintf("ip, nw_dst=%s, reg0=%d, ip, nw_src=%s", serverIP(npns), vnid, clientIP(npns)),
					},
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 6, 7, 8, 9:
			err := assertPolicies(npns, 0, nil)
			if err != nil {
				t.Error(err.Error())
			}

		default:
			t.Errorf("Unexpected namespace %d / %s", vnid, npns.name)
		}
	}

	// If we delete a namespace, then stale policies may be left behind...
	synced.Store(false)
	delNamespace(np, "two", 2)
	err = assertPolicies(npns1, 5, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			flows: []string{
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
	addNamespace(np, "unrelated", 100, nil)
	err = waitForEvent(np, func() bool { return synced.Load().(bool) })
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for namespace sync: %v", err))
	}

	err = assertPolicies(npns1, 5, map[string]*npPolicy{
		"allow-from-even": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			flows: []string{
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

	err = assertPolicies(npns4, 2, map[string]*npPolicy{
		"allow-from-self": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			flows: []string{
				fmt.Sprintf("reg0=%d", npns4.vnid),
			},
		},
		"allow-client-to-server": {
			watchesNamespaces: false,
			watchesAllPods:    false,
			watchesOwnPods:    true,
			flows: []string{
				fmt.Sprintf("ip, nw_dst=%s, reg0=%d, ip, nw_src=%s", serverIP(npns4), npns4.vnid, clientIP(npns4)),
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	err = assertPolicies(npns1, 5, map[string]*npPolicy{
		"allow-from-default": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			flows: []string{
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
	// make sure we add the right flows
	err = assertPolicies(npns, 1, map[string]*npPolicy{
		"allow-from-host-network-ns": {
			watchesNamespaces: true,
			watchesAllPods:    false,
			watchesOwnPods:    false,
			flows: []string{
				"reg0=0", //make sure host network namespace is classified into vnid 0
			},
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}

// Disabled (by initial "_") becaues it's really really slow in CI for some reason?
func _TestNetworkPolicyCache(t *testing.T) {
	const (
		initialNamespaces uint32 = 1000
		extraNamespaces   uint32 = 500
	)

	np := newTestNPP()

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

func TestNetworkPolicy_MultiplePoliciesOneNamespace(t *testing.T) {
	np := newTestNPP()

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
		addPods(np, npns, true)
		// both policies should be updated
		err := assertPolicies(npns, 2, map[string]*npPolicy{
			"allow-client-to-server-1": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    true,
				flows: []string{
					fmt.Sprintf("ip, nw_dst=%s, reg0=%d, ip, nw_src=%s", serverIP(npns), npns.vnid, clientIP(npns)),
				},
			},
			"allow-client-to-server-2": {
				watchesNamespaces: false,
				watchesAllPods:    false,
				watchesOwnPods:    true,
				flows: []string{
					fmt.Sprintf("ip, nw_dst=%s, reg0=%d, ip, nw_src=%s", serverIP(npns), npns.vnid, clientIP(npns)),
				},
			},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}
}
