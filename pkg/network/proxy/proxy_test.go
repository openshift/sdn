// +build linux

package proxy

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/kubernetes/pkg/util/async"

	networkv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
)

type testProxy struct {
	name string

	services       sets.String
	endpoints      sets.String
	endpointSlices sets.String

	events []string
}

func newTestProxy(name string, usesEndpointSlices bool) *testProxy {
	tp := &testProxy{
		name: name,

		services: sets.NewString(),
	}

	if usesEndpointSlices {
		tp.endpointSlices = sets.NewString()
	} else {
		tp.endpoints = sets.NewString()
	}

	return tp
}

func (tp *testProxy) assertEvents(when string, events ...string) error {
	happened := sets.NewString(tp.events...)
	expected := sets.NewString(events...)
	tp.events = nil

	if !happened.Equal(expected) {
		return fmt.Errorf("Bad events for %s proxy %s:\nMistakenly present: %s\nMistakenly missing: %s\n",
			tp.name, when,
			strings.Join(happened.Difference(expected).List(), ", "),
			strings.Join(expected.Difference(happened).List(), ", "))
	}
	return nil
}

func (tp *testProxy) assertNoEvents(when string) error {
	return tp.assertEvents(when)
}

func (tp *testProxy) OnServiceAdd(svc *corev1.Service) {
	name := svc.Namespace + "/" + svc.Name
	if tp.services.Has(name) {
		panic(fmt.Sprintf("%s proxy got service add for already-existing service %s", tp.name, name))
	}

	tp.services.Insert(name)
	tp.events = append(tp.events, fmt.Sprintf("add service %s", name))
}

func (tp *testProxy) OnServiceUpdate(old, svc *corev1.Service) {
	name := svc.Namespace + "/" + svc.Name
	if !tp.services.Has(name) {
		panic(fmt.Sprintf("%s proxy got service update for non-existent service %s", tp.name, name))
	}

	tp.events = append(tp.events, fmt.Sprintf("update service %s", name))
}

func (tp *testProxy) OnServiceDelete(svc *corev1.Service) {
	name := svc.Namespace + "/" + svc.Name
	if !tp.services.Has(name) {
		panic(fmt.Sprintf("%s proxy got service delete for non-existent service %s", tp.name, name))
	}

	tp.services.Delete(name)
	tp.events = append(tp.events, fmt.Sprintf("delete service %s", name))
}

func (tp *testProxy) OnServiceSynced() {
}

func endpointIPs(ep *corev1.Endpoints) string {
	if len(ep.Subsets) == 0 || len(ep.Subsets[0].Addresses) == 0 {
		return "-"
	}
	ips := ""
	for _, ss := range ep.Subsets {
		for _, addr := range ss.Addresses {
			if len(ips) > 0 {
				ips += " "
			}
			ips += addr.IP
		}
	}
	return ips
}

func (tp *testProxy) OnEndpointsAdd(ep *corev1.Endpoints) {
	if tp.endpoints == nil {
		panic(fmt.Sprintf("%s proxy got unexpected Endpoints event", tp.name))
	}

	name := ep.Namespace + "/" + ep.Name
	if tp.endpoints.Has(name) {
		panic(fmt.Sprintf("%s proxy got endpoints add for already-existing endpoints %s", tp.name, name))
	}

	tp.endpoints.Insert(name)
	tp.events = append(tp.events, fmt.Sprintf("add endpoints %s %s", name, endpointIPs(ep)))
}

func (tp *testProxy) OnEndpointsUpdate(old, ep *corev1.Endpoints) {
	if tp.endpoints == nil {
		panic(fmt.Sprintf("%s proxy got unexpected Endpoints event", tp.name))
	}

	name := ep.Namespace + "/" + ep.Name
	if !tp.endpoints.Has(name) {
		panic(fmt.Sprintf("%s proxy got endpoints update for non-existent endpoints %s", tp.name, name))
	}

	tp.events = append(tp.events, fmt.Sprintf("update endpoints %s %s", name, endpointIPs(ep)))
}

func (tp *testProxy) OnEndpointsDelete(ep *corev1.Endpoints) {
	if tp.endpoints == nil {
		panic(fmt.Sprintf("%s proxy got unexpected Endpoints event", tp.name))
	}

	name := ep.Namespace + "/" + ep.Name
	if !tp.endpoints.Has(name) {
		panic(fmt.Sprintf("%s proxy got endpoints delete for non-existent endpoints %s", tp.name, name))
	}

	tp.endpoints.Delete(name)
	tp.events = append(tp.events, fmt.Sprintf("delete endpoints %s %s", name, endpointIPs(ep)))
}

func (tp *testProxy) OnEndpointsSynced() {
	if tp.endpoints == nil {
		panic(fmt.Sprintf("%s proxy got unexpected Endpoints event", tp.name))
	}
}

func endpointSliceIPs(slice *discoveryv1beta1.EndpointSlice) string {
	if len(slice.Endpoints) == 0 || len(slice.Endpoints[0].Addresses) == 0 {
		return "-"
	}
	ips := ""
	for _, ep := range slice.Endpoints {
		for _, addr := range ep.Addresses {
			if len(ips) > 0 {
				ips += " "
			}
			ips += addr
		}
	}
	return ips
}

func (tp *testProxy) OnEndpointSliceAdd(slice *discoveryv1beta1.EndpointSlice) {
	if tp.endpointSlices == nil {
		panic(fmt.Sprintf("%s proxy got unexpected EndpointSlice event", tp.name))
	}

	name := slice.Namespace + "/" + slice.Name
	if tp.endpointSlices.Has(name) {
		panic(fmt.Sprintf("got endpointslice add for already-existing endpoints %s", name))
	}

	tp.endpointSlices.Insert(name)
	tp.events = append(tp.events, fmt.Sprintf("add endpointslice %s %s", name, endpointSliceIPs(slice)))
}

func (tp *testProxy) OnEndpointSliceUpdate(old, slice *discoveryv1beta1.EndpointSlice) {
	if tp.endpointSlices == nil {
		panic(fmt.Sprintf("%s proxy got unexpected EndpointSlice event", tp.name))
	}

	name := slice.Namespace + "/" + slice.Name
	if !tp.endpointSlices.Has(name) {
		panic(fmt.Sprintf("got endpointslice update for non-existent endpoints %s", name))
	}

	tp.events = append(tp.events, fmt.Sprintf("update endpointslice %s %s", name, endpointSliceIPs(slice)))
}

func (tp *testProxy) OnEndpointSliceDelete(slice *discoveryv1beta1.EndpointSlice) {
	if tp.endpointSlices == nil {
		panic(fmt.Sprintf("%s proxy got unexpected EndpointSlice event", tp.name))
	}

	name := slice.Namespace + "/" + slice.Name
	if !tp.endpointSlices.Has(name) {
		panic(fmt.Sprintf("got endpointslice delete for non-existent endpoints %s", name))
	}

	tp.endpointSlices.Delete(name)
	tp.events = append(tp.events, fmt.Sprintf("delete endpointslice %s %s", name, endpointSliceIPs(slice)))
}

func (tp *testProxy) OnEndpointSlicesSynced() {
	if tp.endpointSlices == nil {
		panic(fmt.Sprintf("%s proxy got unexpected EndpointSlice event", tp.name))
	}
}

func (tp *testProxy) OnNodeAdd(node *corev1.Node) {
}

func (tp *testProxy) OnNodeUpdate(oldNode, node *corev1.Node) {
}

func (tp *testProxy) OnNodeDelete(node *corev1.Node) {
}

func (tp *testProxy) OnNodeSynced() {
}

func (tp *testProxy) Sync() {
}

func (tp *testProxy) SyncLoop() {
}

func (tp *testProxy) SyncProxyRules() {
}

func (tp *testProxy) SetSyncRunner(b *async.BoundedFrequencyRunner) {
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("bad CIDR string constant " + cidr)
	}
	return net
}

func makeEndpoints(namespace, name string, ips ...string) (*corev1.Endpoints, *discoveryv1beta1.EndpointSlice) {
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			UID:         ktypes.UID(namespace + "/" + name),
			Annotations: make(map[string]string),
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: make([]corev1.EndpointAddress, len(ips)),
				Ports: []corev1.EndpointPort{
					{
						Port: 80,
					},
				},
			},
		},
	}
	for i, ip := range ips {
		ep.Subsets[0].Addresses[i].IP = ip
	}

	slice := &discoveryv1beta1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       ktypes.UID(namespace + "/" + name),
		},
		Endpoints: []discoveryv1beta1.Endpoint{
			{
				Addresses: ips,
			},
		},
	}

	return ep, slice
}

func newTestOsdnProxy(usesEndpointSlices bool) (*OsdnProxy, *testProxy, *testProxy, error) {
	kubeClient := fake.NewSimpleClientset()
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, time.Hour)

	proxy, err := New(kubeClient, kubeInformers, nil, nil, 0)
	if err != nil {
		return nil, nil, nil, err
	}

	proxy.networkInfo = &common.ParsedClusterNetwork{
		ClusterNetworks: []common.ParsedClusterNetworkEntry{
			{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
		},
		ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
	}

	mainProxy := newTestProxy("main", usesEndpointSlices)
	unidlingProxy := newTestProxy("unidling", false)
	proxy.SetBaseProxies(mainProxy, unidlingProxy)

	stopCh := make(chan struct{})
	proxy.kubeInformers.Start(stopCh)

	return proxy, mainProxy, unidlingProxy, nil
}

func TestOsdnProxy(t *testing.T) {
	proxy, tp, _, err := newTestOsdnProxy(true)
	if err != nil {
		t.Fatalf("unexpected error creating OsdnProxy: %v", err)
	}

	// Create NetNamespaces
	namespaces := make([]*networkv1.NetNamespace, 5)
	for i, name := range []string{"default", "one", "two", "three", "four"} {
		namespaces[i] = &networkv1.NetNamespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			NetID: uint32(i),
		}
		proxy.handleAddOrUpdateNetNamespace(namespaces[i], nil, watch.Added)
	}

	// Create EgressNetworkPolicy rules in "one"
	enp1 := &networkv1.EgressNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespaces[1].Name,
			Name:      "enp1",
			UID:       ktypes.UID("enp1"),
		},
		Spec: networkv1.EgressNetworkPolicySpec{
			Egress: []networkv1.EgressNetworkPolicyRule{
				{
					Type: networkv1.EgressNetworkPolicyRuleAllow,
					To: networkv1.EgressNetworkPolicyPeer{
						CIDRSelector: "192.168.1.1/32",
					},
				},
				{
					Type: networkv1.EgressNetworkPolicyRuleDeny,
					To: networkv1.EgressNetworkPolicyPeer{
						CIDRSelector: "192.168.1.0/24",
					},
				},
				{
					Type: networkv1.EgressNetworkPolicyRuleAllow,
					To: networkv1.EgressNetworkPolicyPeer{
						CIDRSelector: "192.168.0.0/16",
					},
				},
			},
		},
	}
	proxy.handleAddOrUpdateEgressNetworkPolicy(enp1, nil, watch.Added)

	// Create Endpoints
	initialEvents := sets.NewString()

	_, ep := makeEndpoints("default", "kubernetes", "10.0.0.1", "10.0.0.2", "10.0.0.3")
	proxy.OnEndpointSliceAdd(ep)
	initialEvents.Insert("add endpointslice default/kubernetes 10.0.0.1 10.0.0.2 10.0.0.3")

	eps := make(map[string]map[string]*discoveryv1beta1.EndpointSlice)
	for _, ns := range namespaces {
		if ns.Name == "default" {
			continue
		}
		eps[ns.Name] = make(map[string]*discoveryv1beta1.EndpointSlice)

		_, ep := makeEndpoints(ns.Name, "local", "10.130.0.5", "10.131.2.5")
		proxy.OnEndpointSliceAdd(ep)
		eps[ns.Name]["local"] = ep
		initialEvents.Insert("add endpointslice " + ns.Name + "/local 10.130.0.5 10.131.2.5")

		_, ep = makeEndpoints(ns.Name, "extfar", "1.2.3.4")
		proxy.OnEndpointSliceAdd(ep)
		eps[ns.Name]["extfar"] = ep
		initialEvents.Insert("add endpointslice " + ns.Name + "/extfar 1.2.3.4")

		_, ep = makeEndpoints(ns.Name, "extnear", "192.168.2.5")
		proxy.OnEndpointSliceAdd(ep)
		eps[ns.Name]["extnear"] = ep
		initialEvents.Insert("add endpointslice " + ns.Name + "/extnear 192.168.2.5")

		_, ep = makeEndpoints(ns.Name, "extbad", "192.168.1.5")
		proxy.OnEndpointSliceAdd(ep)
		eps[ns.Name]["extbad"] = ep
		initialEvents.Insert("add endpointslice " + ns.Name + "/extbad 192.168.1.5")

		_, ep = makeEndpoints(ns.Name, "extexcept", "192.168.1.1")
		proxy.OnEndpointSliceAdd(ep)
		eps[ns.Name]["extexcept"] = ep
		initialEvents.Insert("add endpointslice " + ns.Name + "/extexcept 192.168.1.1")

		_, ep = makeEndpoints(ns.Name, "extmixed", "10.130.0.5", "192.168.1.5")
		proxy.OnEndpointSliceAdd(ep)
		eps[ns.Name]["extmixed"] = ep
		initialEvents.Insert("add endpointslice " + ns.Name + "/extmixed 10.130.0.5 192.168.1.5")
	}
	// fixup: we added a few endpoints that we don't actually expect
	initialEvents.Delete(
		"add endpointslice one/extbad 192.168.1.5",
		"add endpointslice one/extmixed 10.130.0.5 192.168.1.5",
	)

	// *****

	// Initial state
	err = tp.assertEvents("at startup", initialEvents.UnsortedList()...)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// Add a new EgressNetworkPolicy to an existing namespace
	enp3 := &networkv1.EgressNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespaces[3].Name,
			Name:      "enp3",
			UID:       ktypes.UID("enp3"),
		},
		Spec: networkv1.EgressNetworkPolicySpec{
			Egress: []networkv1.EgressNetworkPolicyRule{
				{
					Type: networkv1.EgressNetworkPolicyRuleAllow,
					To: networkv1.EgressNetworkPolicyPeer{
						CIDRSelector: "192.168.1.1/32",
					},
				},
				{
					Type: networkv1.EgressNetworkPolicyRuleDeny,
					To: networkv1.EgressNetworkPolicyPeer{
						CIDRSelector: "0.0.0.0/0",
					},
				},
			},
		},
	}
	proxy.handleAddOrUpdateEgressNetworkPolicy(enp3, nil, watch.Added)

	// That should result in everything external except "extexcept" being blocked
	err = tp.assertEvents("after adding EgressNetworkPolicy to namespace three",
		"delete endpointslice three/extfar 1.2.3.4",
		"delete endpointslice three/extnear 192.168.2.5",
		"delete endpointslice three/extbad 192.168.1.5",
		"delete endpointslice three/extmixed 10.130.0.5 192.168.1.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// Fiddle with EgressNetworkPolicies in namespace "two". First copy "one"s ENP to "two"
	enp2a := enp1.DeepCopy()
	enp2a.Namespace = namespaces[2].Name
	enp2a.Name = "enp2a"
	enp2a.UID = ktypes.UID("enp2a")
	proxy.handleAddOrUpdateEgressNetworkPolicy(enp2a, nil, watch.Added)

	err = tp.assertEvents("after copying first EgressNetworkPolicy to namespace two",
		"delete endpointslice two/extbad 192.168.1.5",
		"delete endpointslice two/extmixed 10.130.0.5 192.168.1.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now copy "three"s ENP to "two" too, which should totally break external connectivity
	enp2b := enp3.DeepCopy()
	enp2b.Namespace = namespaces[2].Name
	enp2b.Name = "enp2b"
	enp2b.UID = ktypes.UID("enp2b")
	proxy.handleAddOrUpdateEgressNetworkPolicy(enp2b, nil, watch.Added)

	err = tp.assertEvents("after copying second EgressNetworkPolicy to namespace two",
		"delete endpointslice two/extfar 1.2.3.4",
		"delete endpointslice two/extnear 192.168.2.5",
		"delete endpointslice two/extexcept 192.168.1.1",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now delete the first ENP, which should result in the second becoming active
	// (meaning "two" will allow the same things as "three")
	proxy.handleDeleteEgressNetworkPolicy(enp2a)
	err = tp.assertEvents("after deleting first EgressNetworkPolicy from namespace two",
		"add endpointslice two/extexcept 192.168.1.1",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now delete the second ENP, which should unblock everything
	proxy.handleDeleteEgressNetworkPolicy(enp2b)
	err = tp.assertEvents("after deleting second EgressNetworkPolicy from namespace two",
		"add endpointslice two/extfar 1.2.3.4",
		"add endpointslice two/extnear 192.168.2.5",
		"add endpointslice two/extbad 192.168.1.5",
		"add endpointslice two/extmixed 10.130.0.5 192.168.1.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// An ENP in "default" should just be ignored
	enpDefault := &networkv1.EgressNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespaces[0].Name,
			Name:      "enpDefault",
			UID:       ktypes.UID("enpDefault"),
		},
		Spec: networkv1.EgressNetworkPolicySpec{
			Egress: []networkv1.EgressNetworkPolicyRule{
				{
					Type: networkv1.EgressNetworkPolicyRuleDeny,
					To: networkv1.EgressNetworkPolicyPeer{
						CIDRSelector: "0.0.0.0/0",
					},
				},
			},
		},
	}
	proxy.handleAddOrUpdateEgressNetworkPolicy(enpDefault, nil, watch.Added)
	err = tp.assertNoEvents("after adding EgressNetworkPolicy to default")
	if err != nil {
		t.Fatalf("%v", err)
	}

	proxy.handleDeleteEgressNetworkPolicy(enpDefault)
	err = tp.assertNoEvents("after deleting EgressNetworkPolicy from default")
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// Delete namespace "four"
	for _, ep := range eps[namespaces[4].Name] {
		proxy.OnEndpointSliceDelete(ep)
	}
	proxy.handleDeleteNetNamespace(namespaces[4])
	namespaces = namespaces[:4]

	err = tp.assertEvents("after deleting namespace four",
		"delete endpointslice four/local 10.130.0.5 10.131.2.5",
		"delete endpointslice four/extfar 1.2.3.4",
		"delete endpointslice four/extnear 192.168.2.5",
		"delete endpointslice four/extbad 192.168.1.5",
		"delete endpointslice four/extexcept 192.168.1.1",
		"delete endpointslice four/extmixed 10.130.0.5 192.168.1.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// Modify Endpoints
	for _, ns := range namespaces {
		if ns.Name == "default" {
			continue
		}
		_, ep := makeEndpoints(ns.Name, "local", "10.130.0.5", "10.131.1.5")
		proxy.OnEndpointSliceUpdate(eps[ns.Name]["local"], ep)
		eps[ns.Name]["local"] = ep

		_, ep = makeEndpoints(ns.Name, "extnear", "192.168.2.5", "192.168.1.4")
		proxy.OnEndpointSliceUpdate(eps[ns.Name]["extnear"], ep)
		eps[ns.Name]["extnear"] = ep

		_, ep = makeEndpoints(ns.Name, "extbad", "192.168.3.5")
		proxy.OnEndpointSliceUpdate(eps[ns.Name]["extbad"], ep)
		eps[ns.Name]["extbad"] = ep
	}

	err = tp.assertEvents("after modifying endpoints",
		// In namespace one, this blocks extnear and unblocks extbad
		"update endpointslice one/local 10.130.0.5 10.131.1.5",
		"delete endpointslice one/extnear 192.168.2.5",
		"add endpointslice one/extbad 192.168.3.5",

		// In namespace two, there is no effect on blocking; we just observe the
		// updated endpoints
		"update endpointslice two/local 10.130.0.5 10.131.1.5",
		"update endpointslice two/extnear 192.168.2.5 192.168.1.4",
		"update endpointslice two/extbad 192.168.3.5",

		// In namespace three, extnear and extbad were blocked before and are
		// still blocked, so we don't see any updates to them.
		"update endpointslice three/local 10.130.0.5 10.131.1.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// *****

	// Modify EgressNetworkPolicy
	enp3new := enp3.DeepCopy()
	enp3new.Spec.Egress = enp1.Spec.Egress
	proxy.handleAddOrUpdateEgressNetworkPolicy(enp3new, enp3, watch.Modified)

	// Now namespace three will see the extbad, with the updated IP from above
	err = tp.assertEvents("after modifying EgressNetworkPolicy",
		"add endpointslice three/extfar 1.2.3.4",
		"add endpointslice three/extbad 192.168.3.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
