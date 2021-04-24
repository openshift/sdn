// +build linux

package proxy

import (
	"fmt"
	"net"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/util/async"

	networkv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
)

type testProxy struct {
	kubeproxyconfig.NoopEndpointSliceHandler

	name string

	services  sets.String
	endpoints sets.String
	events    []string
}

func newTestProxy(name string) *testProxy {
	return &testProxy{
		name: name,

		services:  sets.NewString(),
		endpoints: sets.NewString(),
	}
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
	name := ep.Namespace + "/" + ep.Name
	if tp.endpoints.Has(name) {
		panic(fmt.Sprintf("%s proxy got endpoints add for already-existing endpoints %s", tp.name, name))
	}

	tp.endpoints.Insert(name)
	tp.events = append(tp.events, fmt.Sprintf("add endpoints %s %s", name, endpointIPs(ep)))
}

func (tp *testProxy) OnEndpointsUpdate(old, ep *corev1.Endpoints) {
	name := ep.Namespace + "/" + ep.Name
	if !tp.endpoints.Has(name) {
		panic(fmt.Sprintf("%s proxy got endpoints update for non-existent endpoints %s", tp.name, name))
	}

	tp.events = append(tp.events, fmt.Sprintf("update endpoints %s %s", name, endpointIPs(ep)))
}

func (tp *testProxy) OnEndpointsDelete(ep *corev1.Endpoints) {
	name := ep.Namespace + "/" + ep.Name
	if !tp.endpoints.Has(name) {
		panic(fmt.Sprintf("%s proxy got endpoints delete for non-existent endpoints %s", tp.name, name))
	}

	tp.endpoints.Delete(name)
	tp.events = append(tp.events, fmt.Sprintf("delete endpoints %s %s", name, endpointIPs(ep)))
}

func (tp *testProxy) OnEndpointsSynced() {
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

func makeEndpoints(namespace, name string, ips ...string) *corev1.Endpoints {
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

	return ep
}

func TestOsdnProxy(t *testing.T) {
	proxy, err := New(nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error creating Proxy: %v", err)
	}
	tp := newTestProxy("filtering")
	proxy.baseProxy = tp
	proxy.networkInfo = &common.ParsedClusterNetwork{
		ClusterNetworks: []common.ParsedClusterNetworkEntry{
			{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
		},
		ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
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

	ep := makeEndpoints("default", "kubernetes", "10.0.0.1", "10.0.0.2", "10.0.0.3")
	proxy.OnEndpointsAdd(ep)
	initialEvents.Insert("add endpoints default/kubernetes 10.0.0.1 10.0.0.2 10.0.0.3")

	eps := make(map[string]map[string]*corev1.Endpoints)
	for _, ns := range namespaces {
		if ns.Name == "default" {
			continue
		}
		eps[ns.Name] = make(map[string]*corev1.Endpoints)

		ep = makeEndpoints(ns.Name, "local", "10.130.0.5", "10.131.2.5")
		proxy.OnEndpointsAdd(ep)
		eps[ns.Name]["local"] = ep
		initialEvents.Insert("add endpoints " + ns.Name + "/local 10.130.0.5 10.131.2.5")

		ep = makeEndpoints(ns.Name, "extfar", "1.2.3.4")
		proxy.OnEndpointsAdd(ep)
		eps[ns.Name]["extfar"] = ep
		initialEvents.Insert("add endpoints " + ns.Name + "/extfar 1.2.3.4")

		ep = makeEndpoints(ns.Name, "extnear", "192.168.2.5")
		proxy.OnEndpointsAdd(ep)
		eps[ns.Name]["extnear"] = ep
		initialEvents.Insert("add endpoints " + ns.Name + "/extnear 192.168.2.5")

		ep = makeEndpoints(ns.Name, "extbad", "192.168.1.5")
		proxy.OnEndpointsAdd(ep)
		eps[ns.Name]["extbad"] = ep
		initialEvents.Insert("add endpoints " + ns.Name + "/extbad 192.168.1.5")

		ep = makeEndpoints(ns.Name, "extexcept", "192.168.1.1")
		proxy.OnEndpointsAdd(ep)
		eps[ns.Name]["extexcept"] = ep
		initialEvents.Insert("add endpoints " + ns.Name + "/extexcept 192.168.1.1")

		ep = makeEndpoints(ns.Name, "extmixed", "10.130.0.5", "192.168.1.5")
		proxy.OnEndpointsAdd(ep)
		eps[ns.Name]["extmixed"] = ep
		initialEvents.Insert("add endpoints " + ns.Name + "/extmixed 10.130.0.5 192.168.1.5")
	}
	// fixup: we added a few endpoints to expectedEndpoints that we don't actually expect
	initialEvents.Delete(
		"add endpoints one/extbad 192.168.1.5",
		"add endpoints one/extmixed 10.130.0.5 192.168.1.5",
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
		"delete endpoints three/extfar 1.2.3.4",
		"delete endpoints three/extnear 192.168.2.5",
		"delete endpoints three/extbad 192.168.1.5",
		"delete endpoints three/extmixed 10.130.0.5 192.168.1.5",
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
		"delete endpoints two/extbad 192.168.1.5",
		"delete endpoints two/extmixed 10.130.0.5 192.168.1.5",
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
		"delete endpoints two/extfar 1.2.3.4",
		"delete endpoints two/extnear 192.168.2.5",
		"delete endpoints two/extexcept 192.168.1.1",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now delete the first ENP, which should result in the second becoming active
	// (meaning "two" will allow the same things as "three")
	proxy.handleDeleteEgressNetworkPolicy(enp2a)
	err = tp.assertEvents("after deleting first EgressNetworkPolicy from namespace two",
		"add endpoints two/extexcept 192.168.1.1",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now delete the second ENP, which should unblock everything
	proxy.handleDeleteEgressNetworkPolicy(enp2b)
	err = tp.assertEvents("after deleting second EgressNetworkPolicy from namespace two",
		"add endpoints two/extfar 1.2.3.4",
		"add endpoints two/extnear 192.168.2.5",
		"add endpoints two/extbad 192.168.1.5",
		"add endpoints two/extmixed 10.130.0.5 192.168.1.5",
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
		proxy.OnEndpointsDelete(ep)
	}
	proxy.handleDeleteNetNamespace(namespaces[4])
	namespaces = namespaces[:4]

	err = tp.assertEvents("after deleting namespace four",
		"delete endpoints four/local 10.130.0.5 10.131.2.5",
		"delete endpoints four/extfar 1.2.3.4",
		"delete endpoints four/extnear 192.168.2.5",
		"delete endpoints four/extbad 192.168.1.5",
		"delete endpoints four/extexcept 192.168.1.1",
		"delete endpoints four/extmixed 10.130.0.5 192.168.1.5",
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
		ep := makeEndpoints(ns.Name, "local", "10.130.0.5", "10.131.1.5")
		proxy.OnEndpointsUpdate(eps[ns.Name]["local"], ep)
		eps[ns.Name]["local"] = ep

		ep = makeEndpoints(ns.Name, "extnear", "192.168.2.5", "192.168.1.4")
		proxy.OnEndpointsUpdate(eps[ns.Name]["extnear"], ep)
		eps[ns.Name]["extnear"] = ep

		ep = makeEndpoints(ns.Name, "extbad", "192.168.3.5")
		proxy.OnEndpointsUpdate(eps[ns.Name]["extbad"], ep)
		eps[ns.Name]["extbad"] = ep
	}

	err = tp.assertEvents("after modifying endpoints",
		// In namespace one, this blocks extnear and unblocks extbad
		"update endpoints one/local 10.130.0.5 10.131.1.5",
		"delete endpoints one/extnear 192.168.2.5",
		"add endpoints one/extbad 192.168.3.5",

		// In namespace two, there is no effect on blocking; we just observe the
		// updated endpoints
		"update endpoints two/local 10.130.0.5 10.131.1.5",
		"update endpoints two/extnear 192.168.2.5 192.168.1.4",
		"update endpoints two/extbad 192.168.3.5",

		// In namespace three, extnear and extbad were blocked before and are
		// still blocked, so we don't see any updates to them.
		"update endpoints three/local 10.130.0.5 10.131.1.5",
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
		"add endpoints three/extfar 1.2.3.4",
		"add endpoints three/extbad 192.168.3.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
