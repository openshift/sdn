package common

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	fakekubeclient "k8s.io/client-go/kubernetes/fake"

	osdnv1 "github.com/openshift/api/network/v1"
)

type testEIPWatcher struct {
	changes []string
}

func (w *testEIPWatcher) Synced() {
	panic("should not be reached in unit test")
}

func (w *testEIPWatcher) ClaimEgressIP(vnid uint32, egressIP, nodeIP, sdnIP string) {
	w.changes = append(w.changes, fmt.Sprintf("claim %s on %s for namespace %d", egressIP, nodeIP, vnid))
}

func (w *testEIPWatcher) ReleaseEgressIP(egressIP, nodeIP string) {
	w.changes = append(w.changes, fmt.Sprintf("release %s on %s", egressIP, nodeIP))
}

func (w *testEIPWatcher) SetNamespaceEgressNormal(vnid uint32) {
	w.changes = append(w.changes, fmt.Sprintf("namespace %d normal", int(vnid)))
}

func (w *testEIPWatcher) SetNamespaceEgressDropped(vnid uint32) {
	w.changes = append(w.changes, fmt.Sprintf("namespace %d dropped", int(vnid)))
}

func (w *testEIPWatcher) SetNamespaceEgressViaEgressIPs(vnid uint32, activeEgressIPs []EgressIPAssignment) {
	for _, activeEgressIP := range activeEgressIPs {
		w.changes = append(w.changes, fmt.Sprintf("namespace %d via %s on %s", int(vnid), activeEgressIP.EgressIP, activeEgressIP.NodeIP))
	}
}

func (w *testEIPWatcher) UpdateEgressCIDRs() {
	w.changes = append(w.changes, "update egress CIDRs")
}

func (w *testEIPWatcher) assertChanges(expected ...string) error {
	changed := w.changes
	w.changes = []string{}
	missing := []string{}

	for len(expected) > 0 {
		exp := expected[0]
		expected = expected[1:]
		for i, ch := range changed {
			if ch == exp {
				changed = append(changed[:i], changed[i+1:]...)
				exp = ""
				break
			}
		}
		if exp != "" {
			missing = append(missing, exp)
		}
	}

	if len(changed) > 0 && len(missing) > 0 {
		return fmt.Errorf("unexpected changes %#v, missing changes %#v", changed, missing)
	} else if len(changed) > 0 {
		return fmt.Errorf("unexpected changes %#v", changed)
	} else if len(missing) > 0 {
		return fmt.Errorf("missing changes %#v", missing)
	} else {
		return nil
	}
}

func (w *testEIPWatcher) assertNoChanges() error {
	return w.assertChanges()
}

func (w *testEIPWatcher) flushChanges() {
	w.changes = []string{}
}

func (w *testEIPWatcher) assertUpdateEgressCIDRsNotification() error {
	for _, change := range w.changes {
		if change == "update egress CIDRs" {
			w.flushChanges()
			return nil
		}
	}
	return fmt.Errorf("expected change \"update egress CIDRs\", got %#v", w.changes)
}

func setupEgressIPTracker(t *testing.T, cloudEgressIP bool) (*EgressIPTracker, *testEIPWatcher) {
	watcher := &testEIPWatcher{}
	return NewEgressIPTracker(watcher, cloudEgressIP, "", nil), watcher
}

func updateHostSubnetEgress(eit *EgressIPTracker, hs *osdnv1.HostSubnet) {
	if hs.Host == "" {
		hs.Host = "node-" + hs.HostIP[strings.LastIndex(hs.HostIP, ".")+1:]
	}
	hs.Name = hs.Host
	hs.UID = ktypes.UID(hs.Name)
	eit.UpdateHostSubnetEgress(hs)
}

func updateNetNamespaceEgress(eit *EgressIPTracker, ns *osdnv1.NetNamespace) {
	if ns.NetName == "" {
		ns.NetName = fmt.Sprintf("ns-%d", ns.NetID)
	}
	ns.Name = ns.NetName
	ns.UID = ktypes.UID(ns.Name)
	eit.UpdateNetNamespaceEgress(ns)
}

func TestEgressIP(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Subnet: "10.128.0.0/23",
		HostIP: "172.17.0.3",
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Subnet: "10.128.0.0/23",
		HostIP: "172.17.0.4",
	})
	eit.DeleteNetNamespaceEgress(42)
	eit.DeleteNetNamespaceEgress(43)

	// No namespaces use egress yet, so should be no changes
	err := w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Assign NetNamespace.EgressIP first, then HostSubnet.EgressIP
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"namespace 42 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"}, // Added .100
	})
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Assign HostSubnet.EgressIP first, then NetNamespace.EgressIP
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100", "172.17.0.101"}, // Added .101
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.5",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.105"},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.105"},
	})
	err = w.assertChanges(
		"claim 172.17.0.105 on 172.17.0.5 for namespace 43",
		"namespace 43 via 172.17.0.105 on 172.17.0.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Change NetNamespace.EgressIP
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101"},
	})
	err = w.assertChanges(
		"release 172.17.0.105 on 172.17.0.5",
		"claim 172.17.0.101 on 172.17.0.3 for namespace 43",
		"namespace 43 via 172.17.0.101 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Assign another EgressIP...
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     44,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.104"},
	})
	err = w.assertChanges(
		"namespace 44 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.102", "172.17.0.104"}, // Added .102, .104
	})
	err = w.assertChanges(
		"claim 172.17.0.104 on 172.17.0.4 for namespace 44",
		"namespace 44 via 172.17.0.104 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Change Namespace EgressIP
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     44,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.102"},
	})
	err = w.assertChanges(
		"release 172.17.0.104 on 172.17.0.4",
		"claim 172.17.0.102 on 172.17.0.4 for namespace 44",
		"namespace 44 via 172.17.0.102 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Assign HostSubnet.EgressIP first, then NetNamespace.EgressIP
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.102", "172.17.0.103"}, // Added .103, Dropped .104
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     45,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.103"},
	})
	err = w.assertChanges(
		"claim 172.17.0.103 on 172.17.0.4 for namespace 45",
		"namespace 45 via 172.17.0.103 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Drop namespace EgressIP
	eit.DeleteNetNamespaceEgress(44)
	err = w.assertChanges(
		"release 172.17.0.102 on 172.17.0.4",
		"namespace 44 normal",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Add namespace EgressIP back again after having removed it...
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     44,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.102"},
	})
	err = w.assertChanges(
		"claim 172.17.0.102 on 172.17.0.4 for namespace 44",
		"namespace 44 via 172.17.0.102 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Drop node EgressIPs
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"}, // Dropped .101
	})
	err = w.assertChanges(
		"release 172.17.0.101 on 172.17.0.3",
		"namespace 43 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.102"}, // Dropped .103
	})
	err = w.assertChanges(
		"release 172.17.0.103 on 172.17.0.4",
		"namespace 45 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Add them back, swapped
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100", "172.17.0.103"}, // Added .103
	})
	err = w.assertChanges(
		"claim 172.17.0.103 on 172.17.0.3 for namespace 45",
		"namespace 45 via 172.17.0.103 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.101", "172.17.0.102"}, // Added .101
	})
	err = w.assertChanges(
		"claim 172.17.0.101 on 172.17.0.4 for namespace 43",
		"namespace 43 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestMultipleNamespaceEgressIPs(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	err := w.assertChanges(
		// after UpdateNamespaceEgress()
		"namespace 42 dropped",
		// after UpdateHostSubnetEgress()
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Prepending a second, unavailable, namespace egress IP should have no effect
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101", "172.17.0.100"},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now assigning that IP to a node should cause ovs to add both of them
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.101"},
	})
	err = w.assertChanges(
		"claim 172.17.0.101 on 172.17.0.4 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Swapping the order in the NetNamespace should do nothing since we are using both of them
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100", "172.17.0.101"},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the 1 egress IP from its node should cause it to be removed
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.200"},
	})
	err = w.assertChanges(
		"release 172.17.0.101 on 172.17.0.4",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the remaining egress IP should now kill the namespace
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{},
	})
	err = w.assertChanges(
		"release 172.17.0.100 on 172.17.0.3",
		"namespace 42 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now add the egress IPs back...this will cause them to all be added
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.101"},
	})
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"claim 172.17.0.101 on 172.17.0.4 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Assigning either of the used Egress IP to another namespace should break that
	// specific Egress IP on both namespaces
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"release 172.17.0.100 on 172.17.0.3",
		"namespace 42 dropped",
		"namespace 43 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	eit.DeleteNetNamespaceEgress(43)
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
		"namespace 43 normal",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     44,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101"},
	})
	err = w.assertChanges(
		"release 172.17.0.101 on 172.17.0.4",
		"namespace 42 dropped",
		"namespace 44 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	eit.DeleteNetNamespaceEgress(44)
	err = w.assertChanges(
		"claim 172.17.0.101 on 172.17.0.4 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
		"namespace 44 normal",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestDuplicateNodeEgressIPs(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	err := w.assertChanges(
		// after UpdateNamespaceEgress()
		"namespace 42 dropped",
		// after UpdateHostSubnetEgress()
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Adding the Egress IP to another node should not work and should cause the
	// namespace to start dropping traffic. (And in particular, should not result
	// in a ClaimEgressIP for the new IP.)
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"release 172.17.0.100 on 172.17.0.3",
		"namespace 42 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Auto-egress-IP assignment should ignore the IP while it is double-booked
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	err = w.assertChanges(
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	allocation := eit.ReallocateEgressIPs()
	if node5ips, ok := allocation["node-5"]; !ok {
		t.Fatalf("Unexpected IP allocation: %#v", allocation)
	} else if len(node5ips) != 0 {
		t.Fatalf("Unexpected IP allocation: %#v", allocation)
	}
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the duplicate node egressIP should restore traffic to the broken namespace
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{},
	})
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// As above, but with a different node IP
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.5",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"release 172.17.0.100 on 172.17.0.3",
		"namespace 42 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the egress IP from the namespace and then adding it back should result
	// in it still being broken.
	eit.DeleteNetNamespaceEgress(42)
	err = w.assertChanges(
		"namespace 42 normal",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"namespace 42 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the original egress node should result in the "duplicate" egress node
	// now being used.
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{},
	})
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.5 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.5",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestDuplicateNamespaceEgressIPs(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	err := w.assertChanges(
		// after UpdateNamespaceEgress()
		"namespace 42 dropped",
		// after UpdateHostSubnetEgress()
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Adding the Egress IP to another namespace should not work and should cause both
	// namespaces to start dropping traffic.
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"release 172.17.0.100 on 172.17.0.3",
		"namespace 42 dropped",
		"namespace 43 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Auto-egress-IP assignment should ignore the IP while it is double-booked
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	err = w.assertChanges(
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	allocation := eit.ReallocateEgressIPs()
	if node5ips, ok := allocation["node-5"]; !ok {
		t.Fatalf("Unexpected IP allocation: %#v", allocation)
	} else if len(node5ips) != 0 {
		t.Fatalf("Unexpected IP allocation: %#v", allocation)
	}
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the duplicate should cause the original to start working again
	eit.DeleteNetNamespaceEgress(43)
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 43 normal",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Add duplicate back, re-breaking it
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	err = w.assertChanges(
		"release 172.17.0.100 on 172.17.0.3",
		"namespace 42 dropped",
		"namespace 43 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now remove and re-add the Node EgressIP; the namespace should stay broken
	// whether the IP is assigned to a node or not.
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Removing the egress IP from the original namespace should result in it being
	// given to the "duplicate" namespace
	eit.DeleteNetNamespaceEgress(42)
	err = w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 43",
		"namespace 42 normal",
		"namespace 43 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestOfflineEgressIPs(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.101"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100", "172.17.0.101"},
	})
	err := w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"claim 172.17.0.101 on 172.17.0.4 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the primary goes offline, just drop that one
	eit.SetNodeOffline("172.17.0.3", true)
	err = w.assertChanges(
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the secondary also goes offline, then we lose
	eit.SetNodeOffline("172.17.0.4", true)
	err = w.assertChanges(
		"namespace 42 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the secondary comes back, use it
	eit.SetNodeOffline("172.17.0.4", false)
	err = w.assertChanges(
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the primary comes back, use both
	eit.SetNodeOffline("172.17.0.3", false)
	err = w.assertChanges(
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"namespace 42 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the secondary goes offline now we do care
	eit.SetNodeOffline("172.17.0.4", true)
	err = w.assertChanges(
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func updateAllocations(eit *EgressIPTracker, allocation map[string][]string) {
	for nodeName, egressIPs := range allocation {
		for _, node := range eit.nodesByNodeIP {
			if node.nodeName == nodeName {
				ec := []osdnv1.HostSubnetEgressCIDR{}
				for _, cidr := range node.requestedCIDRs.List() {
					ec = append(ec, osdnv1.HostSubnetEgressCIDR(cidr))
				}
				updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
					Host:        nodeName,
					HostIP:      node.nodeIP,
					Subnet:      "10.128.0.0/23",
					EgressIPs:   StringsToHSEgressIPs(egressIPs),
					EgressCIDRs: ec,
				})
				break
			}
		}
	}
}

func TestEgressCIDRAllocationWithMultipleAssignmentOptions(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.3",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.4",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})
	err := w.assertChanges(
		"update egress CIDRs",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100", "172.17.0.101", "172.17.0.102"},
	})
	err = w.assertChanges(
		"namespace 42 dropped",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	allocation := eit.ReallocateEgressIPs()
	node3ips := allocation["node-3"]
	node4ips := allocation["node-4"]
	if len(node3ips) != 1 || len(node4ips) != 1 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
}

func TestEgressCIDRAllocation(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.3",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.100/32", "172.17.0.101/32", "172.17.0.102/32", "172.17.0.103/32", "172.17.1.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.4",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})
	err := w.assertChanges(
		"update egress CIDRs",
		"update egress CIDRs",
		// no "update egress CIDRs" for node-5 since it has no EgressCIDRs
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Either of these could be assigned to either node, but they should be balanced
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101"},
	})
	err = w.assertChanges(
		"namespace 42 dropped",
		"update egress CIDRs",
		"namespace 43 dropped",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	allocation := eit.ReallocateEgressIPs()
	node3ips := allocation["node-3"]
	node4ips := allocation["node-4"]
	if len(node3ips) != 1 || len(node4ips) != 1 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
	var n42, n43 string
	if node3ips[0] == "172.17.0.100" && node4ips[0] == "172.17.0.101" {
		n42 = "172.17.0.3"
		n43 = "172.17.0.4"
	} else if node3ips[0] == "172.17.0.101" && node4ips[0] == "172.17.0.100" {
		n42 = "172.17.0.4"
		n43 = "172.17.0.3"
	} else {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}

	updateAllocations(eit, allocation)
	err = w.assertChanges(
		fmt.Sprintf("claim 172.17.0.100 on %s for namespace 42", n42),
		fmt.Sprintf("namespace 42 via 172.17.0.100 on %s", n42),
		fmt.Sprintf("claim 172.17.0.101 on %s for namespace 43", n43),
		fmt.Sprintf("namespace 43 via 172.17.0.101 on %s", n43),
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// First can only be assigned to node3. Second *could* be assigned to either, but
	// must get assigned to node4 for balance
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     44,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.1.1"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     45,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.102"},
	})
	err = w.assertChanges(
		"namespace 44 dropped",
		"update egress CIDRs",
		"namespace 45 dropped",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	allocation = eit.ReallocateEgressIPs()
	updateAllocations(eit, allocation)
	err = w.assertChanges(
		"claim 172.17.1.1 on 172.17.0.3 for namespace 44",
		"namespace 44 via 172.17.1.1 on 172.17.0.3",
		"claim 172.17.0.102 on 172.17.0.4 for namespace 45",
		"namespace 45 via 172.17.0.102 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Manually assigning egress IPs to the node with no EgressCIDRs should have no
	// effect on automatic assignments (though it will result in a spurious "update
	// egress CIDRs" notification).
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:    "172.17.0.5",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.2.100"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     50,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.2.100"},
	})
	err = w.assertChanges(
		"claim 172.17.2.100 on 172.17.0.5 for namespace 50",
		"namespace 50 via 172.17.2.100 on 172.17.0.5",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	allocation = eit.ReallocateEgressIPs()
	updateAllocations(eit, allocation)
	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// First two can only be assigned to node4. Last must get assigned to node3 for balance
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     46,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.200"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     47,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.201"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     48,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.103"},
	})
	err = w.assertChanges(
		"namespace 46 dropped",
		"update egress CIDRs",
		"namespace 47 dropped",
		"update egress CIDRs",
		"namespace 48 dropped",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	allocation = eit.ReallocateEgressIPs()
	updateAllocations(eit, allocation)
	err = w.assertChanges(
		"claim 172.17.0.200 on 172.17.0.4 for namespace 46",
		"namespace 46 via 172.17.0.200 on 172.17.0.4",
		"claim 172.17.0.201 on 172.17.0.4 for namespace 47",
		"namespace 47 via 172.17.0.201 on 172.17.0.4",
		"claim 172.17.0.103 on 172.17.0.3 for namespace 48",
		"namespace 48 via 172.17.0.103 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Dropping an Egress CIDR will drop the Egress IP(s) that came from that CIDR.
	// If we then reallocate, the dropped Egress IP(s) might be allocated to new nodes.
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.3",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   StringsToHSEgressIPs(allocation["node-3"]),
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.100/32", "172.17.0.101/32", "172.17.0.102/32", "172.17.1.0/24"}, // removed "172.17.0.103/32"
	})
	err = w.assertChanges(
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	allocation = eit.ReallocateEgressIPs()
	updateAllocations(eit, allocation)
	err = w.assertChanges(
		"release 172.17.0.103 on 172.17.0.3",
		"namespace 48 dropped",
		// Now that the egress IP has been unassigned, the tracker sees that it
		// could be assigned to a new node.
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	allocation = eit.ReallocateEgressIPs()
	updateAllocations(eit, allocation)
	err = w.assertChanges(
		"claim 172.17.0.103 on 172.17.0.4 for namespace 48",
		"namespace 48 via 172.17.0.103 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Changing/Removing the EgressIPs of a namespace should drop the old allocation and create a new one
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     46,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.202"}, // was 172.17.0.200
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     44,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{}, // was 172.17.1.1
	})
	err = w.assertChanges(
		"release 172.17.0.200 on 172.17.0.4",
		"namespace 46 dropped",
		"update egress CIDRs",
		"release 172.17.1.1 on 172.17.0.3",
		"namespace 44 normal",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	allocation = eit.ReallocateEgressIPs()
	for _, nodeAllocation := range allocation {
		for _, ip := range nodeAllocation {
			if ip == "172.17.1.1" || ip == "172.17.0.200" {
				t.Fatalf("reallocation failed to drop unused egress IP %s: %#v", ip, allocation)
			}
		}
	}
	updateAllocations(eit, allocation)
	err = w.assertChanges(
		"claim 172.17.0.202 on 172.17.0.4 for namespace 46",
		"namespace 46 via 172.17.0.202 on 172.17.0.4",
		"update egress CIDRs",
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// The controller can auto-allocate multiple egress IPs to the same namespace
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     45,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.102", "172.17.1.102"}, // 172.17.0.102 is already allocated above
	})
	err = w.assertChanges(
		"update egress CIDRs",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	allocation = eit.ReallocateEgressIPs()
	updateAllocations(eit, allocation)
	err = w.assertChanges(
		"claim 172.17.1.102 on 172.17.0.3 for namespace 45",
		"namespace 45 via 172.17.0.102 on 172.17.0.4",
		"namespace 45 via 172.17.1.102 on 172.17.0.3",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestEgressNodeRenumbering(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:      "alpha",
		HostIP:    "172.17.0.3",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.100"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:      "beta",
		HostIP:    "172.17.0.4",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.101"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:      "gamma",
		HostIP:    "172.17.0.5",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.102"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     42,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     43,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101"},
	})

	err := w.assertChanges(
		"claim 172.17.0.100 on 172.17.0.3 for namespace 42",
		"namespace 42 via 172.17.0.100 on 172.17.0.3",
		"claim 172.17.0.101 on 172.17.0.4 for namespace 43",
		"namespace 43 via 172.17.0.101 on 172.17.0.4",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Renumber one of the hosts
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:      "beta",
		HostIP:    "172.17.0.6",
		Subnet:    "10.128.0.0/23",
		EgressIPs: []osdnv1.HostSubnetEgressIP{"172.17.0.101"},
	})
	err = w.assertChanges(
		"release 172.17.0.101 on 172.17.0.4",
		"namespace 43 dropped",
		"claim 172.17.0.101 on 172.17.0.6 for namespace 43",
		"namespace 43 via 172.17.0.101 on 172.17.0.6",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestEgressCIDRAllocationOffline(t *testing.T) {
	eit, w := setupEgressIPTracker(t, false)

	// Create nodes...
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.3",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24", "172.17.1.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.4",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		HostIP:      "172.17.0.5",
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.1.0/24"},
	})

	// Create namespaces
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     100,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.100"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     102,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.102"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     200,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.1.200"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     201,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.1.201"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     202,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.1.202"},
	})

	// In a perfect world, we'd get 2 IPs on each node, but depending on processing
	// order, this isn't guaranteed. Eg, if the three 172.17.0.x IPs get processed
	// first, we could get two of them on node-3 and one on node-4. Then the first two
	// 172.17.1.x IPs get assigned to node-5, and the last one could go to either
	// node-3 or node-5. Regardless of order, node-3 is guaranteed to get at least
	// two IPs since there's no way either node-4 or node-5 could be assigned a
	// third IP if node-3 still only had one.
	allocation := eit.ReallocateEgressIPs()
	node3ips := allocation["node-3"]
	node4ips := allocation["node-4"]
	node5ips := allocation["node-5"]
	if len(node3ips) < 2 || len(node4ips) == 0 || len(node5ips) == 0 ||
		len(node3ips)+len(node4ips)+len(node5ips) != 6 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
	updateAllocations(eit, allocation)

	w.flushChanges()

	// Now take node-3 offline
	eit.SetNodeOffline("172.17.0.3", true)
	err := w.assertUpdateEgressCIDRsNotification()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// First reallocation should empty out node-3
	allocation = eit.ReallocateEgressIPs()
	if node3ips, ok := allocation["node-3"]; !ok || len(node3ips) != 0 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
	updateAllocations(eit, allocation)

	err = w.assertUpdateEgressCIDRsNotification()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Next reallocation should reassign egress IPs to node-4 and node-5
	allocation = eit.ReallocateEgressIPs()
	node3ips = allocation["node-3"]
	node4ips = allocation["node-4"]
	node5ips = allocation["node-5"]
	if len(node3ips) != 0 || len(node4ips) != 3 || len(node5ips) != 3 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
	updateAllocations(eit, allocation)

	// Bring node-3 back
	eit.SetNodeOffline("172.17.0.3", false)
	err = w.assertUpdateEgressCIDRsNotification()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// First reallocation should remove some IPs from node-4 and node-5 but not add
	// them to node-3. As above, the "balanced" allocation we're aiming for may not
	// be perfect, but it has to be planning to assign at least 2 IPs to node-3.
	allocation = eit.ReallocateEgressIPs()
	node3ips = allocation["node-3"]
	node4ips = allocation["node-4"]
	node5ips = allocation["node-5"]
	if len(node3ips) != 0 || len(node4ips)+len(node5ips) > 4 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
	updateAllocations(eit, allocation)

	err = w.assertUpdateEgressCIDRsNotification()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Next reallocation should reassign the IPs that were removed in the previous
	// round. While the last reallocation was designed to aim for a next reallocation
	// where all of the removed IPs end up on node-3, it's possible 1 of them will
	// end up getting reallocated back to the same node it was removed from.
	allocation = eit.ReallocateEgressIPs()
	node3ips = allocation["node-3"]
	node4ips = allocation["node-4"]
	node5ips = allocation["node-5"]
	if len(node3ips) < 1 || len(node3ips) > 3 ||
		len(node4ips) < 1 || len(node4ips) > 3 ||
		len(node5ips) < 1 || len(node5ips) > 3 ||
		len(node3ips)+len(node4ips)+len(node5ips) != 6 {
		t.Fatalf("Bad IP allocation: %#v", allocation)
	}
	updateAllocations(eit, allocation)
}

func TestAutomaticEgressAllocationRespectingCapacityAndNamespaceBalancingWithFullAssignment(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 2
	node2Name, node2IP, node2Capacity := "node2", "172.17.0.2", 1
	egressIP1, egressIP2, egressIP3 := "172.17.0.101", "172.17.0.102", "172.17.0.103"

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node2Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node2IP,
				},
			},
		},
	}

	fClient := fakekubeclient.NewSimpleClientset(node1, node2)
	eit, _ := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{osdnv1.NetNamespaceEgressIP(egressIP1), osdnv1.NetNamespaceEgressIP(egressIP2)},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     103,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{osdnv1.NetNamespaceEgressIP(egressIP3)},
	})

	allocation := eit.ReallocateEgressIPs()
	// In the above case (the global amount of egress IPs requested can be
	// assigned given the cluster's overall capacity) there is only one optimal
	// solution, namely: obtaining a full assignment. This forces the solution
	// to be the following:
	if sets.NewString(allocation[node2Name]...).Has(egressIP3) {
		t.Fatalf("Unexpected sub-optimal solution, egress IP: %s, was assigned to node with smallest capacity", egressIP3)
	}
	if len(allocation[node1Name]) != 2 || len(allocation[node2Name]) != 1 {
		t.Fatalf("Unexpected sub-optimal solution, unexpected amount of allocations on egress nodes")
	}
}

func TestAutomaticEgressAllocationRespectingCapacityAndBalancedNamespaceAssignment(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 2
	node2Name, node2IP, node2Capacity := "node2", "172.17.0.2", 2
	node3Name, node3IP, node3Capacity := "node3", "172.17.0.3", 1
	egressIP1, egressIP2, egressIP3, egressIP4, egressIP5, egressIP6 := "172.17.0.101", "172.17.0.102", "172.17.0.103", "172.17.0.104", "172.17.0.105", "172.17.0.106"

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node2Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node2IP,
				},
			},
		},
	}
	node3 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node3Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node3Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node3IP,
				},
			},
		},
	}

	fClient := fakekubeclient.NewSimpleClientset(node1, node2, node3)

	eit, _ := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node3Name,
		HostIP:      node3IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP1),
			osdnv1.NetNamespaceEgressIP(egressIP2),
			osdnv1.NetNamespaceEgressIP(egressIP3),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 102,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP4),
			osdnv1.NetNamespaceEgressIP(egressIP5),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 103,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP6),
		},
	})

	allocation := eit.ReallocateEgressIPs()
	// In the case above (where the amount of requested egress IPs superseed the
	// cluster's global capacity) there is again only one optimal solution,
	// namely: assigning all but one egress IP, and making sure all namespaces
	// get a fair assignment of its requested IPs, fair meaning: we assigning as
	// many as we can from all namespaces and have the left-out egress IP being
	// one from the namespace that requests the most multiple. That means that
	// the solution must be:
	if getAllAssignedEgressIPs(allocation).HasAll(egressIP1, egressIP2, egressIP3) {
		t.Fatalf("Unexpected sub-optimal solution, namespace with the most requested IPs, got all assigned")
	}
	if len(allocation[node1Name]) != 2 || len(allocation[node2Name]) != 2 || len(allocation[node3Name]) != 1 {
		t.Fatalf("Unexpected sub-optimal solution, unexpected amount of allocations on egress nodes")
	}
}

func TestAutomaticEgressAllocationRespectingCapacityAndBalancedNamespaceAssignmentForAFullyConstraintProblem(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 1
	node2Name, node2IP, node2Capacity := "node2", "172.17.0.2", 1
	node3Name, node3IP, node3Capacity := "node3", "172.17.0.3", 1
	egressIP1, egressIP2, egressIP3, egressIP4, egressIP5, egressIP6 := "172.17.0.101", "172.17.0.102", "172.17.0.103", "172.17.0.104", "172.17.0.105", "172.17.0.106"

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node2Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node2IP,
				},
			},
		},
	}
	node3 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node3Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node3Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node3IP,
				},
			},
		},
	}

	fClient := fakekubeclient.NewSimpleClientset(node1, node2, node3)

	eit, _ := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node3Name,
		HostIP:      node3IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP1),
			osdnv1.NetNamespaceEgressIP(egressIP2),
			osdnv1.NetNamespaceEgressIP(egressIP3),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 102,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP4),
			osdnv1.NetNamespaceEgressIP(egressIP5),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 103,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP6),
		},
	})

	allocation := eit.ReallocateEgressIPs()
	// In the case above we need to make sure all namespaces get at least one IP
	// assigned.
	if !getAllAssignedEgressIPs(allocation).HasAll(egressIP1, egressIP4, egressIP6) {
		t.Fatalf("Unexpected sub-optimal solution, one IP from every namespace was not assigned")
	}
	if len(allocation[node1Name]) != 1 || len(allocation[node2Name]) != 1 || len(allocation[node3Name]) != 1 {
		t.Fatalf("Unexpected sub-optimal solution, unexpected amount of allocations on egress nodes")
	}
}

func TestAutomaticEgressAllocationRespectingCapacityAndConsistentFullGlobalAssignment(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 2
	node2Name, node2IP, node2Capacity := "node2", "172.17.0.2", 1
	egressIP1, egressIP2, egressIP3, egressIP4, egressIP5 := "172.17.0.101", "172.17.0.102", "172.17.0.103", "172.17.0.104", "172.17.0.105"

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node2Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node2IP,
				},
			},
		},
	}

	fClient := fakekubeclient.NewSimpleClientset(node1, node2)
	eit, _ := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/24"},
	})

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 100,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP1),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP2),
		},
	})

	allocation := eit.ReallocateEgressIPs()
	// Simple case: both IPs should be assigned to different nodes
	if len(allocation[node1Name]) != 1 || len(allocation[node2Name]) != 1 {
		t.Fatalf("Unexpected amount of allocations on egress nodes")
	}

	updateAllocations(eit, allocation)
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP2),
			osdnv1.NetNamespaceEgressIP(egressIP3),
		},
	})

	allocation = eit.ReallocateEgressIPs()
	// We can't verify the amount of allocations on each node determinstically,
	// because this depends on how things have been assigned in the previous
	// round of assignment, so verify some basic conditions that **must** hold
	// true
	if !getAllAssignedEgressIPs(allocation).Has(egressIP1) {
		t.Fatalf("Unexpected allocations on egress nodes, namespace 100 is missing its requested egress IP")
	}
	if !getAllAssignedEgressIPs(allocation).HasAny(egressIP2, egressIP3) {
		t.Fatalf("Unexpected allocations on egress nodes, namespace 101 is missing both of its requested egress IPs")
	}

	updateAllocations(eit, allocation)
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     100,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{},
	})

	allocation = eit.ReallocateEgressIPs()
	// We can verify the amount of allocations deterministally because this is a
	// simple case where all IPs can be assigned without any heuristics, i.e:
	// there is place for both IPs everywhere and assignment strategy (the way
	// you assign IPs) has no effect on the final outcome.
	if len(allocation[node1Name]) != 1 || len(allocation[node2Name]) != 1 {
		t.Fatalf("Unexpected amount of allocations on egress nodes")
	}

	updateAllocations(eit, allocation)
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 100,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP1),
			osdnv1.NetNamespaceEgressIP(egressIP4),
			osdnv1.NetNamespaceEgressIP(egressIP5),
		},
	})

	allocation = eit.ReallocateEgressIPs()
	// We can verify the amount of assignments deterministically because we know
	// we had both IPs from namespace 101 assigned to both nodes in the previous
	// round, hence: as there is only room for one more IP from namespace 100,
	// we know where it will go.
	if len(allocation[node1Name]) != 2 || len(allocation[node2Name]) != 1 {
		t.Fatalf("Unexpected amount of allocations on egress nodes")
	}
	if !getAllAssignedEgressIPs(allocation).HasAll(egressIP2, egressIP3) {
		t.Fatalf("Unexpected sub-optimal solution, existing allocations: %s and %s have been moved in favour of new ones, though that was not necessary", egressIP2, egressIP3)
	}

	updateAllocations(eit, allocation)
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP2),
		},
	})

	allocation = eit.ReallocateEgressIPs()
	// Again: we can't verify the amount of assignments deterministically
	// because things depend on how things have been assigned up until this
	// point. EgressIP2 needs to remain assigned though.
	if !sets.NewString(allocation[node1Name]...).Has(egressIP2) && !sets.NewString(allocation[node2Name]...).Has(egressIP2) {
		t.Fatalf("Unexpected removal of the only egress IP requested by one namespace")
	}
}

func TestAutomaticEgressAllocationRespectingAvailability(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 3
	node2Name, node2IP, node2Capacity := "node2", "172.17.0.2", 6
	egressIP1, egressIP2, egressIP3, egressIP4, egressIP5, egressIP6 := "172.17.0.55", "172.17.0.56", "172.17.0.57", "172.17.0.58", "172.17.0.59", "172.17.0.5"

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node2Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node2IP,
				},
			},
		},
	}

	fClient := fakekubeclient.NewSimpleClientset(node1, node2)

	eit, _ := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/29"},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/26"},
	})

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 100,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP1),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP2),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 102,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP3),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 103,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP4),
		},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 104,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP5),
		},
	})

	allocation := eit.ReallocateEgressIPs()
	// Since all IPs can only be assigned to node two, and node two has capacity
	// to host them, they should go there.
	if len(allocation[node2Name]) != 5 {
		t.Fatalf("Unexpected amount of allocations on egress node two")
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID: 105,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{
			osdnv1.NetNamespaceEgressIP(egressIP6),
		},
	})

	allocation = eit.ReallocateEgressIPs()

	// The last IP can be assigned to both nodes, but should be preferred on
	// node one since it has less allocations and is more "available" (capacity
	// - current assignments)
	if len(allocation[node1Name]) != 1 && len(allocation[node2Name]) != 5 {
		t.Fatalf("Unexpected amount of allocations on egress nodes")
	}
}

func TestManualEgressAllocationRespectingCapacity(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 2
	node2Name, node2IP, node2Capacity := "node2", "172.17.0.2", 1

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.0/23"}}]`, node2Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node2IP,
				},
			},
		},
	}
	fClient := fakekubeclient.NewSimpleClientset(node1, node2)

	eit, w := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})
	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})

	// No namespaces use egress yet, hence no changes
	err := w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     100,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.101", "172.17.0.103"},
	})
	updateNetNamespaceEgress(eit, &osdnv1.NetNamespace{
		NetID:     101,
		EgressIPs: []osdnv1.NetNamespaceEgressIP{"172.17.0.102", "172.17.0.104"},
	})

	// No namespaces use egress yet, hence no changes
	err = w.assertChanges(
		"namespace 100 dropped",
		"namespace 101 dropped",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{"172.17.0.101"},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})

	// First namespace get assigned first IP
	err = w.assertChanges(
		"claim 172.17.0.101 on 172.17.0.2 for namespace 100",
		"namespace 100 via 172.17.0.101 on 172.17.0.2",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{"172.17.0.102"},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})

	// Second namespace get assigned first IP
	err = w.assertChanges(
		"claim 172.17.0.102 on 172.17.0.1 for namespace 101",
		"namespace 101 via 172.17.0.102 on 172.17.0.1",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Two egress IPs on node 2 superseeds its capacity, hence is illegal. But
	// call handleAddOrUpdateHostSubnet since that will perform the validation
	// of user input in manual assignment mode and is hence what should reject
	// the change.
	eit.handleAddOrUpdateHostSubnet(&osdnv1.HostSubnet{
		ObjectMeta: v1.ObjectMeta{
			Name: node2Name,
			UID:  ktypes.UID(node2Name),
		},
		Host:        node2Name,
		HostIP:      node2IP,
		Subnet:      "10.129.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{"172.17.0.101", "172.17.0.104"},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	}, nil, watch.Modified)

	err = w.assertNoChanges()
	if err != nil {
		t.Fatalf("%v", err)
	}

	updateHostSubnetEgress(eit, &osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{"172.17.0.102", "172.17.0.103"},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{},
	})

	// Second namespace gets assigned second IP, since node 1 still has space
	// for it.
	err = w.assertChanges(
		"claim 172.17.0.103 on 172.17.0.1 for namespace 100",
		"namespace 100 via 172.17.0.103 on 172.17.0.1",
		"namespace 100 via 172.17.0.101 on 172.17.0.2",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestValidEgressCIDRsForCloudNodes(t *testing.T) {
	node1Name, node1IP, node1Capacity := "node1", "172.17.0.1", 2

	node1 := &corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: node1Name,
			Annotations: map[string]string{
				nodeEgressIPConfigAnnotationKey: fmt.Sprintf(`[{"capacity":{"ipv4":%v}, "ifaddr": {"ipv4": "172.17.0.2/23"}}]`, node1Capacity),
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: node1IP,
				},
			},
		},
	}

	fClient := fakekubeclient.NewSimpleClientset(node1)

	eit, _ := setupEgressIPTracker(t, true)
	eit.kubeClient = fClient

	// Fully within the cloud network, no error
	err := eit.validateEgressCIDRsAreSubnetOfCloudNetwork(&osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/26"},
	})
	if err != nil {
		t.Fatalf("EgressCIDR is fully within cloud network, but failed, err: %v", err)
	}

	// Overlaps and is greater than the cloud network, error
	err = eit.validateEgressCIDRsAreSubnetOfCloudNetwork(&osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.17.0.0/22"},
	})
	if err == nil {
		t.Fatalf("EgressCIDR is greater than the cloud network, should fail")
	}

	// Does not overlap the cloud network at all, error
	err = eit.validateEgressCIDRsAreSubnetOfCloudNetwork(&osdnv1.HostSubnet{
		Host:        node1Name,
		HostIP:      node1IP,
		Subnet:      "10.128.0.0/23",
		EgressIPs:   []osdnv1.HostSubnetEgressIP{},
		EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"172.18.0.0/23"},
	})
	if err == nil {
		t.Fatalf("EgressCIDR does not overlap the cloud network, should fail")
	}
}

func getAllAssignedEgressIPs(allocation map[string][]string) sets.String {
	assignedEgressIPs := sets.NewString()
	for _, nodeAllocations := range allocation {
		assignedEgressIPs.Insert(nodeAllocations...)
	}
	return assignedEgressIPs
}
