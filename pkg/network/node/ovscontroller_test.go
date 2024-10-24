package node

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/util/ovs"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/containernetworking/plugins/pkg/utils/hwaddr"
)

func setupOVSController(t *testing.T) (ovs.Interface, *ovsController, []string) {
	ovsif := ovs.NewFake(Br0)
	oc := NewOVSController(ovsif, 0, "172.17.0.4", "00:09:dc:a4:5e:a3")
	oc.tunMAC = "c6:ac:2c:13:48:4b"
	err := oc.SetupOVS([]string{"10.128.0.0/14"}, "172.30.0.0/16", "10.128.0.0/23", "10.128.0.1", 1450, 4789)
	if err != nil {
		t.Fatalf("Unexpected error setting up OVS: %v", err)
	}
	err = oc.FinishSetupOVS()
	if err != nil {
		t.Fatalf("Unexpected error setting up OVS: %v", err)
	}

	origFlows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}

	return ovsif, oc, origFlows
}

type flowChangeKind string

const (
	flowAdded   flowChangeKind = "added"
	flowRemoved flowChangeKind = "removed"
)

type flowChange struct {
	kind    flowChangeKind
	match   []string
	noMatch []string
}

// assertFlowChanges asserts that origFlows and newFlows differ in the ways described by
// changes, which consists of a series of flows that have been removed from origFlows or
// added to newFlows. There must be exactly 1 matching flow that contains all of the
// strings in match and none of the strings in noMatch.
func assertFlowChanges(origFlows, newFlows []string, changes ...flowChange) error {
	err := findFlowChangesInternal(origFlows, newFlows, changes...)
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v\n%s", err, diffFlows(origFlows, newFlows))
}

func findFlowChangesInternal(origFlows, newFlows []string, changes ...flowChange) error {
	// copy to avoid modifying originals
	dup := make([]string, 0, len(origFlows))
	origFlows = append(dup, origFlows...)
	dup = make([]string, 0, len(newFlows))
	newFlows = append(dup, newFlows...)

	for _, change := range changes {
		var modFlows *[]string
		if change.kind == flowAdded {
			modFlows = &newFlows
		} else {
			modFlows = &origFlows
		}

		matchIndex := -1
		for i, flow := range *modFlows {
			matches := true
			for _, match := range change.match {
				if !strings.Contains(flow, match) {
					matches = false
					break
				}
			}
			for _, nonmatch := range change.noMatch {
				if strings.Contains(flow, nonmatch) {
					matches = false
					break
				}
			}
			if matches {
				if matchIndex == -1 {
					matchIndex = i
				} else {
					return fmt.Errorf("multiple %s flows matching %#v", string(change.kind), change.match)
				}
			}
		}
		if matchIndex == -1 {
			return fmt.Errorf("no %s flow matching %#v", string(change.kind), change.match)
		}
		*modFlows = append((*modFlows)[:matchIndex], (*modFlows)[matchIndex+1:]...)
	}

	if !reflect.DeepEqual(origFlows, newFlows) {
		return fmt.Errorf("unexpected additional changes to flows")
	}
	return nil
}

func diffFlows(origFlows, newFlows []string) string {
	orig, err := ioutil.TempFile("", "flows-orig-")
	if err != nil {
		return err.Error()
	}
	_, err = io.WriteString(orig, strings.Join(origFlows, "\n"))
	if err != nil {
		return err.Error()
	}
	_, err = io.WriteString(orig, "\n")
	if err != nil {
		return err.Error()
	}
	_ = orig.Close()

	new, err := ioutil.TempFile("", "flows-new-")
	if err != nil {
		return err.Error()
	}
	_, err = io.WriteString(new, strings.Join(newFlows, "\n"))
	if err != nil {
		return err.Error()
	}
	_, err = io.WriteString(new, "\n")
	if err != nil {
		return err.Error()
	}
	_ = new.Close()

	output, _ := exec.Command("diff", "-u", orig.Name(), new.Name()).CombinedOutput()
	return string(output)
}

const (
	sandboxID string = "bcb5d8d287fcf97458c48ad643b101079e3bc265a94e097e7407440716112f69"
)

func TestOVSPod(t *testing.T) {
	ovsif, oc, origFlows := setupOVSController(t)

	// Add
	ofport, err := oc.SetUpPod(sandboxID, "veth1", net.ParseIP("10.128.0.2"), 42)
	if err != nil {
		t.Fatalf("Unexpected error adding pod rules: %v", err)
	}

	flows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=20", fmt.Sprintf("in_port=%d", ofport), "arp", "10.128.0.2", "00:00:0a:80:00:02/00:00:ff:ff:ff:ff"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=20", fmt.Sprintf("in_port=%d", ofport), "ip", "10.128.0.2", "42->NXM_NX_REG0"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=25", "ip", "10.128.0.2", "42->NXM_NX_REG0"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=40", "arp", "10.128.0.2", fmt.Sprintf("output:%d", ofport)},
			noMatch: []string{"reg0=42"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=70", "ip", "10.128.0.2", "42->NXM_NX_REG1", fmt.Sprintf("%d->NXM_NX_REG2", ofport)},
			noMatch: []string{"reg0=42"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Update
	err = oc.UpdatePod(sandboxID, 43)
	if err != nil {
		t.Fatalf("Unexpected error updating pod rules: %v", err)
	}

	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=20", fmt.Sprintf("in_port=%d", ofport), "arp", "10.128.0.2", "00:00:0a:80:00:02/00:00:ff:ff:ff:ff"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=20", fmt.Sprintf("in_port=%d", ofport), "ip", "10.128.0.2", "43->NXM_NX_REG0"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=25", "ip", "10.128.0.2", "43->NXM_NX_REG0"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=40", "arp", "10.128.0.2", fmt.Sprintf("output:%d", ofport)},
			noMatch: []string{"reg0=43"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=70", "ip", "10.128.0.2", "43->NXM_NX_REG1", fmt.Sprintf("%d->NXM_NX_REG2", ofport)},
			noMatch: []string{"reg0=43"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Delete
	err = oc.TearDownPod(sandboxID)
	if err != nil {
		t.Fatalf("Unexpected error deleting pod rules: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes

	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
}

func TestGetPodDetails(t *testing.T) {
	type testcase struct {
		sandboxID string
		ip        string
		errStr    string
	}

	testcases := []testcase{
		{
			sandboxID: sandboxID,
			ip:        "10.130.0.2",
		},
	}

	for _, tc := range testcases {
		_, oc, _ := setupOVSController(t)
		tcOFPort, err := oc.SetUpPod(tc.sandboxID, "veth1", net.ParseIP(tc.ip), 42)
		if err != nil {
			t.Fatalf("Unexpected error adding pod rules: %v", err)
		}

		ofport, ip, err := oc.getPodDetailsBySandboxID(tc.sandboxID)
		if err != nil {
			if tc.errStr != "" {
				if !strings.Contains(err.Error(), tc.errStr) {
					t.Fatalf("unexpected error %v (expected %q)", err, tc.errStr)
				}
			} else {
				t.Fatalf("unexpected failure %v", err)
			}
		} else if tc.errStr != "" {
			t.Fatalf("expected error %q", tc.errStr)
		}
		if ofport != tcOFPort {
			t.Fatalf("unexpected ofport %d (expected %d)", ofport, tcOFPort)
		}
		if ip.String() != tc.ip {
			t.Fatalf("unexpected ip %q (expected %q)", ip.String(), tc.ip)
		}
	}
}

func TestOVSLocalMulticast(t *testing.T) {
	ovsif, oc, origFlows := setupOVSController(t)

	err := oc.UpdateLocalMulticastFlows(99, true, []int{4, 5, 6})
	if err != nil {
		t.Fatalf("Unexpected error adding multicast flows: %v", err)
	}
	flows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=110", "reg0=99", "goto_table:111"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=120", "reg0=99", "output:4,output:5,output:6"},
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	err = oc.UpdateLocalMulticastFlows(88, false, []int{7, 8})
	if err != nil {
		t.Fatalf("Unexpected error adding multicast flows: %v", err)
	}
	lastFlows := flows
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(lastFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	err = oc.UpdateLocalMulticastFlows(99, false, []int{4, 5})
	if err != nil {
		t.Fatalf("Unexpected error adding multicast flows: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertFlowChanges(origFlows, flows) // no changes
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
}

var enp1 = osdnv1.EgressNetworkPolicy{
	TypeMeta: metav1.TypeMeta{
		Kind: "EgressNetworkPolicy",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name: "enp1",
	},
	Spec: osdnv1.EgressNetworkPolicySpec{
		Egress: []osdnv1.EgressNetworkPolicyRule{
			{
				Type: osdnv1.EgressNetworkPolicyRuleAllow,
				To: osdnv1.EgressNetworkPolicyPeer{
					CIDRSelector: "192.168.0.0/16",
				},
			},
			{
				Type: osdnv1.EgressNetworkPolicyRuleDeny,
				To: osdnv1.EgressNetworkPolicyPeer{
					CIDRSelector: "192.168.1.0/24",
				},
			},
			{
				Type: osdnv1.EgressNetworkPolicyRuleAllow,
				To: osdnv1.EgressNetworkPolicyPeer{
					CIDRSelector: "192.168.1.1/32",
				},
			},
		},
	},
}

var enp2 = osdnv1.EgressNetworkPolicy{
	TypeMeta: metav1.TypeMeta{
		Kind: "EgressNetworkPolicy",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name: "enp2",
	},
	Spec: osdnv1.EgressNetworkPolicySpec{
		Egress: []osdnv1.EgressNetworkPolicyRule{
			{
				Type: osdnv1.EgressNetworkPolicyRuleAllow,
				To: osdnv1.EgressNetworkPolicyPeer{
					CIDRSelector: "192.168.1.0/24",
				},
			},
			{
				Type: osdnv1.EgressNetworkPolicyRuleAllow,
				To: osdnv1.EgressNetworkPolicyPeer{
					CIDRSelector: "192.168.2.0/24",
				},
			},
			{
				Type: osdnv1.EgressNetworkPolicyRuleDeny,
				To: osdnv1.EgressNetworkPolicyPeer{
					// "/32" is wrong but accepted for backward-compatibility
					CIDRSelector: "0.0.0.0/32",
				},
			},
		},
	},
}

var enpDenyAll = osdnv1.EgressNetworkPolicy{
	TypeMeta: metav1.TypeMeta{
		Kind: "EgressNetworkPolicy",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name: "enpDenyAll",
	},
	Spec: osdnv1.EgressNetworkPolicySpec{
		Egress: []osdnv1.EgressNetworkPolicyRule{
			{
				Type: osdnv1.EgressNetworkPolicyRuleDeny,
				To: osdnv1.EgressNetworkPolicyPeer{
					CIDRSelector: "0.0.0.0/0",
				},
			},
		},
	},
}

type enpFlowAddition struct {
	policy *osdnv1.EgressNetworkPolicy
	vnid   int
}

func assertENPFlowAdditions(origFlows, newFlows []string, additions ...enpFlowAddition) error {
	changes := make([]flowChange, 0)
	for _, addition := range additions {
		for i, rule := range addition.policy.Spec.Egress {
			var change flowChange
			change.kind = flowAdded
			change.match = []string{
				"table=100",
				fmt.Sprintf("reg0=%d", addition.vnid),
				fmt.Sprintf("priority=%d", len(addition.policy.Spec.Egress)-i),
			}
			if rule.To.CIDRSelector == "0.0.0.0/0" || rule.To.CIDRSelector == "0.0.0.0/32" {
				change.noMatch = []string{"nw_dst"}
			} else {
				change.match = append(change.match, fmt.Sprintf("nw_dst=%s", rule.To.CIDRSelector))
			}
			if rule.Type == osdnv1.EgressNetworkPolicyRuleAllow {
				change.match = append(change.match, "actions=goto_table:101")
			} else {
				change.match = append(change.match, "actions=drop")
			}
			changes = append(changes, change)
		}
	}

	return assertFlowChanges(origFlows, newFlows, changes...)
}

func TestOVSEgressNetworkPolicy(t *testing.T) {
	ovsif, oc, origFlows := setupOVSController(t)

	// SUCCESSFUL CASES

	// Set one EgressNetworkPolicy on VNID 42
	err := oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp1},
		42,
		[]string{"ns1"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp1,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Set one EgressNetworkPolicy on VNID 43
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp2},
		43,
		[]string{"ns2"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp1,
		},
		enpFlowAddition{
			vnid:   43,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Change VNID 42 from ENP1 to ENP2
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp2},
		42,
		[]string{"ns1"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
		enpFlowAddition{
			vnid:   43,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Drop EgressNetworkPolicy from VNID 43
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{},
		43,
		[]string{"ns2"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Set no EgressNetworkPolicy on VNID 0
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{},
		0,
		[]string{"default", "my-global-project"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Set no EgressNetworkPolicy on a shared namespace
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{},
		44,
		[]string{"ns3", "ns4"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// ERROR CASES

	// Can't set non-empty ENP in default namespace
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp1},
		0,
		[]string{"default"},
		nil,
	)
	if err == nil {
		t.Fatalf("Unexpected lack of error updating egress network policy")
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Can't set non-empty ENP in a shared namespace
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp1},
		45,
		[]string{"ns3", "ns4"},
		nil,
	)
	if err == nil {
		t.Fatalf("Unexpected lack of error updating egress network policy")
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
		enpFlowAddition{
			vnid:   45,
			policy: &enpDenyAll,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// Can't set multiple policies
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp1, enp2},
		46,
		[]string{"ns5"},
		nil,
	)
	if err == nil {
		t.Fatalf("Unexpected lack of error updating egress network policy")
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
		enpFlowAddition{
			vnid:   45,
			policy: &enpDenyAll,
		},
		enpFlowAddition{
			vnid:   46,
			policy: &enpDenyAll,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	// CLEARING ERRORS

	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{},
		45,
		[]string{"ns3", "ns4"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
		enpFlowAddition{
			vnid:   46,
			policy: &enpDenyAll,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}

	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{},
		46,
		[]string{"ns5"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}
	flows, err = ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	err = assertENPFlowAdditions(origFlows, flows,
		enpFlowAddition{
			vnid:   42,
			policy: &enp2,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected flow changes: %v", err)
	}
}

func TestAlreadySetUp(t *testing.T) {
	testcases := []struct {
		flow    string
		success bool
	}{
		{
			// Good note
			flow:    fmt.Sprintf("cookie=0x0, duration=4.796s, table=253, n_packets=0, n_bytes=0, actions=note:00.%02x.00.00.00.00", ruleVersion),
			success: true,
		},
		{
			// Wrong version
			flow:    fmt.Sprintf("cookie=0x0, duration=4.796s, table=253, n_packets=0, n_bytes=0, actions=note:00.%02x.00.00.00.00", ruleVersion-1),
			success: false,
		},
		{
			// Wrong table
			flow:    fmt.Sprintf("cookie=0x0, duration=4.796s, table=10, n_packets=0, n_bytes=0, actions=note:00.%02x.00.00.00.00", ruleVersion),
			success: false,
		},
		{
			// No note
			flow:    "cookie=0x0, duration=4.796s, table=253, n_packets=0, n_bytes=0, actions=goto_table:50",
			success: false,
		},
	}

	for i, tc := range testcases {
		ovsif := ovs.NewFake(Br0)
		if err := ovsif.AddBridge("fail_mode=secure", "protocols=OpenFlow13"); err != nil {
			t.Fatalf("(%d) unexpected error from AddBridge: %v", i, err)
		}
		oc := NewOVSController(ovsif, 0, "172.17.0.4", "00:09:dc:a4:5e:a3")
		/* In order to test AlreadySetUp the vxlan port has to be added, we are not testing AddPort here */
		_, err := ovsif.AddPort("vxlan0", 1, "type=vxlan", `options:remote_ip="flow"`, `options:key="flow"`, fmt.Sprintf("options:dst_port=%d", 4789))
		if err != nil {
			t.Fatalf("(%d) unexpected error from AddPort: %v", i, err)
		}

		otx := ovsif.NewTransaction()
		otx.AddFlow(tc.flow)
		if err := otx.Commit(); err != nil {
			t.Fatalf("(%d) unexpected error from AddFlow: %v", i, err)
		}
		if success := oc.AlreadySetUp(4789); success != tc.success {
			t.Fatalf("(%d) unexpected setup value %v (expected %v)", i, success, tc.success)
		}
	}
}

func TestFindUnusedVNIDs(t *testing.T) {
	testcases := []struct {
		flows  []string
		policy []int
		unused []int
	}{
		{
			/* VNID 0 is never unused, even if there are no table 70 rules for it */
			flows: []string{
				"table=70,priority=100,ip,nw_dst=10.129.0.2 actions=load:0x55fac->NXM_NX_REG1[],load:0x3->NXM_NX_REG2[],goto_table:80",
				"table=70,priority=100,ip,nw_dst=10.129.0.3 actions=load:0xcb81e9->NXM_NX_REG1[],load:0x4->NXM_NX_REG2[],goto_table:80",
				"table=70,priority=0 actions=drop",
				"table=80,priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg0=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg1=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0x55fac,reg1=0x55fac actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0xcb81e9,reg1=0xcb81e9 actions=output:NXM_NX_REG2[]",
				"table=80,priority=0 actions=drop",
			},
			policy: []int{0x0, 0x55fac, 0xcb81e9},
			unused: []int{},
		},
		{
			/* Both VNIDs have 1 pod, so they stay */
			flows: []string{
				"table=70,priority=100,ip,nw_dst=10.129.0.2 actions=load:0x55fac->NXM_NX_REG1[],load:0x3->NXM_NX_REG2[],goto_table:80",
				"table=70,priority=100,ip,nw_dst=10.129.0.3 actions=load:0xcb81e9->NXM_NX_REG1[],load:0x4->NXM_NX_REG2[],goto_table:80",
				"table=70,priority=0 actions=drop",
				"table=80,priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg0=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg1=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0x55fac,reg1=0x55fac actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0xcb81e9,reg1=0xcb81e9 actions=output:NXM_NX_REG2[]",
				"table=80,priority=0 actions=drop",
			},
			policy: []int{0x0, 0x55fac, 0xcb81e9},
			unused: []int{},
		},
		{
			/* 0xcb81e9 gets GCed, 0x55fac stays */
			flows: []string{
				"table=70,priority=100,ip,nw_dst=10.129.0.2 actions=load:0x55fac->NXM_NX_REG1[],load:0x3->NXM_NX_REG2[],goto_table:80",
				"table=70,priority=0 actions=drop",
				"table=80,priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg0=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg1=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0x55fac,reg1=0x55fac actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0xcb81e9,reg1=0xcb81e9 actions=output:NXM_NX_REG2[]",
				"table=80,priority=0 actions=drop",
			},
			policy: []int{0x0, 0x55fac, 0xcb81e9},
			unused: []int{0xcb81e9},
		},
		{
			/* Both get GCed */
			flows: []string{
				"table=70,priority=0 actions=drop",
				"table=80,priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg0=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg1=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0x55fac,reg1=0x55fac actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0xcb81e9,reg1=0xcb81e9 actions=output:NXM_NX_REG2[]",
				"table=80,priority=0 actions=drop",
			},
			policy: []int{0x0, 0x55fac, 0xcb81e9},
			unused: []int{0x55fac, 0xcb81e9},
		},
		{
			/* Invalid state; we lost the 0x55fac policy rules somehow. But we should still notice that 0xcb81e9 is unused. */
			flows: []string{
				"table=70,priority=100,ip,nw_dst=10.129.0.2 actions=load:0x55fac->NXM_NX_REG1[],load:0x3->NXM_NX_REG2[],goto_table:80",
				"table=70,priority=0 actions=drop",
				"table=80,priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg0=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=200,reg1=0 actions=output:NXM_NX_REG2[]",
				"table=80,priority=100,reg0=0xcb81e9,reg1=0xcb81e9 actions=output:NXM_NX_REG2[]",
				"table=80,priority=0 actions=drop",
			},
			policy: []int{0x0, 0xcb81e9},
			unused: []int{0xcb81e9},
		},
	}

	for i, tc := range testcases {
		_, oc, _ := setupOVSController(t)

		otx := oc.NewTransaction()
		for _, flow := range tc.flows {
			otx.AddFlow(flow)
		}
		if err := otx.Commit(); err != nil {
			t.Fatalf("(%d) unexpected error from AddFlow: %v", i, err)
		}

		unused := oc.FindUnusedVNIDs()
		sort.Ints(unused)
		if !reflect.DeepEqual(unused, tc.unused) {
			t.Fatalf("(%d) wrong result for unused, expected %v, got %v", i, tc.unused, unused)
		}
	}
}

func TestFindPolicyVNIDs(t *testing.T) {
	testcases := []struct {
		flows       []string
		policyVNIDs sets.Int
	}{
		{
			// No rules -> no VNIDs
			flows: []string{
				"table=80,priority=0 actions=drop",
			},
			policyVNIDs: sets.NewInt(),
		},
		{
			// Namespaces without any rule on table 80 must be present.
			flows: []string{
				"table=60, priority=200 actions=output:tun0",
				"table=60, priority=0 actions=drop",
				"table=70, priority=100,ip,nw_dst=10.129.0.52 actions=load:0x2bd973->NXM_NX_REG1[],load:0x15->NXM_NX_REG2[],goto_table:80",
				"table=70, priority=100,ip,nw_dst=10.129.0.53 actions=load:0x0->NXM_NX_REG1[],load:0x16->NXM_NX_REG2[],goto_table:80",
				"table=70, priority=0 actions=drop",
				"table=80, priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80, priority=200,ct_state=+rpl,ip actions=output:NXM_NX_REG2[]",
				"table=80, priority=0 actions=drop",
			},
			policyVNIDs: sets.NewInt(0x0, 0x2bd973),
		},
		{
			// Namespaces present in table 80 must always be present, even if they don't have pods
			flows: []string{
				"table=80, priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80, priority=200,ct_state=+rpl,ip actions=output:NXM_NX_REG2[]",
				"table=80, priority=50,reg1=0x58bb64 actions=output:NXM_NX_REG2[]",
				"table=80, priority=50,reg1=0x0 actions=output:NXM_NX_REG2[]",
				"table=80, priority=0 actions=drop",
			},
			policyVNIDs: sets.NewInt(0x0, 0x58bb64),
		},
		{
			// All tests combined
			flows: []string{
				"table=60, priority=200 actions=output:tun0",
				"table=60, priority=0 actions=drop",
				"table=70, priority=100,ip,nw_dst=10.129.0.52 actions=load:0x2bd973->NXM_NX_REG1[],load:0x15->NXM_NX_REG2[],goto_table:80",
				"table=70, priority=100,ip,nw_dst=10.129.0.54 actions=load:0x58bb64->NXM_NX_REG1[],load:0x17->NXM_NX_REG2[],goto_table:80",
				"table=70, priority=0 actions=drop",
				"table=80, priority=300,ip,nw_src=10.129.0.1 actions=output:NXM_NX_REG2[]",
				"table=80, priority=200,ct_state=+rpl,ip actions=output:NXM_NX_REG2[]",
				"table=80, priority=50,reg1=0x58bb64 actions=output:NXM_NX_REG2[]",
				"table=80, priority=50,reg1=0x243c14 actions=output:NXM_NX_REG2[]",
				"table=80, priority=0 actions=drop",
			},
			policyVNIDs: sets.NewInt(0x2bd973, 0x58bb64, 0x243c14),
		},
	}

	for i, tc := range testcases {
		_, oc, _ := setupOVSController(t)

		otx := oc.NewTransaction()
		for _, flow := range tc.flows {
			otx.AddFlow(flow)
		}
		if err := otx.Commit(); err != nil {
			t.Fatalf("(%d) unexpected error from AddFlow: %v", i, err)
		}

		policyVNIDs := oc.FindPolicyVNIDs()

		if !policyVNIDs.Equal(tc.policyVNIDs) {
			t.Fatalf("(%d) wrong result for unused, expected %v, got %v", i, tc.policyVNIDs, policyVNIDs)
		}
	}

}

// Ensure that CNI's IP-addressed-based MAC addresses use the IP in the way we expect
func TestSetHWAddrByIP(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	hwAddr, err := hwaddr.GenerateHardwareAddr4(ip, hwaddr.PrivateMACPrefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedHWAddr := net.HardwareAddr(append(hwaddr.PrivateMACPrefix, ip.To4()...))
	if !reflect.DeepEqual(hwAddr, expectedHWAddr) {
		t.Fatalf("hwaddr.GenerateHardwareAddr4 changed behavior! (%#v != %#v)", hwAddr, expectedHWAddr)
	}
}

// *** IF YOU UPDATE THIS ARRAY YOU *MUST* CHANGE ruleVersion IN ovscontroller.go ***
var expectedFlows = []string{
	" cookie=0, table=0, priority=1000, ip, ct_state=-trk, actions=ct(table=0)",
	" cookie=0, table=0, priority=400, in_port=2, ip, nw_src=10.128.0.1, actions=goto_table:30",
	" cookie=0, table=0, priority=300, in_port=2, ip, nw_src=10.128.0.0/23, nw_dst=10.128.0.0/14, actions=goto_table:25",
	" cookie=0, table=0, priority=250, in_port=2, ip, nw_dst=224.0.0.0/4, actions=drop",
	" cookie=0, table=0, priority=200, in_port=1, arp, arp_spa=10.128.0.0/14, arp_tpa=10.128.0.0/23, actions=move:NXM_NX_TUN_ID[0..31]->NXM_NX_REG0[],goto_table:10",
	" cookie=0, table=0, priority=200, in_port=1, ip, nw_src=10.128.0.0/14, actions=move:NXM_NX_TUN_ID[0..31]->NXM_NX_REG0[],goto_table:10",
	" cookie=0, table=0, priority=200, in_port=1, ip, nw_dst=10.128.0.0/14, actions=move:NXM_NX_TUN_ID[0..31]->NXM_NX_REG0[],goto_table:10",
	" cookie=0, table=0, priority=200, in_port=2, arp, arp_spa=10.128.0.1, arp_tpa=10.128.0.0/14, actions=goto_table:30",
	" cookie=0, table=0, priority=200, in_port=2, ip, actions=goto_table:30",
	" cookie=0, table=0, priority=150, in_port=1, actions=drop",
	" cookie=0, table=0, priority=150, in_port=2, actions=drop",
	" cookie=0, table=0, priority=100, arp, actions=goto_table:20",
	" cookie=0, table=0, priority=100, ip, actions=goto_table:20",
	" cookie=0, table=0, priority=0, actions=drop",
	" cookie=0, table=10, priority=210, ip, nw_dst=10.128.0.1, eth_dst=00:09:dc:a4:5e:a3, actions=set_field:c6:ac:2c:13:48:4b->eth_dst,resubmit:10",
	" cookie=0, table=10, priority=200, ip, nw_dst=10.128.0.0/23, eth_dst=00:09:dc:a4:5e:a3, actions=move:nw_dst->eth_dst[0..31],set_field:0a:58:00:00:00:00/ff:ff:00:00:00:00->eth_dst,resubmit:10",
	" cookie=0x0f46ee1a, table=10, priority=100, tun_src=10.0.123.45, actions=goto_table:30",
	" cookie=0, table=10, priority=0, actions=drop",
	" cookie=0, table=20, priority=300, udp, udp_dst=4789, actions=drop",
	" cookie=0, table=20, priority=100, in_port=3, arp, arp_spa=10.128.0.2, arp_sha=00:00:0a:80:00:02/00:00:ff:ff:ff:ff, actions=load:42->NXM_NX_REG0[],goto_table:30",
	" cookie=0, table=20, priority=100, in_port=3, ip, nw_src=10.128.0.2, actions=load:42->NXM_NX_REG0[],goto_table:27",
	" cookie=0, table=20, priority=0, actions=drop",
	" cookie=0, table=25, priority=100, ip, nw_src=10.128.0.2, actions=load:42->NXM_NX_REG0[],goto_table:27",
	" cookie=0, table=25, priority=0, actions=drop",
	" cookie=0, table=27, priority=0, actions=drop",
	" cookie=0, table=30, priority=0, actions=goto_table:31",
	" cookie=0, table=31, priority=300, arp, arp_tpa=10.128.0.1, actions=output:2",
	" cookie=0, table=31, priority=300, ip, nw_dst=10.128.0.1, actions=output:2",
	" cookie=0, table=31, priority=250, ip, nw_dst=10.128.0.0/23, ct_state=+rpl, actions=ct(nat,table=70)",
	" cookie=0, table=31, priority=200, arp, arp_tpa=10.128.0.0/23, actions=goto_table:40",
	" cookie=0, table=31, priority=200, ip, nw_dst=10.128.0.0/23, actions=goto_table:70",
	" cookie=0, table=31, priority=100, arp, arp_tpa=10.128.0.0/14, actions=goto_table:50",
	" cookie=0, table=31, priority=100, ip, nw_dst=172.30.0.0/16, actions=goto_table:60",
	" cookie=0, table=31, priority=100, ip, nw_dst=10.128.0.0/14, actions=goto_table:90",
	" cookie=0, table=31, priority=50, in_port=1, ip, nw_dst=224.0.0.0/4, actions=goto_table:120",
	" cookie=0, table=31, priority=25, ip, nw_dst=224.0.0.0/4, actions=goto_table:110",
	" cookie=0, table=31, priority=0, ip, actions=goto_table:99",
	" cookie=0, table=31, priority=0, arp, actions=drop",
	" cookie=0, table=40, priority=100, arp, arp_tpa=10.128.0.2, actions=output:3",
	" cookie=0, table=40, priority=0, actions=drop",
	" cookie=0x0f46ee1a, table=50, priority=100, arp, arp_tpa=10.128.2.0/23, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:10.0.123.45->tun_dst,output:1",
	" cookie=0, table=50, priority=0, actions=drop",
	" cookie=0, table=60, priority=200, actions=output:2",
	" cookie=0, table=70, priority=100, ip, nw_dst=10.128.0.2, actions=load:42->NXM_NX_REG1[],load:3->NXM_NX_REG2[],goto_table:80",
	" cookie=0, table=70, priority=0, actions=drop",
	" cookie=0, table=80, priority=300, ip, nw_src=10.128.0.1/32, actions=output:NXM_NX_REG2[]",
	" cookie=0, table=80, priority=0, actions=drop",
	" cookie=0x0f46ee1a, table=90, priority=100, ip, nw_dst=10.128.2.0/23, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:10.0.123.45->tun_dst,output:1",
	" cookie=0, table=90, priority=0, actions=drop",
	" cookie=0, table=99, priority=200, tcp, tcp_dst=53, nw_dst=172.17.0.4, actions=output:2",
	" cookie=0, table=99, priority=200, udp, udp_dst=53, nw_dst=172.17.0.4, actions=output:2",
	" cookie=0, table=99, priority=0, actions=goto_table:100",
	" cookie=0, table=100, priority=3, reg0=42, ip, nw_dst=192.168.0.0/16, actions=goto_table:101",
	" cookie=0, table=100, priority=2, reg0=42, ip, nw_dst=192.168.1.0/24, actions=drop",
	" cookie=0, table=100, priority=1, reg0=42, ip, nw_dst=192.168.1.1/32, actions=goto_table:101",
	" cookie=0, table=100, priority=0, actions=goto_table:101",
	" cookie=0, table=101, priority=150, ct_state=+rpl, actions=output:2",
	" cookie=0, table=101, priority=100, ip, reg0=37, actions=ct(commit),group:37",
	" cookie=0, table=101, priority=0, actions=output:2",
	" cookie=0, table=110, reg0=99, actions=goto_table:111",
	" cookie=0, table=110, priority=0, actions=drop",
	" cookie=0, table=111, priority=100, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:10.0.123.45->tun_dst,output:1,set_field:10.0.45.123->tun_dst,output:1,goto_table:120",
	" cookie=0, table=120, priority=100, reg0=99, actions=output:4,output:5,output:6",
	" cookie=0, table=120, priority=0, actions=drop",
	" cookie=0, table=253, actions=note:00.0E",
}

// Ensure that we do not change the OVS flows without bumping ruleVersion
func TestRuleVersion(t *testing.T) {
	ovsif, oc, _ := setupOVSController(t)

	// Now call each oc method that adds flows

	// Pod-related flows
	_, err := oc.SetUpPod(sandboxID, "veth1", net.ParseIP("10.128.0.2"), 42)
	if err != nil {
		t.Fatalf("Unexpected error adding pod rules: %v", err)
	}

	// VXLAN flows
	hs := osdnv1.HostSubnet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			UID:  "node1UID",
		},
		HostIP: "10.0.123.45",
		Subnet: "10.128.2.0/23",
	}
	err = oc.AddHostSubnetRules(&hs)
	if err != nil {
		t.Fatalf("Unexpected error adding hostsubnet rules: %v", err)
	}

	// Multicast flows
	err = oc.UpdateLocalMulticastFlows(99, true, []int{4, 5, 6})
	if err != nil {
		t.Fatalf("Unexpected error adding local multicast flows: %v", err)
	}
	err = oc.UpdateVXLANMulticastFlows([]string{"10.0.123.45", "10.0.45.123"})
	if err != nil {
		t.Fatalf("Unexpected error adding local multicast flows: %v", err)
	}

	// EgressNetworkPolicy flows
	err = oc.UpdateEgressNetworkPolicyRules(
		[]osdnv1.EgressNetworkPolicy{enp1},
		42,
		[]string{"ns1"},
		nil,
	)
	if err != nil {
		t.Fatalf("Unexpected error updating egress network policy: %v", err)
	}

	// Egress IP flows
	egressIPsMetaData := []egressIPMetaData{
		{nodeIP: "10.0.12.34", packetMark: getMarkForVNID(37, 0x1)}}
	err = oc.SetNamespaceEgressViaEgressIPs(uint32(37), egressIPsMetaData)
	if err != nil {
		t.Fatalf("Unexpected error updating egress IPs: %v", err)
	}

	flows, err := ovsif.DumpFlows("")
	if err != nil {
		t.Fatalf("Unexpected error dumping flows: %v", err)
	}
	if reflect.DeepEqual(flows, expectedFlows) {
		return
	}

	t.Logf("*** FLOWS HAVE CHANGED FROM PREVIOUS COMMIT ***\n%s\nIf this change is expected then make sure you have bumped ruleVersion in pkg/network/node/ovscontroller.go, and then update expectedFlows in pkg/network/node/ovscontroller_test.go", diffFlows(expectedFlows, flows))

	t.Fatalf("flows changed")
}
