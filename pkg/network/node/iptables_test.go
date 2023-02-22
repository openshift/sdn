package node

import (
	"fmt"
	"testing"

	iptablestest "github.com/openshift/sdn/pkg/network/node/testing"
	"k8s.io/kubernetes/pkg/util/iptables"
)

func TestVxlanNoTrackRulesWithDefaultVxlanPort(t *testing.T) {
	validateIPTableRuleForVxlanPort(t, 4789)
}

func TestVxlanNoTrackRulesWithCustomVxlanPort(t *testing.T) {
	validateIPTableRuleForVxlanPort(t, 4788)
}

func validateIPTableRuleForVxlanPort(t *testing.T, dstPort uint32) {
	ipt := iptablestest.NewFake()
	nodeIpt := newNodeIPTables(ipt, nil, dstPort, uint32(0))
	err := nodeIpt.syncIPTableRules()
	if err != nil {
		t.Fatalf("unexpected error while syncing ip table rules: %v", err)
	}
	exists := ipt.IsPresent(iptables.Append, iptables.Table("raw"), iptables.Chain("PREROUTING"), "-m", "comment", "--comment", "disable conntrack for vxlan", "-j", "OPENSHIFT-NOTRACK")
	if !exists {
		t.Fatalf("vxlan ip table prerouting rule must exist")
	}

	exists = ipt.IsPresent(iptables.Append, iptables.Table("raw"), iptables.Chain("OUTPUT"), "-m", "comment", "--comment", "disable conntrack for vxlan", "-j", "OPENSHIFT-NOTRACK")
	if !exists {
		t.Fatalf("vxlan ip table output rule must exist")
	}

	exists = ipt.IsPresent(iptables.Append, iptables.Table("raw"), iptables.Chain("OPENSHIFT-NOTRACK"), "-p", "udp", "--dport", fmt.Sprint(dstPort), "-j", "NOTRACK")
	if !exists {
		t.Fatalf("vxlan ip table notrack rule must exist")
	}
}
