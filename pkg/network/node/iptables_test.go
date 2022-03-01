package node

import (
	"fmt"
	"testing"

	"k8s.io/kubernetes/pkg/util/iptables"
	kexec "k8s.io/utils/exec"
)

func TestVxlanNoTrackRulesWithDefaultVxlanPort(t *testing.T) {
	validateIPTableRuleForVxlanPort(t, 4789)
}

func TestVxlanNoTrackRulesWithCustomVxlanPort(t *testing.T) {
	validateIPTableRuleForVxlanPort(t, 4788)
}

func validateIPTableRuleForVxlanPort(t *testing.T, dstPort uint32) {
	ipt := iptables.New(kexec.New(), iptables.ProtocolIPv4)
	nodeIpt := newNodeIPTables(ipt, nil, true, dstPort, uint32(0))
	err := nodeIpt.syncIPTableRules()
	if err != nil {
		t.Fatalf("unexpected error while syncing ip table rules: %v", err)
	}
	exists, err := ipt.EnsureRule(iptables.Append, iptables.Table("raw"), iptables.Chain("PREROUTING"), "-m", "comment", "--comment", "disable conntrack for vxlan", "-j", "OPENSHIFT-NOTRACK")
	if err != nil {
		t.Fatalf("error while checking vxlan ip table prerouting rule: %v", err)
	}
	if !exists {
		t.Fatalf("vxlan ip table prerouting rule must exist")
	}

	exists, err = ipt.EnsureRule(iptables.Append, iptables.Table("raw"), iptables.Chain("OUTPUT"), "-m", "comment", "--comment", "disable conntrack for vxlan", "-j", "OPENSHIFT-NOTRACK")
	if err != nil {
		t.Fatalf("error while checking vxlan ip table output rule: %v", err)
	}
	if !exists {
		t.Fatalf("vxlan ip table output rule must exist")
	}

	exists, err = ipt.EnsureRule(iptables.Append, iptables.Table("raw"), iptables.Chain("OPENSHIFT-NOTRACK"), "-p", "udp", "--dport", fmt.Sprint(dstPort), "-j", "NOTRACK")
	if err != nil {
		t.Fatalf("error while checking vxlan ip table notrack rule: %v", err)
	}
	if !exists {
		t.Fatalf("vxlan ip table notrack rule must exist")
	}
	ipt.DeleteRule(iptables.Table("raw"), iptables.Chain("PREROUTING"), "-m", "comment", "--comment", "disable conntrack for vxlan", "-j", "OPENSHIFT-NOTRACK")
	ipt.DeleteRule(iptables.Table("raw"), iptables.Chain("OUTPUT"), "-m", "comment", "--comment", "disable conntrack for vxlan", "-j", "OPENSHIFT-NOTRACK")
	ipt.DeleteRule(iptables.Table("raw"), iptables.Chain("OPENSHIFT-NOTRACK"), "-p", "udp", "--dport", fmt.Sprint(dstPort), "-j", "NOTRACK")
	ipt.DeleteChain(iptables.Table("raw"), iptables.Chain("OPENSHIFT-NOTRACK"))
}
