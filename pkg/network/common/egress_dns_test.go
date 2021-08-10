package common

import (
	"net"
	"testing"
	"time"

	osdnv1 "github.com/openshift/api/network/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

type delayedDNSTest struct {
	name  string
	ips   [][]net.IP
	delay time.Duration
}

func newEgressNetworkPolicy(dnsName string, namespace string) osdnv1.EgressNetworkPolicy {
	return osdnv1.EgressNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enp",
			Namespace: namespace,
			UID:       ktypes.UID(namespace + "-enp"),
		},
		Spec: osdnv1.EgressNetworkPolicySpec{
			Egress: []osdnv1.EgressNetworkPolicyRule{
				{
					Type: osdnv1.EgressNetworkPolicyRuleAllow,
					To: osdnv1.EgressNetworkPolicyPeer{
						DNSName: dnsName,
					},
				},
			},
		},
	}
}

func TestSync(t *testing.T) {

	startTime := time.Now().Add(150 * time.Millisecond)
	DNSReplies := []fakeDNSReply{
		{
			name:          "domain1.com",
			ttl:           1 * time.Second,
			ips:           []net.IP{net.ParseIP("1.1.1.1")},
			delay:         50 * time.Millisecond,
			nextQueryTime: startTime.Add(100 * time.Millisecond),
		},
		{
			name:          "domain2.com",
			ttl:           1 * time.Second,
			ips:           []net.IP{net.ParseIP("1.2.3.4")},
			delay:         3500 * time.Millisecond,
			nextQueryTime: startTime.Add(150 * time.Millisecond),
		},
		{
			name:          "domain1.com",
			ttl:           1 * time.Second,
			ips:           []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.2")},
			delay:         50 * time.Millisecond,
			nextQueryTime: startTime.Add(200 * time.Millisecond),
		},
	}

	dnsInfo := NewFakeDNS(DNSReplies)
	egressDNS := EgressDNS{
		dns:                dnsInfo,
		dnsNamesToPolicies: map[string]sets.String{},
		namespaces:         map[ktypes.UID]string{},
		added:              make(chan bool),
		Updates:            make(chan EgressDNSUpdates),
		dnsResponse:        make(chan DNSResponseNotification),
		stopCh:             make(chan struct{}),
	}

	egressDNS.Add(newEgressNetworkPolicy("domain1.com", "fake-ns-1"))
	egressDNS.Add(newEgressNetworkPolicy("domain2.com", "fake-ns-2"))
	egressDNS.Add(newEgressNetworkPolicy("domain1.com", "fake-ns-3"))

	go egressDNS.Sync()
	update := <-egressDNS.Updates
	if len(update) != 2 {
		t.Errorf("Expected exactly two elements in the update: %v", update)
		// Exit the function to avoid a nil pointer dereference
		return
	}

	u0 := update[0]
	u1 := update[1]
	if !((u0.Namespace == "fake-ns-1" && u1.Namespace == "fake-ns-3") ||
		(u0.Namespace == "fake-ns-3" && u1.Namespace == "fake-ns-1")) {
		t.Errorf("Expecting an update for fake-ns-1 and fake-ns-3. Got: %v", update)
	}

	update = <-egressDNS.Updates
	if len(update) != 2 {
		t.Errorf("Expected exactly two elements in the update: %v", update)
		// Exit the function to avoid a nil pointer dereference
		return
	}

	u0 = update[0]
	u1 = update[1]
	if !((u0.Namespace == "fake-ns-1" && u1.Namespace == "fake-ns-3") ||
		(u0.Namespace == "fake-ns-3" && u1.Namespace == "fake-ns-1")) {
		t.Errorf("Expecting an update for fake-ns-1 and fake-ns-3. Got: %v", update)
	}

	update = <-egressDNS.Updates
	if len(update) != 1 {
		t.Errorf("Expected exactly one element in the update: %v", update)
		// Exit the function to avoid a nil pointer dereference
		return
	}
	u0 = update[0]
	if u0.Namespace != "fake-ns-2" {
		t.Errorf("Expecting an update for fake-ns-2. Got: %v", update)
	}
	egressDNS.Stop()
}
