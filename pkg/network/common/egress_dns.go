package common

import (
	"fmt"
	"net"
	"sync"
	"time"

	networkv1 "github.com/openshift/api/network/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	utiltrace "k8s.io/utils/trace"
)

type EgressDNSUpdate struct {
	UID       ktypes.UID
	Namespace string
}

type EgressDNSUpdates []EgressDNSUpdate

type EgressDNS struct {
	// Protects pdMap/namespaces operations
	lock sync.Mutex
	// holds DNS entries globally
	dns DNSInterface
	// this map holds which DNS names are in what policy objects
	dnsNamesToPolicies map[string]sets.String
	// Maintain namespaces for each policy to avoid querying etcd in syncEgressDNSPolicyRules()
	namespaces map[ktypes.UID]string

	// Report change when Add operation is done
	added chan bool

	// Report changes when there are dns updates
	Updates chan EgressDNSUpdates

	// Notify when a dns query is responded
	dnsResponse chan DNSResponseNotification

	// Notify when a dns query is responded
	stopCh chan struct{}
}

func NewEgressDNS(ipv4, ipv6 bool) (*EgressDNS, error) {
	dnsInfo, err := NewDNS("/etc/resolv.conf", ipv4, ipv6)
	if err != nil {
		utilruntime.HandleError(err)
		return nil, err
	}
	return &EgressDNS{
		dns:                dnsInfo,
		dnsNamesToPolicies: map[string]sets.String{},
		namespaces:         map[ktypes.UID]string{},
		added:              make(chan bool),
		Updates:            make(chan EgressDNSUpdates),
		dnsResponse:        make(chan DNSResponseNotification),
		stopCh:             make(chan struct{}),
	}, nil
}

func (e *EgressDNS) Add(policy networkv1.EgressNetworkPolicy) {
	e.lock.Lock()
	defer e.lock.Unlock()

	for _, rule := range policy.Spec.Egress {
		if len(rule.To.DNSName) > 0 {
			if uids, exists := e.dnsNamesToPolicies[rule.To.DNSName]; !exists {
				e.dnsNamesToPolicies[rule.To.DNSName] = sets.NewString(string(policy.UID))
				//only call Add if the dnsName doesn't exist in the dnsNamesToPolicies
				if err := e.dns.Add(rule.To.DNSName); err != nil {
					utilruntime.HandleError(err)
				}
				e.signalAdded()
			} else {
				e.dnsNamesToPolicies[rule.To.DNSName] = uids.Insert(string(policy.UID))
			}
		}
	}
	e.namespaces[policy.UID] = policy.Namespace
}

func (e *EgressDNS) Delete(policy networkv1.EgressNetworkPolicy) {
	e.lock.Lock()
	defer e.lock.Unlock()
	//delete the entry from the dnsNames to UIDs map for each rule in the policy
	//if the slice is empty at this point, delete the entry from the dns object too
	//also remove the policy entry from the namespaces map.
	for _, rule := range policy.Spec.Egress {
		if len(rule.To.DNSName) > 0 {
			if uids, ok := e.dnsNamesToPolicies[rule.To.DNSName]; ok {
				uids.Delete(string(policy.UID))
				if uids.Len() == 0 {
					e.dns.Delete(rule.To.DNSName)
					delete(e.dnsNamesToPolicies, rule.To.DNSName)
				} else {
					e.dnsNamesToPolicies[rule.To.DNSName] = uids
				}
			}
		}
	}

	if _, ok := e.namespaces[policy.UID]; ok {
		delete(e.namespaces, policy.UID)
	}
}

func (e *EgressDNS) update(dns string) {
	changed, err := e.dns.Update(dns)
	if err != nil {
		klog.Errorf("Unable to update ip addreses for %q: %v", dns, err)
	}

	trace := utiltrace.New(fmt.Sprintf("Update egressDNS response channel for %q", dns))
	defer trace.LogIfLong(dnsMapTraceThreshold)
	e.dnsResponse <- DNSResponseNotification{Changed: changed, Name: dns}
}

func (e *EgressDNS) Sync() {
	var duration time.Duration
	for {
		tm, dnsName, ok := e.dns.GetNextQueryTime()
		if !ok {
			duration = 30 * time.Minute
		} else {
			now := time.Now()
			if tm.After(now) {
				// Item needs to wait for this duration before it can be processed
				duration = tm.Sub(now)
			} else {
				e.dns.SetUpdating(dnsName)
				go e.update(dnsName)
			}
		}

		// Wait for the the next query time, until there is a reply,
		// or until a new name is added.
		select {
		case response := <-e.dnsResponse:
			go e.handleDNSResponse(response)
		case <-e.added:
		case <-e.stopCh:
			return
		case <-time.After(duration):
		}
	}
}

func (e *EgressDNS) handleDNSResponse(response DNSResponseNotification) {
	trace := utiltrace.New(fmt.Sprintf("Handle DNS response notification for %q", response.Name))
	defer trace.LogIfLong(dnsMapTraceThreshold)

	if response.Changed {
		updates := e.getEgressDNSUpdates(response.Name)
		trace.Step("getEgressDNSUpdates")
		e.Updates <- updates
	}

}

func (e *EgressDNS) getEgressDNSUpdates(dnsName string) []EgressDNSUpdate {
	e.lock.Lock()
	defer e.lock.Unlock()
	policyUpdates := make([]EgressDNSUpdate, 0)
	if uids, exists := e.dnsNamesToPolicies[dnsName]; exists {
		for uid := range uids {
			policyUpdates = append(policyUpdates, EgressDNSUpdate{ktypes.UID(uid), e.namespaces[ktypes.UID(uid)]})
		}
	} else {
		klog.V(5).Infof("Didn't find any entry for dns name: %s in the dns map.", dnsName)
	}
	return policyUpdates
}

func (e *EgressDNS) GetIPs(dnsName string) []net.IP {
	e.lock.Lock()
	defer e.lock.Unlock()
	return e.dns.Get(dnsName).ips

}

func (e *EgressDNS) GetNetCIDRs(dnsName string) []net.IPNet {
	cidrs := []net.IPNet{}
	masklen := 0
	for _, ip := range e.GetIPs(dnsName) {
		if utilnet.IsIPv6(ip) {
			masklen = 128
		} else {
			masklen = 32
		}
		cidrs = append(cidrs, net.IPNet{IP: ip, Mask: net.CIDRMask(masklen, masklen)})
	}
	return cidrs
}

func (e *EgressDNS) signalAdded() {
	// Non-blocking op
	select {
	case e.added <- true:
	default:
	}
}

func (e *EgressDNS) Stop() {
	klog.V(5).Info("Stopping EgressDNS")
	e.stopCh <- struct{}{}
}
