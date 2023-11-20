package node

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"

	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/vishvananda/netlink"
)

const (
	maxRetries            = 2
	defaultKubeletDropBit = 1 << uint32(15) // https://github.com/kubernetes/kubelet/blob/release-1.24/config/v1beta1/types.go#L555
)

type egressNode struct {
	nodeIP  string
	sdnIP   string
	offline bool

	egressIPs sets.String
	retries   int
}

type egressIPWatcher struct {
	// We don't need a mutex because tracker serializes all of its callbacks to us

	tracker *common.EgressIPTracker

	oc            *ovsController
	localIP       string
	masqueradeBit uint32

	iptables     *NodeIPTables
	iptablesMark map[string]string

	monitorNodesLock sync.Mutex
	monitorNodes     map[string]*egressNode
	stopMonitorNodes chan struct{}

	stopIPResync chan struct{}

	testModeChan chan string
}

type egressIPMetaData struct {
	nodeIP     string
	packetMark string
}

func newEgressIPWatcher(oc *ovsController, cloudEgressIP bool, localIP string, masqueradeBit *int32) *egressIPWatcher {
	eip := &egressIPWatcher{
		oc:           oc,
		localIP:      localIP,
		monitorNodes: make(map[string]*egressNode),
		iptablesMark: make(map[string]string),
	}
	if masqueradeBit != nil {
		eip.masqueradeBit = 1 << uint32(*masqueradeBit)
	}

	eip.tracker = common.NewEgressIPTracker(eip, cloudEgressIP, localIP)
	return eip
}

func (eip *egressIPWatcher) Start(osdnInformers osdninformers.SharedInformerFactory, kubeInformers informers.SharedInformerFactory, kubeClient kubernetes.Interface, iptables *NodeIPTables) error {
	eip.iptables = iptables
	if eip.tracker.CloudEgressIP {
		eip.tracker.Start(kubeClient, osdnInformers.Network().V1().HostSubnets(), osdnInformers.Network().V1().NetNamespaces(), kubeInformers.Core().V1().Nodes())
	} else {
		eip.tracker.Start(kubeClient, osdnInformers.Network().V1().HostSubnets(), osdnInformers.Network().V1().NetNamespaces(), nil)
	}
	return nil
}

func (eip *egressIPWatcher) SyncIPAssignments() error {
	link, _, err := GetLinkDetails(eip.localIP)
	if err != nil {
		return fmt.Errorf("could not get %s link details %v", eip.localIP, err)
	}
	label, err := egressIPLabel(link)
	if err != nil {
		return fmt.Errorf("invalid egress IP label: %v", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("could not check for egress IPs: %v", err)
	}

	existingIPs := sets.NewString()
	for _, addr := range addrs {
		ip := addr.IP.String()
		if addr.Label == label {
			if eip.iptablesMark[ip] == "" {
				klog.Infof("Cleaning up stale egress IP %s", addr.IP.String())
				err = netlink.AddrDel(link, &addr)
				if err != nil {
					klog.Errorf("Could not clean up stale egress IP: %v", err)
				}
			} else {
				existingIPs.Insert(ip)
			}
		}
	}
	for ip, mark := range eip.iptablesMark {
		if !existingIPs.Has(ip) {
			klog.Infof("Assigning missing egress IP %s", ip)
			eip.assignEgressIP(ip, mark)
		}
	}
	return nil
}

func (eip *egressIPWatcher) Synced() {
	if err := eip.SyncIPAssignments(); err != nil {
		klog.Errorf("Failed to sync ip assignments: %v", err)
		return
	}
	eip.iptables.SyncEgressIPRules()
}

func egressIPLabel(link netlink.Link) (string, error) {
	// An address label must start with the link name plus ":", and must be at most 15
	// characters long. If the link name is too long then we can't label egress IPs.
	label := link.Attrs().Name + ":eip"
	if len(label) > 15 {
		return "", fmt.Errorf("link name %q is too long", link.Attrs().Name)
	}
	return label, nil
}

// Convert vnid to a hex value that is not 0, does not have masqueradeBit and defaultKubeletDropBit set, and isn't
// the same value as would be returned for any other valid vnid.
func getMarkForVNID(vnid, masqueradeBit uint32) string {
	if vnid == 0 {
		vnid = 0xff000000
	}
	if (vnid & defaultKubeletDropBit) != 0 {
		vnid = (vnid | 0x10000000) ^ defaultKubeletDropBit
	}
	if (vnid & masqueradeBit) != 0 {
		vnid = (vnid | 0x01000000) ^ masqueradeBit
	}
	return fmt.Sprintf("0x%08x", vnid)
}

func (eip *egressIPWatcher) runIPAssignmentResync(stopCh <-chan struct{}) {
	var addrChan chan netlink.AddrUpdate
	addrSubscribe := func() error {
		addrChan = make(chan netlink.AddrUpdate)
		err := netlink.AddrSubscribeWithOptions(addrChan, stopCh, netlink.AddrSubscribeOptions{
			ErrorCallback: func(err error) {
				klog.Errorf("Failed during AddrSubscribe callback: %v", err)
			},
		})
		// when AddrSubscribeWithOptions fails it does not close the addrChan
		if err != nil {
			close(addrChan)
		}
		return err
	}

	// ~1 sec total
	syncIPsBackOff := utilwait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.25,
		Steps:    7,
	}
	syncIPs := func() {
		eip.tracker.Lock()
		defer eip.tracker.Unlock()

		var lastSyncErr error
		if err := utilwait.ExponentialBackoff(syncIPsBackOff, func() (bool, error) {
			if err := eip.SyncIPAssignments(); err != nil {
				klog.V(5).Infof("Error synchronizing IP assignments: %v", err)
				lastSyncErr = err
				return false, nil
			}
			return true, nil
		}); err != nil {
			klog.Errorf("Failed to sync IP assignments: %v", lastSyncErr)
		}
	}

	subscribeErr := addrSubscribe()
	if subscribeErr != nil {
		klog.Errorf("Error during netlink subscribe: %v", subscribeErr)
	}

	for {
		select {
		case <-stopCh:
			klog.V(5).Infof("Stopping egress IP assignment resync")
			return
		case a, ok := <-addrChan:
			if !ok {
				if subscribeErr = addrSubscribe(); subscribeErr != nil {
					klog.Errorf("Error during netlink re-subscribe due to address channel closing: %v", subscribeErr)
					// limit the retry attempts
					time.Sleep(common.DefaultPollInterval)
				}
				continue
			}

			// sync IP assignments on any egress IP removal event
			if _, ok := eip.iptablesMark[a.LinkAddress.IP.String()]; ok && !a.NewAddr {
				klog.V(5).Infof("Egress IP %s removed from the interface, syncing assignments", a.LinkAddress.IP.String())
				syncIPs()
			}
		}
	}
}

func (eip *egressIPWatcher) ClaimEgressIP(vnid uint32, egressIP, nodeIP, sdnIP string, nodeOffline bool) {
	if nodeIP == eip.localIP {
		mark := getMarkForVNID(vnid, eip.masqueradeBit)
		eip.iptablesMark[egressIP] = mark
		if err := eip.assignEgressIP(egressIP, mark); err != nil {
			klog.Errorf("Error assigning Egress IP %q: %v", egressIP, err)
		}

		if len(eip.iptablesMark) == 1 {
			eip.stopIPResync = make(chan struct{})
			go eip.runIPAssignmentResync(eip.stopIPResync)
		}
	} else {
		eip.addEgressIP(nodeIP, egressIP, sdnIP, nodeOffline)
	}
}

func (eip *egressIPWatcher) ReleaseEgressIP(egressIP, nodeIP string) {
	if nodeIP == eip.localIP {
		mark := eip.iptablesMark[egressIP]
		delete(eip.iptablesMark, egressIP)
		if err := eip.releaseEgressIP(egressIP, mark); err != nil {
			klog.Errorf("Error releasing Egress IP %q: %v", egressIP, err)
		}

		if len(eip.iptablesMark) == 0 && eip.stopIPResync != nil {
			close(eip.stopIPResync)
			eip.stopIPResync = nil
		}
	} else {
		eip.removeEgressIP(nodeIP, egressIP)
	}
}

func (eip *egressIPWatcher) addEgressIP(nodeIP, egressIP, sdnIP string, nodeOffline bool) {
	eip.monitorNodesLock.Lock()
	defer eip.monitorNodesLock.Unlock()

	if eip.monitorNodes[nodeIP] != nil {
		eip.monitorNodes[nodeIP].egressIPs.Insert(egressIP)
		return
	}
	klog.V(4).Infof("Monitoring node %s", nodeIP)

	eip.monitorNodes[nodeIP] = &egressNode{
		nodeIP:    nodeIP,
		sdnIP:     sdnIP,
		egressIPs: sets.NewString(egressIP),
		offline:   nodeOffline,
	}
	if len(eip.monitorNodes) == 1 {
		eip.stopMonitorNodes = make(chan struct{})
		go utilwait.PollUntil(common.DefaultPollInterval, eip.poll, eip.stopMonitorNodes)
	}
}

func (eip *egressIPWatcher) removeEgressIP(nodeIP, egressIP string) {
	eip.monitorNodesLock.Lock()
	defer eip.monitorNodesLock.Unlock()

	if eip.monitorNodes[nodeIP] == nil {
		return
	}
	eip.monitorNodes[nodeIP].egressIPs.Delete(egressIP)
	if eip.monitorNodes[nodeIP].egressIPs.Len() == 0 {
		klog.V(4).Infof("Unmonitoring node %s", nodeIP)
		delete(eip.monitorNodes, nodeIP)
		if len(eip.monitorNodes) == 0 && eip.stopMonitorNodes != nil {
			close(eip.stopMonitorNodes)
			eip.stopMonitorNodes = nil
		}
	}
}

func (eip *egressIPWatcher) poll() (bool, error) {
	retry := eip.check(false)
	for retry {
		time.Sleep(common.RepollInterval)
		retry = eip.check(true)
	}
	return false, nil
}

func (eip *egressIPWatcher) check(retrying bool) bool {
	offlineResult, needRetry := eip.getOfflineResult(retrying)
	for nodeIP, offline := range offlineResult {
		eip.tracker.SetNodeOffline(nodeIP, offline)
	}
	return needRetry
}

func (eip *egressIPWatcher) getOfflineResult(retrying bool) (map[string]bool, bool) {
	eip.monitorNodesLock.Lock()
	defer eip.monitorNodesLock.Unlock()

	var timeout time.Duration
	if retrying {
		timeout = common.RepollInterval
	} else {
		timeout = common.DefaultPollInterval
	}

	needRetry := false
	offlineResult := make(map[string]bool)
	for _, node := range eip.monitorNodes {
		if retrying && node.retries == 0 {
			continue
		}

		online := eip.tracker.Ping(node.sdnIP, timeout)
		if node.offline && online {
			klog.Infof("Node %s is back online", node.nodeIP)
			node.offline = false
			offlineResult[node.nodeIP] = false
		} else if !node.offline && !online {
			node.retries++
			if node.retries > maxRetries {
				klog.Warningf("Node %s is offline", node.nodeIP)
				node.retries = 0
				node.offline = true
				offlineResult[node.nodeIP] = true
			} else {
				klog.V(2).Infof("Node %s may be offline... retrying", node.nodeIP)
				needRetry = true
			}
		}
	}
	return offlineResult, needRetry
}

func (eip *egressIPWatcher) UpdateEgressCIDRs() {
}

func (eip *egressIPWatcher) SetNamespaceEgressNormal(vnid uint32) {
	if err := eip.oc.SetNamespaceEgressNormal(vnid); err != nil {
		klog.Errorf("Error updating Namespace egress rules for VNID %d: %v", vnid, err)
	}
}

func (eip *egressIPWatcher) SetNamespaceEgressDropped(vnid uint32) {
	if err := eip.oc.SetNamespaceEgressDropped(vnid); err != nil {
		klog.Errorf("Error updating Namespace egress rules for VNID %d: %v", vnid, err)
	}
}

func (eip *egressIPWatcher) SetNamespaceEgressViaEgressIPs(vnid uint32, activeEgressIPs []common.EgressIPAssignment) {
	egressIPsMetaData := []egressIPMetaData{}
	for _, egressIPAssignment := range activeEgressIPs {
		egressIPsMetaData = append(egressIPsMetaData, egressIPMetaData{nodeIP: egressIPAssignment.NodeIP, packetMark: eip.iptablesMark[egressIPAssignment.EgressIP]})
	}
	if err := eip.oc.SetNamespaceEgressViaEgressIPs(vnid, egressIPsMetaData); err != nil {
		klog.Errorf("Error updating Namespace egress rules for VNID %d: %v", vnid, err)
	}
}

func (eip *egressIPWatcher) getEgressLinkDetails() (netlink.Link, *net.IPNet, *net.IPNet, error) {
	localEgressLink, localEgressNet, err := GetLinkDetails(eip.localIP)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get egress link(%s) details: %v", eip.localIP, err)
	}

	if !eip.tracker.CloudEgressIP {
		return localEgressLink, localEgressNet, nil, err
	}

	nodeName := eip.tracker.GetNodeNameByNodeIP(eip.localIP)
	egressIPConfig, err := eip.tracker.GetNodeCloudEgressIPConfig(nodeName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get cloud egress ip config: %v", err)
	}
	_, cloudEgressNet, err := net.ParseCIDR(egressIPConfig.IFAddr.IPv4)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse cloud egress ip config: %v", err)
	}

	return localEgressLink, localEgressNet, cloudEgressNet, err
}

func (eip *egressIPWatcher) assignEgressIP(egressIP, mark string) error {
	if egressIP == eip.localIP {
		return fmt.Errorf("desired egress IP %q is the node IP", egressIP)
	}

	if eip.testModeChan != nil {
		eip.testModeChan <- fmt.Sprintf("claim %s", egressIP)
		return nil
	}

	localEgressLink, localEgressNet, cloudEgressNet, err := eip.getEgressLinkDetails()
	if err != nil {
		return fmt.Errorf("unable to get egress link details: %v", err)
	}

	localEgressIPMaskLen, _ := localEgressNet.Mask.Size()
	egressIPNet := fmt.Sprintf("%s/%d", egressIP, localEgressIPMaskLen)
	addr, err := netlink.ParseAddr(egressIPNet)
	if err != nil {
		return fmt.Errorf("could not parse egress IP %q: %v", egressIPNet, err)
	}
	if !eip.tracker.CloudEgressIP && !localEgressNet.Contains(addr.IP) {
		return fmt.Errorf("egress IP %q is not in local network %s of interface %s", egressIP, localEgressNet.String(), localEgressLink.Attrs().Name)
	}
	if eip.tracker.CloudEgressIP && !cloudEgressNet.Contains(addr.IP) {
		return fmt.Errorf("egress IP %q is not in cloud network %s", egressIP, cloudEgressNet.String())
	}

	addr.Label, _ = egressIPLabel(localEgressLink)
	err = netlink.AddrAdd(localEgressLink, addr)
	if err != nil {
		if err == syscall.EEXIST {
			klog.V(2).Infof("Egress IP %q already exists on %s", egressIPNet, localEgressLink.Attrs().Name)
		} else {
			return fmt.Errorf("could not add egress IP %q to %s: %v", egressIPNet, localEgressLink.Attrs().Name, err)
		}
	}
	// Use arping to try to update other hosts ARP caches, in case this IP was
	// previously active on another node. (Based on code from "ifup".)
	go func() {
		out, err := exec.Command("/sbin/arping", "-q", "-A", "-c", "1", "-I", localEgressLink.Attrs().Name, egressIP).CombinedOutput()
		if err != nil {
			klog.Warningf("Failed to send ARP claim for egress IP %q: %v (%s)", egressIP, err, string(out))
			return
		}
		time.Sleep(2 * time.Second)
		_ = exec.Command("/sbin/arping", "-q", "-U", "-c", "1", "-I", localEgressLink.Attrs().Name, egressIP).Run()
	}()

	if err := eip.iptables.AddEgressIPRules(egressIP, mark); err != nil {
		return fmt.Errorf("could not add egress IP iptables rule: %v", err)
	}

	return nil
}

func (eip *egressIPWatcher) releaseEgressIP(egressIP, mark string) error {
	if egressIP == eip.localIP {
		return nil
	}

	if eip.testModeChan != nil {
		eip.testModeChan <- fmt.Sprintf("release %s", egressIP)
		return nil
	}

	localEgressLink, localEgressNet, err := GetLinkDetails(eip.localIP)
	if err != nil {
		return fmt.Errorf("unable to get egress link details: %v", err)
	}

	localEgressIPMaskLen, _ := localEgressNet.Mask.Size()
	egressIPNet := fmt.Sprintf("%s/%d", egressIP, localEgressIPMaskLen)
	addr, err := netlink.ParseAddr(egressIPNet)
	if err != nil {
		return fmt.Errorf("could not parse egress IP %q: %v", egressIPNet, err)
	}
	err = netlink.AddrDel(localEgressLink, addr)
	if err != nil {
		if err == syscall.EADDRNOTAVAIL {
			klog.V(2).Infof("Could not delete egress IP %q from %s: no such address", egressIPNet, localEgressLink.Attrs().Name)
		} else {
			return fmt.Errorf("could not delete egress IP %q from %s: %v", egressIPNet, localEgressLink.Attrs().Name, err)
		}
	}

	if err := eip.iptables.DeleteEgressIPRules(egressIP, mark); err != nil {
		return fmt.Errorf("could not delete egress IP iptables rule: %v", err)
	}

	return nil
}
