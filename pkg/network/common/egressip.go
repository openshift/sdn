package common

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	networkv1 "github.com/openshift/api/network/v1"
	networkinformers "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
)

type NodeEgress struct {
	NodeName string
	NodeIP   string
	sdnIP    string

	requestedIPs   sets.String
	requestedCIDRs sets.String
	parsedCIDRs    map[string]*net.IPNet

	activeEgressIPs sets.String
	offline         bool
	retries         int
}

type namespaceEgress struct {
	vnid              uint32
	requestedIPs      []string
	shouldDropTraffic bool

	activeEgressIPs []EgressIPAssignment
}

type EgressIPAssignment struct {
	NodeIP   string
	EgressIP string
}

type egressIPInfo struct {
	ip     string
	parsed net.IP

	nodes      []*NodeEgress
	namespaces []*namespaceEgress

	assignedNodeIP string
	assignedVNID   uint32
}

type EgressIPWatcher interface {
	Synced()

	ClaimEgressIP(vnid uint32, egressIP, nodeIP, nodeName string)
	ReleaseEgressIP(egressIP, nodeIP string)

	SetNamespaceEgressNormal(vnid uint32)
	SetNamespaceEgressDropped(vnid uint32)
	SetNamespaceEgressViaEgressIPs(vnid uint32, activeEgressIPs []EgressIPAssignment)

	UpdateEgressCIDRs()
}

type EgressIPTracker struct {
	sync.Mutex

	watcher EgressIPWatcher

	nodeInformer     kcoreinformers.NodeInformer
	nodes            map[ktypes.UID]*NodeEgress
	nodesByNodeIP    map[string]*NodeEgress
	namespacesByVNID map[uint32]*namespaceEgress
	egressIPs        map[string]*egressIPInfo
	nodesWithCIDRs   int
	monitorNodes     map[string]*NodeEgress
	stop             chan struct{}

	changedEgressIPs  map[*egressIPInfo]bool
	changedNamespaces map[*namespaceEgress]bool
	updateEgressCIDRs bool
}

func NewEgressIPTracker(watcher EgressIPWatcher) *EgressIPTracker {
	return &EgressIPTracker{
		watcher: watcher,

		nodes:            make(map[ktypes.UID]*NodeEgress),
		nodesByNodeIP:    make(map[string]*NodeEgress),
		namespacesByVNID: make(map[uint32]*namespaceEgress),
		egressIPs:        make(map[string]*egressIPInfo),
		monitorNodes:     make(map[string]*NodeEgress),

		changedEgressIPs:  make(map[*egressIPInfo]bool),
		changedNamespaces: make(map[*namespaceEgress]bool),
	}
}

func (eit *EgressIPTracker) Start(hostSubnetInformer networkinformers.HostSubnetInformer, netNamespaceInformer networkinformers.NetNamespaceInformer, nodeInformer kcoreinformers.NodeInformer) {
	eit.watchHostSubnets(hostSubnetInformer)
	eit.watchNetNamespaces(netNamespaceInformer)
	eit.nodeInformer = nodeInformer

	go func() {
		cache.WaitForCacheSync(utilwait.NeverStop,
			hostSubnetInformer.Informer().HasSynced,
			netNamespaceInformer.Informer().HasSynced,
			nodeInformer.Informer().HasSynced)

		eit.Lock()
		defer eit.Unlock()

		eit.watcher.Synced()
	}()
}

func (eit *EgressIPTracker) ensureEgressIPInfo(egressIP string) *egressIPInfo {
	eg := eit.egressIPs[egressIP]
	if eg == nil {
		eg = &egressIPInfo{ip: egressIP, parsed: net.ParseIP(egressIP)}
		eit.egressIPs[egressIP] = eg
	}
	return eg
}

func (eit *EgressIPTracker) egressIPChanged(eg *egressIPInfo) {
	eit.changedEgressIPs[eg] = true
	for _, ns := range eg.namespaces {
		eit.changedNamespaces[ns] = true
	}
}

func (eit *EgressIPTracker) addNodeEgressIP(node *NodeEgress, egressIP string) {
	eg := eit.ensureEgressIPInfo(egressIP)
	eg.nodes = append(eg.nodes, node)

	eit.egressIPChanged(eg)
}

func (eit *EgressIPTracker) deleteNodeEgressIP(node *NodeEgress, egressIP string) {
	eg := eit.egressIPs[egressIP]
	if eg == nil {
		return
	}

	for i := range eg.nodes {
		if eg.nodes[i] == node {
			eit.egressIPChanged(eg)
			eg.nodes = append(eg.nodes[:i], eg.nodes[i+1:]...)
			return
		}
	}
}

func (eit *EgressIPTracker) addNamespaceEgressIP(ns *namespaceEgress, egressIP string) {
	eg := eit.ensureEgressIPInfo(egressIP)
	eg.namespaces = append(eg.namespaces, ns)

	eit.egressIPChanged(eg)
}

func (eit *EgressIPTracker) deleteNamespaceEgressIP(ns *namespaceEgress, egressIP string) {
	eg := eit.egressIPs[egressIP]
	if eg == nil {
		return
	}

	for i := range eg.namespaces {
		if eg.namespaces[i] == ns {
			eit.egressIPChanged(eg)
			eg.namespaces = append(eg.namespaces[:i], eg.namespaces[i+1:]...)
			return
		}
	}
}

func (eit *EgressIPTracker) watchHostSubnets(hostSubnetInformer networkinformers.HostSubnetInformer) {
	funcs := InformerFuncs(&networkv1.HostSubnet{}, eit.handleAddOrUpdateHostSubnet, eit.handleDeleteHostSubnet)
	hostSubnetInformer.Informer().AddEventHandler(funcs)
}

func (eit *EgressIPTracker) handleAddOrUpdateHostSubnet(obj, _ interface{}, eventType watch.EventType) {
	hs := obj.(*networkv1.HostSubnet)
	klog.V(5).Infof("Watch %s event for HostSubnet %q", eventType, hs.Name)

	if err := ValidateHostSubnetEgress(hs); err != nil {
		utilruntime.HandleError(fmt.Errorf("Ignoring invalid HostSubnet %s: %v", HostSubnetToString(hs), err))
		return
	}

	eit.UpdateHostSubnetEgress(hs)
}

func (eit *EgressIPTracker) handleDeleteHostSubnet(obj interface{}) {
	hs := obj.(*networkv1.HostSubnet)
	klog.V(5).Infof("Watch %s event for HostSubnet %q", watch.Deleted, hs.Name)

	hs = hs.DeepCopy()
	hs.EgressCIDRs = nil
	hs.EgressIPs = nil
	eit.UpdateHostSubnetEgress(hs)
}

func (eit *EgressIPTracker) UpdateHostSubnetEgress(hs *networkv1.HostSubnet) {
	eit.Lock()
	defer eit.Unlock()

	sdnIP := ""
	if hs.Subnet != "" {
		_, cidr, err := net.ParseCIDR(hs.Subnet)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("could not parse HostSubnet %q CIDR: %v", hs.Name, err))
		}
		sdnIP = GenerateDefaultGateway(cidr).String()
	}

	node := eit.nodes[hs.UID]
	if node == nil {
		if len(hs.EgressIPs) == 0 && len(hs.EgressCIDRs) == 0 {
			return
		}
		node = &NodeEgress{
			NodeName:     hs.Host,
			NodeIP:       hs.HostIP,
			sdnIP:        sdnIP,
			requestedIPs: sets.NewString(),
		}
		eit.nodes[hs.UID] = node
		eit.nodesByNodeIP[hs.HostIP] = node
	} else if len(hs.EgressIPs) == 0 && len(hs.EgressCIDRs) == 0 {
		delete(eit.nodes, hs.UID)
		delete(eit.nodesByNodeIP, node.NodeIP)
	}

	// Process EgressCIDRs
	newRequestedCIDRs := sets.NewString()
	for _, cidr := range hs.EgressCIDRs {
		newRequestedCIDRs.Insert(string(cidr))
	}

	if !node.requestedCIDRs.Equal(newRequestedCIDRs) {
		if len(hs.EgressCIDRs) == 0 {
			eit.nodesWithCIDRs--
		} else if node.requestedCIDRs.Len() == 0 {
			eit.nodesWithCIDRs++
		}
		node.requestedCIDRs = newRequestedCIDRs
		node.parsedCIDRs = make(map[string]*net.IPNet)
		for _, cidr := range hs.EgressCIDRs {
			_, parsed, _ := net.ParseCIDR(string(cidr))
			node.parsedCIDRs[string(cidr)] = parsed
		}
		eit.updateEgressCIDRs = true
	}

	if node.NodeIP != hs.HostIP {
		// We have to clean up the old egress IP mappings and call syncEgressIPs
		// before we can change node.NodeIP
		movedEgressIPs := make([]string, 0, node.requestedIPs.Len())
		for _, ip := range node.requestedIPs.UnsortedList() {
			eg := eit.egressIPs[ip]
			if eg != nil && eg.assignedNodeIP == node.NodeIP {
				movedEgressIPs = append(movedEgressIPs, ip)
				eit.deleteNodeEgressIP(node, ip)
			}
		}
		eit.syncEgressIPs()

		delete(eit.nodesByNodeIP, node.NodeIP)
		node.NodeIP = hs.HostIP
		eit.nodesByNodeIP[node.NodeIP] = node

		for _, ip := range movedEgressIPs {
			eit.addNodeEgressIP(node, ip)
		}
	}

	// Process new and removed EgressIPs
	oldRequestedIPs := node.requestedIPs
	node.requestedIPs = sets.NewString(HSEgressIPsToStrings(hs.EgressIPs)...)
	for _, ip := range node.requestedIPs.Difference(oldRequestedIPs).UnsortedList() {
		eit.addNodeEgressIP(node, ip)
	}
	for _, ip := range oldRequestedIPs.Difference(node.requestedIPs).UnsortedList() {
		eit.deleteNodeEgressIP(node, ip)
	}

	eit.syncEgressIPs()
}

func nodeIsReady(node *v1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == v1.NodeReady {
			if cond.Status == v1.ConditionFalse || cond.Status == v1.ConditionUnknown {
				return false
			}
		}
	}
	return true
}

// FIXME: currently SetMonitorNodes/GetMonitorNodes/AddEgressIP and
// ReleaseEgressIP all assume that the tracker lock is already held. This
// enforces some knowledge regarding the chain of execution for egress IP
// related setup. This is not great, since the API shouldn't make assumptions
// about the lock and enforce indirect conditions on the caller's side. This
// should ideally be re-worked so that all of these functions acquire the lock
// themselves.

// SetMonitorNodes updates EgressIPTracker with the node data provided and
// starts a go-routine (if one is not already running) which polls monitorNodes
// to check if they are ready and reachable. It assumes the lock is held.
func (eit *EgressIPTracker) SetMonitorNodes(monitorNodes map[string]*NodeEgress) {
	eit.monitorNodes = monitorNodes
	if len(monitorNodes) > 0 {
		if eit.stop == nil {
			eit.stop = make(chan struct{})
			go utilwait.PollUntil(defaultPollInterval, eit.poll, eit.stop)
		}
	} else {
		if eit.stop != nil {
			close(eit.stop)
			eit.stop = nil
		}
	}
}

// GetMonitorNodes gets the node data from EgressIPTracker.
// It assumes the lock is held.
func (eit *EgressIPTracker) GetMonitorNodes() map[string]*NodeEgress {
	return eit.monitorNodes
}

// AddEgressIP assumes the EgressIPTracker lock is already held. The access to
// this function call is currently percolated down from `syncEgressIPs`, which
// always has the lock held. It starts a go-routine (if one is not already
// running) which polls monitorNodes to check if they are ready and reachable
func (eit *EgressIPTracker) AddEgressIP(nodeIP, nodeName, egressIP string) {
	if eit.monitorNodes[nodeIP] != nil {
		eit.monitorNodes[nodeIP].activeEgressIPs.Insert(egressIP)
		return
	}
	klog.V(4).Infof("Monitoring node %s", nodeIP)

	eit.monitorNodes[nodeIP] = &NodeEgress{
		NodeIP:          nodeIP,
		activeEgressIPs: sets.NewString(egressIP),
		NodeName:        nodeName,
	}
	if len(eit.monitorNodes) == 1 && eit.stop == nil {
		eit.stop = make(chan struct{})
		go utilwait.PollUntil(defaultPollInterval, eit.poll, eit.stop)
	}
}

// This function assumes the EgressIPTracker lock is already held. The access to
// this function call is currently percolated down from `syncEgressIPs`, which
// always has the lock held. It stops the running go-routine which polls
// monitorNodes to check if they are ready and reachable (if there is one
// running)
func (eit *EgressIPTracker) RemoveEgressIP(nodeIP, egressIP string) {
	if eit.monitorNodes[nodeIP] == nil {
		return
	}
	eit.monitorNodes[nodeIP].activeEgressIPs.Delete(egressIP)
	if eit.monitorNodes[nodeIP].activeEgressIPs.Len() == 0 {
		klog.V(4).Infof("Unmonitoring node %s", nodeIP)
		delete(eit.monitorNodes, nodeIP)
		if len(eit.monitorNodes) == 0 && eit.stop != nil {
			close(eit.stop)
			eit.stop = nil
		}
	}
}

const (
	defaultPollInterval = 5 * time.Second
	repollInterval      = time.Second
	maxRetries          = 2
)

func (eit *EgressIPTracker) poll() (bool, error) {
	retry := eit.check(false)
	for retry {
		time.Sleep(repollInterval)
		retry = eit.check(true)
	}
	return false, nil
}

func (eit *EgressIPTracker) check(retrying bool) bool {
	eit.Lock()
	defer eit.Unlock()

	var timeout time.Duration
	if retrying {
		timeout = repollInterval
	} else {
		timeout = defaultPollInterval
	}

	needRetry := false
	for _, node := range eit.monitorNodes {
		if retrying && node.retries == 0 {
			continue
		}

		nn, err := eit.nodeInformer.Lister().Get(node.NodeName)
		if err != nil {
			return false
		}

		if !nodeIsReady(nn) {
			klog.Warningf("Node %s is not Ready", node.NodeName)
			node.offline = true
			eit.SetNodeOffline(node.NodeIP, true)
			// Return when there's a not Ready node
			return false
		}

		online := eit.Ping(node.NodeIP, timeout)
		if node.offline && online {
			klog.Infof("Node %s is back online", node.NodeIP)
			node.offline = false
			eit.SetNodeOffline(node.NodeIP, false)
		} else if !node.offline && !online {
			node.retries++
			if node.retries > maxRetries {
				klog.Warningf("Node %s is offline", node.NodeIP)
				node.retries = 0
				node.offline = true
				eit.SetNodeOffline(node.NodeIP, true)
			} else {
				klog.V(2).Infof("Node %s may be offline... retrying", node.NodeIP)
				needRetry = true
			}
		}
	}

	return needRetry
}

func (eit *EgressIPTracker) watchNetNamespaces(netNamespaceInformer networkinformers.NetNamespaceInformer) {
	funcs := InformerFuncs(&networkv1.NetNamespace{}, eit.handleAddOrUpdateNetNamespace, eit.handleDeleteNetNamespace)
	netNamespaceInformer.Informer().AddEventHandler(funcs)
}

func (eit *EgressIPTracker) handleAddOrUpdateNetNamespace(obj, _ interface{}, eventType watch.EventType) {
	netns := obj.(*networkv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", eventType, netns.Name)

	eit.UpdateNetNamespaceEgress(netns)
}

func (eit *EgressIPTracker) handleDeleteNetNamespace(obj interface{}) {
	netns := obj.(*networkv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", watch.Deleted, netns.Name)

	eit.DeleteNetNamespaceEgress(netns.NetID)
}

func (eit *EgressIPTracker) UpdateNetNamespaceEgress(netns *networkv1.NetNamespace) {
	eit.Lock()
	defer eit.Unlock()

	ns := eit.namespacesByVNID[netns.NetID]
	if ns == nil {
		if len(netns.EgressIPs) == 0 {
			return
		}
		ns = &namespaceEgress{vnid: netns.NetID}
		eit.namespacesByVNID[netns.NetID] = ns
	} else if len(netns.EgressIPs) == 0 {
		delete(eit.namespacesByVNID, netns.NetID)
	}

	oldRequestedIPs := sets.NewString(ns.requestedIPs...)
	ns.requestedIPs = make([]string, 0, len(netns.EgressIPs))
	for _, ip := range netns.EgressIPs {
		ns.requestedIPs = append(ns.requestedIPs, string(ip))
	}
	newRequestedIPs := sets.NewString(ns.requestedIPs...)

	// Process new and removed EgressIPs
	for _, ip := range newRequestedIPs.Difference(oldRequestedIPs).UnsortedList() {
		eit.addNamespaceEgressIP(ns, ip)
	}
	for _, ip := range oldRequestedIPs.Difference(newRequestedIPs).UnsortedList() {
		eit.deleteNamespaceEgressIP(ns, ip)
	}

	// Even IPs that weren't added/removed need to be considered "changed", to
	// ensure we correctly process reorderings, duplicates added/removed, etc.
	for _, ip := range newRequestedIPs.Intersection(oldRequestedIPs).UnsortedList() {
		if eg := eit.egressIPs[ip]; eg != nil {
			eit.egressIPChanged(eg)
		}
	}

	eit.syncEgressIPs()
}

func (eit *EgressIPTracker) DeleteNetNamespaceEgress(vnid uint32) {
	eit.UpdateNetNamespaceEgress(&networkv1.NetNamespace{
		NetID: vnid,
	})
}

func (eit *EgressIPTracker) egressIPActive(eg *egressIPInfo) (bool, error) {
	if len(eg.nodes) == 0 || len(eg.namespaces) == 0 {
		return false, nil
	}
	if len(eg.nodes) > 1 {
		return false, fmt.Errorf("Multiple nodes (%s, %s) claiming EgressIP %s", eg.nodes[0].NodeIP, eg.nodes[1].NodeIP, eg.ip)
	}
	if len(eg.namespaces) > 1 {
		return false, fmt.Errorf("Multiple namespaces (%d, %d) claiming EgressIP %s", eg.namespaces[0].vnid, eg.namespaces[1].vnid, eg.ip)
	}
	for _, ip := range eg.namespaces[0].requestedIPs {
		eg2 := eit.egressIPs[ip]
		if eg2 != nil && eg2 != eg && len(eg2.nodes) == 1 && eg2.nodes[0] == eg.nodes[0] {
			return false, fmt.Errorf("Multiple EgressIPs (%s, %s) for VNID %d on node %s", eg.ip, eg2.ip, eg.namespaces[0].vnid, eg.nodes[0].NodeIP)
		}
	}
	return true, nil
}

func (eit *EgressIPTracker) syncEgressIPs() {
	changedEgressIPs := eit.changedEgressIPs
	eit.changedEgressIPs = make(map[*egressIPInfo]bool)

	changedNamespaces := eit.changedNamespaces
	eit.changedNamespaces = make(map[*namespaceEgress]bool)

	for eg := range changedEgressIPs {
		active, err := eit.egressIPActive(eg)
		if err != nil {
			utilruntime.HandleError(err)
		}
		eit.syncEgressNodeState(eg, active)
	}

	for ns := range changedNamespaces {
		eit.syncEgressNamespaceState(ns)
	}

	for eg := range changedEgressIPs {
		if len(eg.namespaces) == 0 && len(eg.nodes) == 0 {
			delete(eit.egressIPs, eg.ip)
		}
	}

	if eit.updateEgressCIDRs {
		eit.updateEgressCIDRs = false
		if eit.nodesWithCIDRs > 0 {
			eit.watcher.UpdateEgressCIDRs()
		}
	}
}

func (eit *EgressIPTracker) syncEgressNodeState(eg *egressIPInfo, active bool) {
	if active && eg.assignedNodeIP != eg.nodes[0].NodeIP {
		klog.V(4).Infof("Assigning egress IP %s to node %s", eg.ip, eg.nodes[0].NodeIP)
		eg.assignedNodeIP = eg.nodes[0].NodeIP
		eit.watcher.ClaimEgressIP(eg.namespaces[0].vnid, eg.ip, eg.assignedNodeIP, eg.nodes[0].NodeName)
	} else if !active && eg.assignedNodeIP != "" {
		klog.V(4).Infof("Removing egress IP %s from node %s", eg.ip, eg.assignedNodeIP)
		eit.watcher.ReleaseEgressIP(eg.ip, eg.assignedNodeIP)
		eg.assignedNodeIP = ""
	}

	if eg.assignedNodeIP == "" {
		eit.updateEgressCIDRs = true
	}
}

func (eit *EgressIPTracker) syncEgressNamespaceState(ns *namespaceEgress) {
	if len(ns.requestedIPs) == 0 {
		if len(ns.activeEgressIPs) != 0 || ns.shouldDropTraffic {
			ns.activeEgressIPs = []EgressIPAssignment{}
			ns.shouldDropTraffic = false
			eit.watcher.SetNamespaceEgressNormal(ns.vnid)
		}
		return
	}

	activeEgressIPs := make([]EgressIPAssignment, 0, len(ns.requestedIPs))
	for _, ip := range ns.requestedIPs {
		eg := eit.egressIPs[ip]
		if eg == nil {
			continue
		}
		if len(eg.namespaces) > 1 {
			klog.V(4).Infof("VNID %d gets no egress due to multiply-assigned egress IP %s", ns.vnid, eg.ip)
			activeEgressIPs = nil
			break
		}
		eg.assignedVNID = ns.vnid
		if eg.assignedNodeIP == "" {
			klog.V(4).Infof("VNID %d cannot use unassigned egress IP %s", ns.vnid, eg.ip)
		} else if len(ns.requestedIPs) > 1 && eg.nodes[0].offline {
			klog.V(4).Infof("VNID %d cannot use egress IP %s on offline node %s", ns.vnid, eg.ip, eg.assignedNodeIP)
		} else {
			activeEgressIPs = append(activeEgressIPs, EgressIPAssignment{NodeIP: eg.assignedNodeIP, EgressIP: eg.ip})
		}
	}

	if len(activeEgressIPs) > 0 {
		if !activeEgressIPsTheSame(ns.activeEgressIPs, activeEgressIPs) {
			ns.activeEgressIPs = activeEgressIPs
			ns.shouldDropTraffic = false
			eit.watcher.SetNamespaceEgressViaEgressIPs(ns.vnid, ns.activeEgressIPs)
		}
	} else {
		if !ns.shouldDropTraffic {
			ns.activeEgressIPs = []EgressIPAssignment{}
			ns.shouldDropTraffic = true
			eit.watcher.SetNamespaceEgressDropped(ns.vnid)
		}
	}
}

// Assumes the EgressIPTracker lock is held.
func (eit *EgressIPTracker) SetNodeOffline(nodeIP string, offline bool) {
	node := eit.nodesByNodeIP[nodeIP]
	if node == nil {
		return
	}

	node.offline = offline
	for _, ip := range node.requestedIPs.UnsortedList() {
		eg := eit.egressIPs[ip]
		if eg != nil {
			eit.egressIPChanged(eg)
		}
	}

	if node.requestedCIDRs.Len() != 0 {
		eit.updateEgressCIDRs = true
	}

	eit.syncEgressIPs()
}

func (eit *EgressIPTracker) lookupNodeIP(ip string) string {
	if node := eit.nodesByNodeIP[ip]; node != nil {
		return node.sdnIP
	}
	return ip
}

// Ping a node and return whether or not we think it is online. We do this by trying to
// open a TCP connection to the "discard" service (port 9); if the node is offline, the
// attempt will either time out with no response, or else return "no route to host" (and
// we will return false). If the node is online then we presumably will get a "connection
// refused" error; but the code below assumes that anything other than timeout or "no
// route" indicates that the node is online.
func (eit *EgressIPTracker) Ping(ip string, timeout time.Duration) bool {
	// If the caller used a public node IP, replace it with the SDN IP
	ip = eit.lookupNodeIP(ip)

	conn, err := net.DialTimeout("tcp", ip+":9", timeout)
	if conn != nil {
		conn.Close()
	}
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Timeout() {
			return false
		}
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok && sysErr.Err == syscall.EHOSTUNREACH {
			return false
		}
	}
	return true
}

func (eit *EgressIPTracker) nodeHasEgressIPForNamespace(node *NodeEgress, eip *egressIPInfo, allocation map[string][]string) bool {
	if namespace, ok := eit.namespacesByVNID[eip.assignedVNID]; ok {
		if sets.NewString(allocation[node.NodeName]...).HasAny(namespace.requestedIPs...) {
			return true
		}
	}
	return false
}

// Finds the best node to allocate the egress IP to, given the existing allocation. The
// boolean return value indicates whether multiple nodes could host the IP.
func (eit *EgressIPTracker) findEgressIPAllocation(eip *egressIPInfo, allocation map[string][]string) (string, bool) {
	bestNode := ""
	otherNodes := false

	for _, node := range eit.nodes {
		if node.offline {
			continue
		}
		if eit.nodeHasEgressIPForNamespace(node, eip, allocation) {
			continue
		}
		egressIPs := allocation[node.NodeName]
		for _, parsed := range node.parsedCIDRs {
			if parsed.Contains(eip.parsed) {
				if bestNode != "" {
					otherNodes = true
					if len(allocation[bestNode]) < len(egressIPs) {
						break
					}
				}
				bestNode = node.NodeName
				break
			}
		}
	}

	return bestNode, otherNodes
}

func (eit *EgressIPTracker) makeEmptyAllocation() (map[string][]string, map[string]bool) {
	allocation := make(map[string][]string)
	alreadyAllocated := make(map[string]bool)

	// Filter out egressIPs that we don't want to auto-assign. This will also cause
	// them to be unassigned if they were previously auto-assigned.
	for egressIP, eip := range eit.egressIPs {
		if len(eip.namespaces) == 0 {
			// Unused
			alreadyAllocated[egressIP] = true
		} else if len(eip.nodes) > 1 || len(eip.namespaces) > 1 {
			// Erroneously allocated to multiple nodes or multiple namespaces
			alreadyAllocated[egressIP] = true
		}
	}

	return allocation, alreadyAllocated
}

func (eit *EgressIPTracker) allocateExistingEgressIPs(allocation map[string][]string, alreadyAllocated map[string]bool) bool {
	removedEgressIPs := false

	for _, node := range eit.nodes {
		if len(node.parsedCIDRs) > 0 {
			allocation[node.NodeName] = make([]string, 0, node.requestedIPs.Len())
		}
	}
	// For each active egress IP, if it still fits within some egress CIDR on its node,
	// add it to that node's allocation.
	for egressIP, eip := range eit.egressIPs {
		if eip.assignedNodeIP == "" || alreadyAllocated[egressIP] {
			continue
		}
		node := eip.nodes[0]
		found := false
		for _, parsed := range node.parsedCIDRs {
			if parsed.Contains(eip.parsed) {
				found = true
				break
			}
		}
		if found && !node.offline {
			allocation[node.NodeName] = append(allocation[node.NodeName], egressIP)
		} else {
			removedEgressIPs = true
		}
		// (We set alreadyAllocated even if the egressIP will be removed from
		// its current node; we can't assign it to a new node until the next
		// reallocation.)
		alreadyAllocated[egressIP] = true
	}

	return removedEgressIPs
}

func (eit *EgressIPTracker) allocateNewEgressIPs(allocation map[string][]string, alreadyAllocated map[string]bool) {
	// Allocate pending egress IPs that can only go to a single node
	for egressIP, eip := range eit.egressIPs {
		if alreadyAllocated[egressIP] {
			continue
		}
		nodeName, otherNodes := eit.findEgressIPAllocation(eip, allocation)
		if nodeName != "" && !otherNodes {
			allocation[nodeName] = append(allocation[nodeName], egressIP)
			alreadyAllocated[egressIP] = true
		}
	}
	// Allocate any other pending egress IPs that we can
	for egressIP, eip := range eit.egressIPs {
		if alreadyAllocated[egressIP] {
			continue
		}
		nodeName, _ := eit.findEgressIPAllocation(eip, allocation)
		if nodeName != "" {
			allocation[nodeName] = append(allocation[nodeName], egressIP)
		}
	}
}

// ReallocateEgressIPs returns a map from Node name to array-of-Egress-IP for all auto-allocated egress IPs
func (eit *EgressIPTracker) ReallocateEgressIPs() map[string][]string {
	eit.Lock()
	defer eit.Unlock()

	allocation, alreadyAllocated := eit.makeEmptyAllocation()
	removedEgressIPs := eit.allocateExistingEgressIPs(allocation, alreadyAllocated)
	eit.allocateNewEgressIPs(allocation, alreadyAllocated)
	if removedEgressIPs {
		// Process the removals now; we'll get called again afterward and can
		// check for balance then.
		return allocation
	}

	// Compare the allocation to what we would have gotten if we started from scratch,
	// to see if things have gotten too unbalanced. (In particular, if a node goes
	// offline, gets emptied, and then comes back online, we want to move a bunch of
	// egress IPs back onto that node.)
	fullReallocation, alreadyAllocated := eit.makeEmptyAllocation()
	eit.allocateNewEgressIPs(fullReallocation, alreadyAllocated)

	emptyNodes := []string{}
	for nodeName, fullEgressIPs := range fullReallocation {
		incrementalEgressIPs := allocation[nodeName]
		if len(incrementalEgressIPs) < len(fullEgressIPs)/2 {
			emptyNodes = append(emptyNodes, nodeName)
		}
	}

	if len(emptyNodes) > 0 {
		// Make a new incremental allocation, but skipping all of the egress IPs
		// that got assigned to the "empty" nodes in the full reallocation; this
		// will cause them to be dropped from their current nodes and then later
		// reassigned (to one of the "empty" nodes, for balance).
		allocation, alreadyAllocated = eit.makeEmptyAllocation()
		for _, nodeName := range emptyNodes {
			for _, egressIP := range fullReallocation[nodeName] {
				alreadyAllocated[egressIP] = true
			}
		}
		eit.allocateExistingEgressIPs(allocation, alreadyAllocated)
		eit.allocateNewEgressIPs(allocation, alreadyAllocated)
		eit.updateEgressCIDRs = true
	}

	return allocation
}

func activeEgressIPsTheSame(oldEIPs, newEIPs []EgressIPAssignment) bool {
	if len(oldEIPs) != len(newEIPs) {
		return false
	}

	for _, olderEIPAssignment := range oldEIPs {
		found := false
		for _, newerEIPAssignment := range newEIPs {
			if newerEIPAssignment == olderEIPAssignment {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true

}
