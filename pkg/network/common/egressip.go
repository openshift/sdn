package common

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	osdnv1 "github.com/openshift/api/network/v1"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	"github.com/openshift/sdn/pkg/network/master/metrics"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
)

const (
	nodeEgressIPConfigAnnotationKey = "cloud.network.openshift.io/egress-ipconfig"
	// unlimitedNodeCapacity indicates a discarded capacity - useful on
	// bare-metal where this is ignored.
	unlimitedNodeCapacity = math.MaxInt32

	// DefaultPollInterval default poll interval used for egress node reachability check
	DefaultPollInterval = 5 * time.Second

	// RepollInterval poll interval used for egress node reachability check retries
	RepollInterval = time.Second
)

type ifAddr struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type capacity struct {
	IPv4 int `json:"ipv4,omitempty"`
	IPv6 int `json:"ipv6,omitempty"`
	IP   int `json:"ip,omitempty"`
}

type nodeCloudEgressIPConfiguration struct {
	Interface string   `json:"interface"`
	IFAddr    ifAddr   `json:"ifaddr"`
	Capacity  capacity `json:"capacity"`
}

type nodeEgress struct {
	nodeName string
	nodeIP   string
	sdnIP    string

	requestedIPs   sets.String
	requestedCIDRs sets.String
	parsedCIDRs    map[string]*net.IPNet

	offline bool

	capacity int
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

	nodes      []*nodeEgress
	namespaces []*namespaceEgress

	assignedNodeIP string
	assignedVNID   uint32
}

type EgressIPWatcher interface {
	Synced()

	ClaimEgressIP(vnid uint32, egressIP, nodeIP, sdnIP string, nodeOffline bool)
	ReleaseEgressIP(egressIP, nodeIP string)

	SetNamespaceEgressNormal(vnid uint32)
	SetNamespaceEgressDropped(vnid uint32)
	SetNamespaceEgressViaEgressIPs(vnid uint32, activeEgressIPs []EgressIPAssignment)

	UpdateEgressCIDRs()
}

type EgressIPTracker struct {
	sync.Mutex

	CloudEgressIP bool

	watcher EgressIPWatcher

	kubeClient kubernetes.Interface

	nodes            map[ktypes.UID]*nodeEgress
	nodesByNodeIP    map[string]*nodeEgress
	namespacesByVNID map[uint32]*namespaceEgress
	egressIPs        map[string]*egressIPInfo
	nodesWithCIDRs   int

	changedEgressIPs  map[*egressIPInfo]bool
	changedNamespaces map[*namespaceEgress]bool
	updateEgressCIDRs bool
}

func NewEgressIPTracker(watcher EgressIPWatcher, cloudEgressIP bool) *EgressIPTracker {
	return &EgressIPTracker{
		watcher: watcher,

		CloudEgressIP: cloudEgressIP,

		nodes:            make(map[ktypes.UID]*nodeEgress),
		nodesByNodeIP:    make(map[string]*nodeEgress),
		namespacesByVNID: make(map[uint32]*namespaceEgress),
		egressIPs:        make(map[string]*egressIPInfo),

		changedEgressIPs:  make(map[*egressIPInfo]bool),
		changedNamespaces: make(map[*namespaceEgress]bool),
	}
}

func (eit *EgressIPTracker) Start(kubeClient kubernetes.Interface, hostSubnetInformer osdninformers.HostSubnetInformer, netNamespaceInformer osdninformers.NetNamespaceInformer, nodeInformer kcoreinformers.NodeInformer) {

	eit.kubeClient = kubeClient
	eit.watchHostSubnets(hostSubnetInformer)
	eit.watchNetNamespaces(netNamespaceInformer)

	if nodeInformer != nil {
		eit.watchNodes(nodeInformer)
	}

	go func() {
		cache.WaitForCacheSync(utilwait.NeverStop,
			hostSubnetInformer.Informer().HasSynced,
			netNamespaceInformer.Informer().HasSynced)
		if nodeInformer != nil {
			cache.WaitForCacheSync(utilwait.NeverStop, nodeInformer.Informer().HasSynced)
		}

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

func (eit *EgressIPTracker) addNodeEgressIP(node *nodeEgress, egressIP string) {
	eg := eit.ensureEgressIPInfo(egressIP)
	eg.nodes = append(eg.nodes, node)

	eit.egressIPChanged(eg)
}

func (eit *EgressIPTracker) deleteNodeEgressIP(node *nodeEgress, egressIP string) {
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

func (eit *EgressIPTracker) watchHostSubnets(hostSubnetInformer osdninformers.HostSubnetInformer) {
	funcs := InformerFuncs(&osdnv1.HostSubnet{}, eit.handleAddOrUpdateHostSubnet, eit.handleDeleteHostSubnet)
	hostSubnetInformer.Informer().AddEventHandler(funcs)
}

func (eit *EgressIPTracker) handleAddOrUpdateHostSubnet(obj, _ interface{}, eventType watch.EventType) {
	hs := obj.(*osdnv1.HostSubnet)
	klog.V(5).Infof("Watch %s event for HostSubnet %q", eventType, hs.Name)

	if err := ValidateHostSubnetEgress(hs); err != nil {
		klog.Errorf("Ignoring invalid HostSubnet %s: %v", HostSubnetToString(hs), err)
		return
	}
	if hs.Subnet == "" {
		klog.V(5).Infof("Ignoring HostSubnet %s with an empty subnet", HostSubnetToString(hs))
		return
	}
	if len(hs.EgressCIDRs) > 0 && eit.CloudEgressIP {
		if err := eit.validateEgressCIDRsAreSubnetOfCloudNetwork(hs); err != nil {
			klog.Errorf("Ignoring invalid HostSubnet %s: %v", HostSubnetToString(hs), err)
			return
		}
	}
	if len(hs.EgressIPs) > 0 && len(hs.EgressCIDRs) == 0 && eit.CloudEgressIP {
		if err := eit.validateEgressIPs(hs); err != nil {
			klog.Errorf("Ignoring invalid HostSubnet %s: %v", HostSubnetToString(hs), err)
			return
		}
	}
	eit.UpdateHostSubnetEgress(hs)
}

func (eit *EgressIPTracker) handleDeleteHostSubnet(obj interface{}) {
	hs := obj.(*osdnv1.HostSubnet)
	klog.V(5).Infof("Watch %s event for HostSubnet %q", watch.Deleted, hs.Name)

	hs = hs.DeepCopy()
	hs.EgressCIDRs = nil
	hs.EgressIPs = nil

	if err := ValidateHostSubnetEgress(hs); err != nil {
		klog.Errorf("Ignoring invalid HostSubnet %s: %v", HostSubnetToString(hs), err)
		return
	}
	if hs.Subnet == "" {
		klog.V(5).Infof("Ignoring HostSubnet %s with an empty subnet", HostSubnetToString(hs))
		return
	}

	eit.UpdateHostSubnetEgress(hs)
}

func (eit *EgressIPTracker) UpdateHostSubnetEgress(hs *osdnv1.HostSubnet) {
	eit.Lock()
	defer eit.Unlock()

	_, cidr, _ := net.ParseCIDR(hs.Subnet)
	sdnIP := GenerateDefaultGateway(cidr).String()

	node := eit.nodes[hs.UID]
	if node == nil {
		if len(hs.EgressIPs) == 0 && len(hs.EgressCIDRs) == 0 {
			return
		}
		node = &nodeEgress{
			nodeName:     hs.Host,
			nodeIP:       hs.HostIP,
			sdnIP:        sdnIP,
			requestedIPs: sets.NewString(),
			capacity:     unlimitedNodeCapacity,
		}
		eit.nodes[hs.UID] = node
		eit.nodesByNodeIP[hs.HostIP] = node
	} else if len(hs.EgressIPs) == 0 && len(hs.EgressCIDRs) == 0 {
		delete(eit.nodes, hs.UID)
		delete(eit.nodesByNodeIP, node.nodeIP)
	}

	// We need to handle the case where the SDN pods restart, upon which both
	// the Node will have the annotation set and all resources will already be
	// existing, meaning: we might receive the HostSubnet event after the Node
	// event, which means we need to lookup the Node annotation as to sync our
	// data correctly.
	if eit.CloudEgressIP && node.capacity == unlimitedNodeCapacity {
		if err := eit.initNodeCapacity(hs.Name, node); err != nil {
			klog.Errorf("Error initializing capacity for Node %q, err: %v", hs.Name, err)
			return
		}
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

	if node.nodeIP != hs.HostIP {
		// We have to clean up the old egress IP mappings and call syncEgressIPs
		// before we can change node.nodeIP
		movedEgressIPs := make([]string, 0, node.requestedIPs.Len())
		for _, ip := range node.requestedIPs.UnsortedList() {
			eg := eit.egressIPs[ip]
			if eg != nil && eg.assignedNodeIP == node.nodeIP {
				movedEgressIPs = append(movedEgressIPs, ip)
				eit.deleteNodeEgressIP(node, ip)
			}
		}
		eit.syncEgressIPs()

		delete(eit.nodesByNodeIP, node.nodeIP)
		node.nodeIP = hs.HostIP
		eit.nodesByNodeIP[node.nodeIP] = node

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
	eit.recordMetrics()
}

func (eit *EgressIPTracker) GetNodeNameByNodeIP(nodeIP string) string {
	if node, exists := eit.nodesByNodeIP[nodeIP]; exists {
		return node.nodeName
	}
	return ""
}

func (eit *EgressIPTracker) watchNodes(nodeInformer kcoreinformers.NodeInformer) {
	funcs := InformerFuncs(&corev1.Node{}, eit.handleAddOrUpdateNode, nil)
	nodeInformer.Informer().AddEventHandler(funcs)
}

func (eit *EgressIPTracker) handleAddOrUpdateNode(obj, _ interface{}, eventType watch.EventType) {
	eit.Lock()
	defer eit.Unlock()

	node := obj.(*corev1.Node)
	klog.V(5).Infof("Watch %s event for Node %q", eventType, node.Name)

	nodeIP := GetNodeInternalIP(node)
	if nodeIP == "" {
		klog.Errorf("node does not have an IPv4 InternalIP address")
		return
	}
	if nodeEgress, exists := eit.nodesByNodeIP[nodeIP]; exists {
		if err := eit.initNodeCapacity(node.Name, nodeEgress); err != nil {
			klog.Errorf("Error initializing capacity for Node %q, err: %v", node.Name, err)
		}
	}
}

// validateEgressCIDRsAreSubnetOfCloudNetwork checks that whatever egress CIDRs are specified
// on the HostSubnet also are a subnet of the cloud network. A failure to
// specify this correctly might lead to egress IP assignments by the SDN which
// are not allowed by the cloud provider.
func (eit *EgressIPTracker) validateEgressCIDRsAreSubnetOfCloudNetwork(hs *osdnv1.HostSubnet) error {
	cloudEgressIPConfig, err := eit.validateEgressIPConfigExists(hs)
	if err != nil {
		return err
	}
	_, cloudNetwork, _ := net.ParseCIDR(cloudEgressIPConfig.IFAddr.IPv4)
	for _, egressCIDR := range hs.EgressCIDRs {
		_, egressSubnet, _ := net.ParseCIDR(string(egressCIDR))
		if !isSubnet(cloudNetwork, egressSubnet) {
			return fmt.Errorf("EgressCIDR: %v is not a subnet of the cloud network: %v", egressSubnet, cloudNetwork)
		}
	}
	return nil
}

// validateEgressIPCapacity checks that whatever egressIPs are specified
// on the HostSubnet do not exceed the capacity of the node.
func (eit *EgressIPTracker) validateEgressIPs(hs *osdnv1.HostSubnet) error {
	cloudEgressIPConfig, err := eit.validateEgressIPConfigExists(hs)
	if err != nil {
		return err
	}
	capacity := cloudEgressIPConfig.Capacity.IP
	if capacity == 0 {
		capacity = cloudEgressIPConfig.Capacity.IPv4
	}
	if len(hs.EgressIPs) > capacity {
		return fmt.Errorf("the amount of requested EgressIPs (%v) on hostSubnet: %q exceeds the node's capacity (%v)", len(hs.EgressIPs), hs.Name, capacity)
	}
	_, cloudNetwork, _ := net.ParseCIDR(cloudEgressIPConfig.IFAddr.IPv4)
	for _, egressIP := range hs.EgressIPs {
		ip := net.ParseIP(string(egressIP))
		if !cloudNetwork.Contains(ip) {
			return fmt.Errorf("the defined egress IP %v is not on the cloud network: %v", ip, cloudNetwork)
		}
	}
	return nil
}

func (eit *EgressIPTracker) validateEgressIPConfigExists(hs *osdnv1.HostSubnet) (*nodeCloudEgressIPConfiguration, error) {
	cloudEgressIPConfig, err := eit.GetNodeCloudEgressIPConfig(hs.Host)
	if err != nil {
		return nil, err
	}
	if cloudEgressIPConfig == nil {
		return nil, fmt.Errorf("related node object %q has an incomplete annotation %q, CloudEgressIPConfig: %+v", hs.Host, nodeEgressIPConfigAnnotationKey, cloudEgressIPConfig)
	}
	return cloudEgressIPConfig, nil
}

// GetNodeCloudEgressIPConfig returns cloud egress IP config for the specified node
func (eit *EgressIPTracker) GetNodeCloudEgressIPConfig(nodeName string) (*nodeCloudEgressIPConfiguration, error) {
	node, err := eit.kubeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving node %q, err: %v", nodeName, err)
	}

	nodeCloudEgressIPAnnotation, exists := node.Annotations[nodeEgressIPConfigAnnotationKey]
	if !exists {
		return nil, nil
	}
	cloudEgressIPConfig := []nodeCloudEgressIPConfiguration{}
	if err := json.Unmarshal([]byte(nodeCloudEgressIPAnnotation), &cloudEgressIPConfig); err != nil {
		return nil, fmt.Errorf("error de-serializing annotation: %q, err: %v", nodeCloudEgressIPAnnotation, err)
	}
	if len(cloudEgressIPConfig) > 0 {
		return &cloudEgressIPConfig[0], nil
	}
	return nil, nil
}

func (eit *EgressIPTracker) initNodeCapacity(nodeName string, nodeEgress *nodeEgress) error {
	if nodeEgress.capacity != unlimitedNodeCapacity {
		return nil
	}
	cloudEgressIPConfig, err := eit.GetNodeCloudEgressIPConfig(nodeName)
	if err != nil {
		return err
	}
	if cloudEgressIPConfig == nil {
		return nil
	}
	// IP and IPv4 are mutually exclusive, so either one or the other is
	// guaranteed to be set if this annotation exists.
	if cloudEgressIPConfig.Capacity.IP != 0 {
		nodeEgress.capacity = cloudEgressIPConfig.Capacity.IP
	} else {
		nodeEgress.capacity = cloudEgressIPConfig.Capacity.IPv4
	}
	klog.Infof("Initialized egress IP capacity: %v for Node: %q", nodeEgress.capacity, nodeName)
	return nil
}

func (eit *EgressIPTracker) watchNetNamespaces(netNamespaceInformer osdninformers.NetNamespaceInformer) {
	funcs := InformerFuncs(&osdnv1.NetNamespace{}, eit.handleAddOrUpdateNetNamespace, eit.handleDeleteNetNamespace)
	netNamespaceInformer.Informer().AddEventHandler(funcs)
}

func (eit *EgressIPTracker) handleAddOrUpdateNetNamespace(obj, _ interface{}, eventType watch.EventType) {
	netns := obj.(*osdnv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", eventType, netns.Name)

	eit.UpdateNetNamespaceEgress(netns)
}

func (eit *EgressIPTracker) handleDeleteNetNamespace(obj interface{}) {
	netns := obj.(*osdnv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", watch.Deleted, netns.Name)

	eit.DeleteNetNamespaceEgress(netns.NetID)
}

func (eit *EgressIPTracker) UpdateNetNamespaceEgress(netns *osdnv1.NetNamespace) {
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
	eit.UpdateNetNamespaceEgress(&osdnv1.NetNamespace{
		NetID: vnid,
	})
}

func (eit *EgressIPTracker) egressIPActive(eg *egressIPInfo) (bool, error) {
	if len(eg.nodes) == 0 || len(eg.namespaces) == 0 {
		return false, nil
	}
	if len(eg.nodes) > 1 {
		return false, fmt.Errorf("Multiple nodes (%s, %s) claiming EgressIP %s", eg.nodes[0].nodeIP, eg.nodes[1].nodeIP, eg.ip)
	}
	if len(eg.namespaces) > 1 {
		return false, fmt.Errorf("Multiple namespaces (%d, %d) claiming EgressIP %s", eg.namespaces[0].vnid, eg.namespaces[1].vnid, eg.ip)
	}
	for _, ip := range eg.namespaces[0].requestedIPs {
		eg2 := eit.egressIPs[ip]
		if eg2 != nil && eg2 != eg && len(eg2.nodes) == 1 && eg2.nodes[0] == eg.nodes[0] {
			return false, fmt.Errorf("Multiple EgressIPs (%s, %s) for VNID %d on node %s", eg.ip, eg2.ip, eg.namespaces[0].vnid, eg.nodes[0].nodeIP)
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
			klog.Errorf("Error processing egress IPs: %v", err)
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
	if active && eg.assignedNodeIP != eg.nodes[0].nodeIP {
		klog.V(4).Infof("Assigning egress IP %s to node %s", eg.ip, eg.nodes[0].nodeIP)
		eg.assignedNodeIP = eg.nodes[0].nodeIP
		eit.watcher.ClaimEgressIP(eg.namespaces[0].vnid, eg.ip, eg.assignedNodeIP, eg.nodes[0].sdnIP, eg.nodes[0].offline)
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
		} else if eg.nodes[0].offline {
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

func (eit *EgressIPTracker) SetNodeOffline(nodeIP string, offline bool) {
	eit.Lock()
	defer eit.Unlock()

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

// Ping a node on its SDN IP and return whether we think it is online. We do this by trying to
// open a TCP connection to the "discard" service (port 9); if the node is offline, the
// attempt will either time out with no response, or else return "no route to host" (and
// we will return false). If the node is online then we presumably will get a "connection
// refused" error; but the code below assumes that anything other than timeout or "no
// route" indicates that the node is online.
// It is required that the IP provided is from SDN, nodes primary IP might drop traffic destined to port 9
func (eit *EgressIPTracker) Ping(sdnIP string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(sdnIP, "9"), timeout)
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

func (eit *EgressIPTracker) nodeHasEgressIPForNamespace(node *nodeEgress, eip *egressIPInfo, allocation map[string][]string) bool {
	if namespace, ok := eit.namespacesByVNID[eip.assignedVNID]; ok {
		if sets.NewString(allocation[node.nodeName]...).HasAny(namespace.requestedIPs...) {
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

	// Given a capacity constraint allocation problem: we need to assign IPs to
	// `bestNode` with the highest availability (capacity - current assignment).
	// This is needed as to avoid sub-optimal allocations, meaning: avoiding
	// assigning IPs to nodes with low availability first only to realize later
	// that the remaining IPs can't be allocated to the nodes with higher
	// availability because they violate other constraints, such as: already
	// having another IP in that namespace allocated to it. Hence we need to
	// sort nodes in increasing order of availability as to make sure the
	// `bestNode` gets chosen as the node with the highest availability out of
	// the set of nodes that are tied for having the fewest current egress IPs,
	// out of the set of nodes that don't currently have an assignment for this
	// namespace.
	sortedNodes := eit.getSortedNodes(eip, allocation)
	for _, node := range sortedNodes {
		egressIPs := allocation[node.nodeName]
		for _, parsed := range node.parsedCIDRs {
			if parsed.Contains(eip.parsed) {
				if bestNode != "" {
					otherNodes = true
					if len(allocation[bestNode]) < len(egressIPs) {
						break
					}
				}
				bestNode = node.nodeName
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
			allocation[node.nodeName] = make([]string, 0, node.requestedIPs.Len())
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
		if found && !node.offline && node.capacity-len(allocation[node.nodeName]) > 0 {
			allocation[node.nodeName] = append(allocation[node.nodeName], egressIP)
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

// getSortedEgressIPs will generate a sorted list of egress IPs following a
// round-robin procedure with an ascending order based on the amount of
// allocations to each namespace, i.e: according to the following strategy:
// namespace1 [1,2,3]
// namespace2 [4,5]
// namespace3 [6]
// will return [6,4,1,5,2,3]
func (eit *EgressIPTracker) getSortedEgressIPs() []*egressIPInfo {
	largestRequestedEgressIPIdx := 0
	sortedNamespaces := make([]*namespaceEgress, 0, len(eit.namespacesByVNID))
	for _, namespace := range eit.namespacesByVNID {
		sortedNamespaces = append(sortedNamespaces, namespace)
		if len(namespace.requestedIPs) > largestRequestedEgressIPIdx {
			largestRequestedEgressIPIdx = len(namespace.requestedIPs)
		}
	}
	sort.Slice(sortedNamespaces, func(i, j int) bool {
		return len(sortedNamespaces[i].requestedIPs) < len(sortedNamespaces[j].requestedIPs)
	})
	sortedEgressIPs := make([]*egressIPInfo, 0, len(eit.egressIPs))
	for i := 0; i < largestRequestedEgressIPIdx; i++ {
		for _, namespace := range sortedNamespaces {
			if len(namespace.requestedIPs)-1 >= i {
				requestedEgressIP := namespace.requestedIPs[i]
				sortedEgressIPs = append(sortedEgressIPs, eit.egressIPs[requestedEgressIP])
			}
		}
	}
	return sortedEgressIPs
}

// getSortedNodes will return a sorted slice of *nodeEgress in ascending order of
// availability (capacity - current assignment)
func (eit *EgressIPTracker) getSortedNodes(eip *egressIPInfo, allocation map[string][]string) []*nodeEgress {
	sNodes := make([]*nodeEgress, 0, len(eit.nodes))
	for _, node := range eit.nodes {
		if node.offline {
			continue
		}
		if eit.nodeHasEgressIPForNamespace(node, eip, allocation) {
			continue
		}
		egressIPs := allocation[node.nodeName]
		if node.capacity-len(egressIPs) <= 0 {
			continue
		}
		sNodes = append(sNodes, node)
	}
	sort.Slice(sNodes, func(i, j int) bool {
		// We can't use nodeEgress.requestedIPs.Len() here because if a
		// netnamespace change triggers the re-allocation:
		// nodeEgress.requestedIPs won't be updated until after the
		// recomputation has been made, and we start updating the HostSubnet.
		iNode := sNodes[i]
		iEgressIPs := allocation[iNode.nodeName]
		jNode := sNodes[j]
		jEgressIPs := allocation[jNode.nodeName]
		return iNode.capacity-len(iEgressIPs) < jNode.capacity-len(jEgressIPs)
	})
	return sNodes
}

func (eit *EgressIPTracker) allocateNewEgressIPs(allocation map[string][]string, alreadyAllocated map[string]bool) {
	// Allocate pending egress IPs that can only go to a single node. Given a
	// capacity constraint allocation problem: we need to round-robin assign IPs
	// from every namespace, where the IPs have been sorted in ascending order
	// from the namespace with the lowest amount of requested egress IPs. Given
	// that these egress IP will be assigned to the nodes with the highest
	// capacity; we begin by solving the  most constrained allocation problem
	// first, leaving the IPs with more options for later. Consider the
	// following example:

	// node1, capacity = 2
	// node2, capacity = 1

	// namespace1, egressIPs = [1,2]
	// namespace2, egressIPs = [3]

	// the optimal assignment would be:

	// node1 [3,1]
	// node2 [2]

	// For that to occur we need a sortedEgressIPs slice following the order:
	// [3,1,2]. [1,3,2] would result in the following assignment:

	// node1 [1]
	// node2 [3]

	// which is sub-optimal. If we however have the following scenario:

	// node1, capacity = 1
	// node2, capacity = 1
	// node2, capacity = 1

	// namespace1, egressIPs = [1,2,3]
	// namespace2, egressIPs = [4,5]
	// namespace3, egressIPs = [6]

	// The optimal allocation is performed by sorting sortedEgressIPs following:
	// [6,4,1] and assigning:

	// node1 [6]
	// node2 [4]
	// node3 [1]
	sortedEgressIPs := eit.getSortedEgressIPs()
	for _, eip := range sortedEgressIPs {
		if alreadyAllocated[eip.ip] {
			continue
		}
		nodeName, otherNodes := eit.findEgressIPAllocation(eip, allocation)
		if nodeName != "" && !otherNodes {
			allocation[nodeName] = append(allocation[nodeName], eip.ip)
			alreadyAllocated[eip.ip] = true
		}
	}
	// Allocate any other pending egress IPs that we can
	for _, eip := range sortedEgressIPs {
		if alreadyAllocated[eip.ip] {
			continue
		}
		nodeName, _ := eit.findEgressIPAllocation(eip, allocation)
		if nodeName != "" {
			allocation[nodeName] = append(allocation[nodeName], eip.ip)
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

	// Compare the allocation to what we would have gotten if we started from
	// scratch, to see if things have gotten too unbalanced or if we can assign
	// more egress IPs globally across the cluster.
	fullReallocation, alreadyAllocated := eit.makeEmptyAllocation()
	eit.allocateNewEgressIPs(fullReallocation, alreadyAllocated)

	// The following checks balance, in particular, if a node goes offline, gets
	// emptied, and then comes back online, we want to move a bunch of egress
	// IPs back onto that node.
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

func (eit *EgressIPTracker) recordMetrics() {
	activeEgressIPCount := 0.0
	for _, eipInfo := range eit.egressIPs {
		if eipInfo.assignedNodeIP != "" {
			activeEgressIPCount += 1
		}
	}
	metrics.RecordEgressIPCount(activeEgressIPCount)
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

func PlatformUsesCloudEgressIP(platformType string) bool {
	return platformType == string(configv1.AWSPlatformType) ||
		platformType == string(configv1.AzurePlatformType) ||
		platformType == string(configv1.GCPPlatformType)
}
