// +build linux

package node

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/util/async"

	networkv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/network/node/ovs"
)

const HostNetworkNamespace = "openshift-host-network"

type networkPolicyPlugin struct {
	node   *OsdnNode
	vnids  *nodeVNIDMap
	runner *async.BoundedFrequencyRunner

	lock sync.Mutex
	// namespacesByName includes every Namespace, including ones that we haven't seen
	// a NetNamespace for, and is only used in the informer-related methods.
	namespacesByName map[string]*npNamespace
	// namespaces includes only the namespaces that we have a VNID for, and is used
	// for all flow-generating methods
	namespaces map[uint32]*npNamespace
	// nsMatchCache caches matches for namespaceSelectors; see selectNamespaceInternal
	nsMatchCache map[string]*npCacheEntry
}

// npNamespace tracks NetworkPolicy-related data for a Namespace
type npNamespace struct {
	name  string
	vnid  uint32
	inUse bool

	// mustRecalculate is true if we need to recalculate policy .flows/.selectedIPs
	mustRecalculate bool
	// mustSync is true if we need to push updated flows to OVS
	mustSync bool

	labels   map[string]string
	policies map[ktypes.UID]*npPolicy

	gotNamespace    bool
	gotNetNamespace bool
}

// npPolicy is a parsed version of a single NetworkPolicy object
type npPolicy struct {
	policy            networkingv1.NetworkPolicy
	watchesNamespaces bool
	watchesAllPods    bool
	watchesOwnPods    bool

	flows         []string
	selectedIPs   []string
	selectsAllIPs bool
}

// npCacheEntry caches information about matches for a LabelSelector
type npCacheEntry struct {
	selector labels.Selector
	matches  map[string]uint32
}

func NewNetworkPolicyPlugin() osdnPolicy {
	return &networkPolicyPlugin{
		namespaces:       make(map[uint32]*npNamespace),
		namespacesByName: make(map[string]*npNamespace),

		nsMatchCache: make(map[string]*npCacheEntry),
	}
}

func (np *networkPolicyPlugin) Name() string {
	return networkutils.NetworkPolicyPluginName
}

func (np *networkPolicyPlugin) SupportsVNIDs() bool {
	return true
}

func (np *networkPolicyPlugin) Start(node *OsdnNode) error {
	np.lock.Lock()
	defer np.lock.Unlock()

	np.node = node
	np.vnids = newNodeVNIDMap(np, node.networkClient)
	if err := np.vnids.Start(node.networkInformers); err != nil {
		return err
	}

	otx := node.oc.NewTransaction()
	for _, cn := range np.node.networkInfo.ClusterNetworks {
		// Must pass packets through CT NAT to ensure NAT state is handled
		// correctly by OVS when NAT-ed packets have tuple collisions.
		// https://bugzilla.redhat.com/show_bug.cgi?id=1910378
		otx.AddFlow("table=21, priority=200, ip, nw_dst=%s, ct_state=-rpl, actions=ct(commit,nat(src=0.0.0.0),table=30)", cn.ClusterCIDR.String())
	}
	otx.AddFlow("table=80, priority=200, ip, ct_state=+rpl, actions=output:NXM_NX_REG2[]")
	if err := otx.Commit(); err != nil {
		return err
	}

	// Rate-limit calls to np.syncFlows to 1-per-second after the 2nd call within 1
	// second. The maxInterval (time.Hour) is irrelevant here because we always call
	// np.runner.Run() if there is syncing to be done.
	np.runner = async.NewBoundedFrequencyRunner("NetworkPolicy", np.syncFlows, time.Second, time.Hour, 2)
	go np.runner.Loop(utilwait.NeverStop)

	if err := np.initNamespaces(); err != nil {
		return err
	}

	np.watchNamespaces()
	np.watchPods()
	np.watchNetworkPolicies()
	return nil
}

func (np *networkPolicyPlugin) initNamespaces() error {
	inUseVNIDs := np.node.oc.FindPolicyVNIDs()

	namespaces, err := np.node.kClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ns := range namespaces.Items {
		npns := newNPNamespace(ns.Name)
		npns.labels = ns.Labels
		npns.gotNamespace = true
		np.namespacesByName[ns.Name] = npns

		// can't call WaitAndGetVNID here, because it calls back in to np
		// and we hold the lock!
		if vnid, err := np.vnids.getVNID(ns.Name); err == nil {
			npns.vnid = vnid
			npns.inUse = inUseVNIDs.Has(int(vnid))
			npns.gotNetNamespace = true
			np.namespaces[vnid] = npns
		}
	}

	policies, err := np.node.kClient.NetworkingV1().NetworkPolicies(corev1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, policy := range policies.Items {
		vnid, err := np.vnids.getVNID(policy.Namespace)
		if err != nil {
			continue
		}
		npns := np.namespaces[vnid]
		np.updateNetworkPolicy(npns, &policy)
	}

	return nil
}

func newNPNamespace(name string) *npNamespace {
	return &npNamespace{
		name:     name,
		policies: make(map[ktypes.UID]*npPolicy),
	}
}

func (np *networkPolicyPlugin) AddNetNamespace(netns *networkv1.NetNamespace) {
	np.lock.Lock()
	defer np.lock.Unlock()

	npns := np.namespacesByName[netns.NetName]
	if npns == nil {
		npns = newNPNamespace(netns.NetName)
		np.namespacesByName[netns.NetName] = npns
	}

	npns.vnid = netns.NetID
	npns.inUse = false
	np.namespaces[netns.NetID] = npns

	npns.gotNetNamespace = true
	if npns.gotNamespace {
		np.updateMatchCache(npns)
		np.refreshNamespaceNetworkPolicies()
	}
}

func (np *networkPolicyPlugin) UpdateNetNamespace(netns *networkv1.NetNamespace, oldNetID uint32) {
	if netns.NetID != oldNetID {
		klog.Warningf("Got VNID change for namespace %s while using %s plugin", netns.NetName, networkutils.NetworkPolicyPluginName)
	}

	np.node.podManager.UpdateLocalMulticastRules(netns.NetID)
}

func (np *networkPolicyPlugin) DeleteNetNamespace(netns *networkv1.NetNamespace) {
	np.lock.Lock()
	defer np.lock.Unlock()

	npns, exists := np.namespaces[netns.NetID]
	if !exists {
		return
	}

	if npns.inUse {
		npns.inUse = false
		// This needs to happen before we forget about the namespace.
		np.syncNamespaceImmediately(npns)
	}
	delete(np.namespaces, netns.NetID)
	npns.gotNetNamespace = false

	// We don't need to call refreshNetworkPolicies here; if the VNID doesn't get
	// reused then the stale flows won't hurt anything, and if it does get reused then
	// things will be cleaned up then. However, we do have to clean up the cache.
	np.updateMatchCache(npns)
}

func (np *networkPolicyPlugin) GetVNID(namespace string) (uint32, error) {
	return np.vnids.WaitAndGetVNID(namespace)
}

func (np *networkPolicyPlugin) GetNamespaces(vnid uint32) []string {
	return np.vnids.GetNamespaces(vnid)
}

func (np *networkPolicyPlugin) GetMulticastEnabled(vnid uint32) bool {
	return np.vnids.GetMulticastEnabled(vnid)
}

func (np *networkPolicyPlugin) syncNamespace(npns *npNamespace) {
	if !npns.mustSync {
		npns.mustSync = true
		np.runner.Run()
	}
}

func (np *networkPolicyPlugin) syncNamespaceImmediately(npns *npNamespace) {
	otx := np.node.oc.NewTransaction()
	np.generateNamespaceFlows(otx, npns)
	if err := otx.Commit(); err != nil {
		utilruntime.HandleError(fmt.Errorf("Error syncing OVS flows for namespace %q: %v", npns.name, err))
	}
}

// This is the entry point for the BoundedFrequencyRunner
func (np *networkPolicyPlugin) syncFlows() {
	np.lock.Lock()
	defer np.lock.Unlock()

	np.recalculate()

	// Push internal data to OVS (for namespaces that have changed)
	otx := np.node.oc.NewTransaction()
	for _, npns := range np.namespaces {
		if npns.mustSync {
			np.generateNamespaceFlows(otx, npns)
			npns.mustSync = false
		}
	}
	if err := otx.Commit(); err != nil {
		utilruntime.HandleError(fmt.Errorf("Error syncing OVS flows: %v", err))
	}
}

// Update internal data to reflect recent pod/namespace changes
func (np *networkPolicyPlugin) recalculate() {
	for _, npns := range np.namespaces {
		if npns.mustRecalculate {
			for _, npp := range npns.policies {
				if np.updateNetworkPolicy(npns, &npp.policy) {
					npns.mustSync = true
				}
			}
			npns.mustRecalculate = false
		}
	}
}

func (np *networkPolicyPlugin) generateNamespaceFlows(otx ovs.Transaction, npns *npNamespace) {
	klog.V(5).Infof("syncNamespace %d", npns.vnid)
	otx.DeleteFlows("table=80, reg1=%d", npns.vnid)
	if npns.inUse {
		allPodsSelected := false

		// Add "allow" rules for all traffic allowed by a NetworkPolicy
		for _, npp := range npns.policies {
			for _, flow := range npp.flows {
				otx.AddFlow("table=80, priority=150, reg1=%d, %s actions=output:NXM_NX_REG2[]", npns.vnid, flow)
			}
			if npp.selectsAllIPs {
				allPodsSelected = true
			}
		}

		if allPodsSelected {
			// Some policy selects all pods, so all pods are "isolated" and no
			// traffic is allowed beyond what we explicitly allowed above. (And
			// the "priority=0, actions=drop" rule will filter out all remaining
			// traffic in this Namespace).
		} else {
			// No policy selects all pods, so we need an "else accept" rule to
			// allow traffic to pod IPs that aren't selected by a policy. But
			// before that we need rules to drop any remaining traffic for any pod
			// IP that *is* selected by a policy.
			selectedIPs := sets.NewString()
			for _, npp := range npns.policies {
				for _, ip := range npp.selectedIPs {
					if !selectedIPs.Has(ip) {
						selectedIPs.Insert(ip)
						otx.AddFlow("table=80, priority=100, reg1=%d, ip, nw_dst=%s, actions=drop", npns.vnid, ip)
					}
				}
			}

			otx.AddFlow("table=80, priority=50, reg1=%d, actions=output:NXM_NX_REG2[]", npns.vnid)
		}
	}
}

func (np *networkPolicyPlugin) EnsureVNIDRules(vnid uint32) {
	np.lock.Lock()
	defer np.lock.Unlock()

	npns, exists := np.namespaces[vnid]
	if !exists || npns.inUse {
		return
	}

	npns.inUse = true
	np.syncNamespace(npns)
}

func (np *networkPolicyPlugin) SyncVNIDRules() {
	np.lock.Lock()
	defer np.lock.Unlock()

	unused := np.node.oc.FindUnusedVNIDs()
	klog.Infof("SyncVNIDRules: %d unused VNIDs", len(unused))

	for _, vnid := range unused {
		npns, exists := np.namespaces[uint32(vnid)]
		if exists {
			npns.inUse = false
			np.syncNamespace(npns)
		}
	}
}

// Match namespaces against a selector, using a cache so that, eg, when a new Namespace is
// added, we only figure out if it matches "name: default" once, rather than recomputing
// the set of namespaces that match that selector for every single "allow-from-default"
// policy in the cluster.
//
// Yes, if a selector matches against multiple labels then the order they appear in
// cacheKey here is non-deterministic, but that just means that, eg, we might compute the
// results twice rather than just once, and twice is still better than 10,000 times.
func (np *networkPolicyPlugin) selectNamespacesInternal(selector labels.Selector) map[string]uint32 {
	cacheKey := selector.String()
	match := np.nsMatchCache[cacheKey]
	if match == nil {
		match = &npCacheEntry{selector: selector, matches: make(map[string]uint32)}
		for vnid, npns := range np.namespaces {
			if npns.gotNamespace && selector.Matches(labels.Set(npns.labels)) {
				// handle host network namespace as special and classify it as vnid 0 for
				// network policy purposes, so it can ride upon the handling of default
				// namespace for host network traffic.
				if npns.name == HostNetworkNamespace {
					match.matches[npns.name] = 0
				} else {
					match.matches[npns.name] = vnid
				}
			}
		}
		np.nsMatchCache[cacheKey] = match
	}
	return match.matches
}

func (np *networkPolicyPlugin) updateMatchCache(npns *npNamespace) {
	for _, match := range np.nsMatchCache {
		if npns.gotNamespace && npns.gotNetNamespace && match.selector.Matches(labels.Set(npns.labels)) {
			match.matches[npns.name] = npns.vnid
		} else {
			delete(match.matches, npns.name)
		}
	}
}

func (np *networkPolicyPlugin) flushMatchCache(lsel *metav1.LabelSelector) {
	selector, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		// Shouldn't happen
		utilruntime.HandleError(fmt.Errorf("ValidateNetworkPolicy() failure! Invalid NamespaceSelector: %v", err))
		return
	}
	delete(np.nsMatchCache, selector.String())
}

func (np *networkPolicyPlugin) selectPodsFromNamespaces(nsLabelSel, podLabelSel *metav1.LabelSelector) []string {
	var peerFlows []string

	nsSel, err := metav1.LabelSelectorAsSelector(nsLabelSel)
	if err != nil {
		// Shouldn't happen
		utilruntime.HandleError(fmt.Errorf("ValidateNetworkPolicy() failure! Invalid NamespaceSelector: %v", err))
		return nil
	}

	podSel, err := metav1.LabelSelectorAsSelector(podLabelSel)
	if err != nil {
		// Shouldn't happen
		utilruntime.HandleError(fmt.Errorf("ValidateNetworkPolicy() failure! Invalid PodSelector: %v", err))
		return nil
	}

	nsLister := np.node.kubeInformers.Core().V1().Pods().Lister()
	for namespace, vnid := range np.selectNamespacesInternal(nsSel) {
		pods, err := nsLister.Pods(namespace).List(podSel)
		if err != nil {
			// Shouldn't happen
			utilruntime.HandleError(fmt.Errorf("Could not find matching pods in namespace %q: %v", namespace, err))
			continue
		}
		for _, pod := range pods {
			if isOnPodNetwork(pod) {
				peerFlows = append(peerFlows, fmt.Sprintf("reg0=%d, ip, nw_src=%s, ", vnid, pod.Status.PodIP))
			}
		}
	}

	return peerFlows
}

func (np *networkPolicyPlugin) selectNamespaces(lsel *metav1.LabelSelector) []string {
	var peerFlows []string
	sel, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		// Shouldn't happen
		utilruntime.HandleError(fmt.Errorf("ValidateNetworkPolicy() failure! Invalid NamespaceSelector: %v", err))
		return peerFlows
	}

	namespaces := np.selectNamespacesInternal(sel)
	for _, vnid := range namespaces {
		peerFlows = append(peerFlows, fmt.Sprintf("reg0=%d, ", vnid))
	}
	return peerFlows
}

func (np *networkPolicyPlugin) selectPods(npns *npNamespace, lsel *metav1.LabelSelector) []string {
	ips := []string{}
	sel, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		// Shouldn't happen
		utilruntime.HandleError(fmt.Errorf("ValidateNetworkPolicy() failure! Invalid PodSelector: %v", err))
		return ips
	}

	pods, err := np.node.kubeInformers.Core().V1().Pods().Lister().Pods(npns.name).List(sel)
	if err != nil {
		// Shouldn't happen
		utilruntime.HandleError(fmt.Errorf("Could not find matching pods in namespace %q: %v", npns.name, err))
		return ips
	}
	for _, pod := range pods {
		if isOnPodNetwork(pod) {
			ips = append(ips, pod.Status.PodIP)
		}
	}
	return ips
}

func (np *networkPolicyPlugin) parseNetworkPolicy(npns *npNamespace, policy *networkingv1.NetworkPolicy) *npPolicy {
	npp := &npPolicy{policy: *policy}

	var affectsIngress, affectsEgress bool
	for _, ptype := range policy.Spec.PolicyTypes {
		if ptype == networkingv1.PolicyTypeIngress {
			affectsIngress = true
		} else if ptype == networkingv1.PolicyTypeEgress {
			if !affectsEgress {
				klog.Warningf("Ignoring egress rules in NetworkPolicy %s/%s", policy.Namespace, policy.Name)
			}
			affectsEgress = true
		}
	}
	if !affectsIngress {
		// The rest of this function assumes that all policies affect ingress: a
		// policy that only affects egress is, for our purposes, equivalent to one
		// that affects ingress but does not select any pods.
		npp.selectedIPs = nil
		npp.selectsAllIPs = false
		return npp
	}

	var destFlows []string
	if len(policy.Spec.PodSelector.MatchLabels) > 0 || len(policy.Spec.PodSelector.MatchExpressions) > 0 {
		npp.watchesOwnPods = true
		npp.selectedIPs = np.selectPods(npns, &policy.Spec.PodSelector)
		for _, ip := range npp.selectedIPs {
			destFlows = append(destFlows, fmt.Sprintf("ip, nw_dst=%s, ", ip))
		}
	} else {
		npp.selectedIPs = nil
		npp.selectsAllIPs = true
		destFlows = []string{""}
	}

	for _, rule := range policy.Spec.Ingress {
		var portFlows, peerFlows []string
		if len(rule.Ports) == 0 {
			portFlows = []string{""}
		}
		for _, port := range rule.Ports {
			var protocol string
			if port.Protocol == nil {
				protocol = "tcp"
			} else if *port.Protocol == corev1.ProtocolTCP || *port.Protocol == corev1.ProtocolUDP || *port.Protocol == corev1.ProtocolSCTP {
				protocol = strings.ToLower(string(*port.Protocol))
			} else {
				// upstream is unlikely to add any more protocol values, but just in case...
				klog.Warningf("Ignoring rule in NetworkPolicy %s/%s with unrecognized Protocol %q", policy.Namespace, policy.Name, *port.Protocol)
				continue
			}
			var portNum int
			if port.Port == nil {
				portFlows = append(portFlows, fmt.Sprintf("%s, ", protocol))
				continue
			} else if port.Port.Type != intstr.Int {
				klog.Warningf("Ignoring rule in NetworkPolicy %s/%s with unsupported named port %q", policy.Namespace, policy.Name, port.Port.StrVal)
				continue
			} else {
				portNum = int(port.Port.IntVal)
			}
			portFlows = append(portFlows, fmt.Sprintf("%s, tp_dst=%d, ", protocol, portNum))
		}

		if len(rule.From) == 0 {
			peerFlows = []string{""}
		}
		for _, peer := range rule.From {
			if peer.PodSelector != nil && peer.NamespaceSelector == nil {
				if len(peer.PodSelector.MatchLabels) == 0 && len(peer.PodSelector.MatchExpressions) == 0 {
					// The PodSelector is empty, meaning it selects all pods in this namespace
					peerFlows = append(peerFlows, fmt.Sprintf("reg0=%d, ", npns.vnid))
				} else {
					npp.watchesOwnPods = true
					for _, ip := range np.selectPods(npns, peer.PodSelector) {
						peerFlows = append(peerFlows, fmt.Sprintf("reg0=%d, ip, nw_src=%s, ", npns.vnid, ip))
					}
				}
			} else if peer.NamespaceSelector != nil && peer.PodSelector == nil {
				if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
					// The NamespaceSelector is empty, meaning it selects all namespaces
					peerFlows = append(peerFlows, "")
				} else {
					npp.watchesNamespaces = true
					peerFlows = append(peerFlows, np.selectNamespaces(peer.NamespaceSelector)...)
				}
			} else {
				npp.watchesNamespaces = true
				npp.watchesAllPods = true
				peerFlows = append(peerFlows, np.selectPodsFromNamespaces(peer.NamespaceSelector, peer.PodSelector)...)
			}

			if peer.IPBlock != nil {
				if peer.IPBlock.Except != nil {
					// Currently IPBlocks with except rules are skipped.
					klog.Warningf("IPBlocks with except rules are not supported (NetworkPolicy [%s], Namespace [%s])", policy.Name, policy.Namespace)
				} else {
					// Network Policy has ipBlocks, allow traffic from those ips.
					peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_src=%s, ", peer.IPBlock.CIDR))
				}
			}
		}
		for _, destFlow := range destFlows {
			for _, peerFlow := range peerFlows {
				for _, portFlow := range portFlows {
					npp.flows = append(npp.flows, fmt.Sprintf("%s%s%s", destFlow, peerFlow, portFlow))
				}
			}
		}
	}

	sort.Strings(npp.flows)
	klog.V(5).Infof("Parsed NetworkPolicy: %#v", npp)
	return npp
}

// Cleans up after a NetworkPolicy that is being deleted
func (np *networkPolicyPlugin) cleanupNetworkPolicy(policy *networkingv1.NetworkPolicy) {
	for _, rule := range policy.Spec.Ingress {
		for _, peer := range rule.From {
			if peer.NamespaceSelector != nil {
				if len(peer.NamespaceSelector.MatchLabels) != 0 || len(peer.NamespaceSelector.MatchExpressions) != 0 {
					// This is overzealous; there may still be other policies
					// with the same selector. But it's simple.
					np.flushMatchCache(peer.NamespaceSelector)
				}
			}
		}
	}
}

func (np *networkPolicyPlugin) updateNetworkPolicy(npns *npNamespace, policy *networkingv1.NetworkPolicy) bool {
	npp := np.parseNetworkPolicy(npns, policy)
	oldNPP, existed := npns.policies[policy.UID]
	npns.policies[policy.UID] = npp

	changed := !existed || !reflect.DeepEqual(oldNPP.flows, npp.flows) || !reflect.DeepEqual(oldNPP.selectedIPs, npp.selectedIPs) || oldNPP.selectsAllIPs != npp.selectsAllIPs
	if !changed {
		klog.V(5).Infof("NetworkPolicy %s/%s is unchanged", policy.Namespace, policy.Name)
	}
	return changed
}

func (np *networkPolicyPlugin) watchNetworkPolicies() {
	funcs := common.InformerFuncs(&networkingv1.NetworkPolicy{}, np.handleAddOrUpdateNetworkPolicy, np.handleDeleteNetworkPolicy)
	np.node.kubeInformers.Networking().V1().NetworkPolicies().Informer().AddEventHandler(funcs)
}

func (np *networkPolicyPlugin) handleAddOrUpdateNetworkPolicy(obj, _ interface{}, eventType watch.EventType) {
	policy := obj.(*networkingv1.NetworkPolicy)
	klog.V(5).Infof("Watch %s event for NetworkPolicy %s/%s", eventType, policy.Namespace, policy.Name)

	vnid, err := np.vnids.WaitAndGetVNID(policy.Namespace)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Could not find VNID for NetworkPolicy %s/%s", policy.Namespace, policy.Name))
		return
	}

	np.lock.Lock()
	defer np.lock.Unlock()

	if npns, exists := np.namespaces[vnid]; exists {
		if changed := np.updateNetworkPolicy(npns, policy); changed {
			if npns.inUse {
				np.syncNamespace(npns)
			}
		}
	}
}

func (np *networkPolicyPlugin) handleDeleteNetworkPolicy(obj interface{}) {
	policy := obj.(*networkingv1.NetworkPolicy)
	klog.V(5).Infof("Watch %s event for NetworkPolicy %s/%s", watch.Deleted, policy.Namespace, policy.Name)

	vnid, err := np.vnids.WaitAndGetVNID(policy.Namespace)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Could not find VNID for NetworkPolicy %s/%s", policy.Namespace, policy.Name))
		return
	}

	np.lock.Lock()
	defer np.lock.Unlock()

	if npns, exists := np.namespaces[vnid]; exists {
		np.cleanupNetworkPolicy(policy)
		delete(npns.policies, policy.UID)
		if npns.inUse {
			np.syncNamespace(npns)
		}
	}
}

func (np *networkPolicyPlugin) watchPods() {
	funcs := common.InformerFuncs(&corev1.Pod{}, np.handleAddOrUpdatePod, np.handleDeletePod)
	np.node.kubeInformers.Core().V1().Pods().Informer().AddEventHandler(funcs)
}

func isOnPodNetwork(pod *corev1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return pod.Status.PodIP != ""
}

func (np *networkPolicyPlugin) handleAddOrUpdatePod(obj, old interface{}, eventType watch.EventType) {
	pod := obj.(*corev1.Pod)
	klog.V(5).Infof("Watch %s event for Pod %q", eventType, getPodFullName(pod))

	if !isOnPodNetwork(pod) {
		return
	}

	if old != nil {
		oldPod := old.(*corev1.Pod)
		if oldPod.Status.PodIP == pod.Status.PodIP && reflect.DeepEqual(oldPod.Labels, pod.Labels) {
			return
		}
	}

	np.lock.Lock()
	defer np.lock.Unlock()

	np.refreshPodNetworkPolicies(pod)
}

func (np *networkPolicyPlugin) handleDeletePod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	klog.V(5).Infof("Watch %s event for Pod %q", watch.Deleted, getPodFullName(pod))

	np.lock.Lock()
	defer np.lock.Unlock()

	np.refreshPodNetworkPolicies(pod)
}

func (np *networkPolicyPlugin) watchNamespaces() {
	funcs := common.InformerFuncs(&corev1.Namespace{}, np.handleAddOrUpdateNamespace, np.handleDeleteNamespace)
	np.node.kubeInformers.Core().V1().Namespaces().Informer().AddEventHandler(funcs)
}

func (np *networkPolicyPlugin) handleAddOrUpdateNamespace(obj, _ interface{}, eventType watch.EventType) {
	ns := obj.(*corev1.Namespace)
	klog.V(5).Infof("Watch %s event for Namespace %q", eventType, ns.Name)

	np.lock.Lock()
	defer np.lock.Unlock()

	npns := np.namespacesByName[ns.Name]
	if npns == nil {
		npns = newNPNamespace(ns.Name)
		np.namespacesByName[ns.Name] = npns
	}

	if npns.gotNamespace && reflect.DeepEqual(npns.labels, ns.Labels) {
		return
	}
	npns.labels = ns.Labels

	npns.gotNamespace = true
	if npns.gotNetNamespace {
		np.updateMatchCache(npns)
		np.refreshNamespaceNetworkPolicies()
	}
}

func (np *networkPolicyPlugin) handleDeleteNamespace(obj interface{}) {
	ns := obj.(*corev1.Namespace)
	klog.V(5).Infof("Watch %s event for Namespace %q", watch.Deleted, ns.Name)

	np.lock.Lock()
	defer np.lock.Unlock()

	npns := np.namespacesByName[ns.Name]
	if npns == nil {
		return
	}

	delete(np.namespacesByName, ns.Name)
	npns.gotNamespace = false

	// We don't need to call refreshNetworkPolicies here; if the VNID doesn't get
	// reused then the stale flows won't hurt anything, and if it does get reused then
	// things will be cleaned up then. However, we do have to clean up the cache.
	np.updateMatchCache(npns)
}

func (np *networkPolicyPlugin) refreshNamespaceNetworkPolicies() {
	for _, npns := range np.namespaces {
		for _, npp := range npns.policies {
			if npp.watchesNamespaces {
				npns.mustRecalculate = true
			}
		}
		if npns.mustRecalculate && npns.inUse {
			np.syncNamespace(npns)
		}
	}
}

func (np *networkPolicyPlugin) refreshPodNetworkPolicies(pod *corev1.Pod) {
	podNs := np.namespacesByName[pod.Namespace]
	for _, npns := range np.namespaces {
		for _, npp := range npns.policies {
			if (npp.watchesOwnPods && npns == podNs) || npp.watchesAllPods {
				npns.mustRecalculate = true
			}
		}
		if npns.mustRecalculate && npns.inUse {
			np.syncNamespace(npns)
		}
	}
}

func getPodFullName(pod *corev1.Pod) string {
	return fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
}
