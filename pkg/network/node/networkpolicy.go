package node

import (
	"context"
	"fmt"
	"math"
	"os"
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
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/util/async"
	utilnet "k8s.io/utils/net"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/util/ovs"
	"github.com/openshift/sdn/pkg/util/ranges"
)

const HostNetworkNamespace = "openshift-host-network"

// NetPolIsolationCookie is a random number to distinguish network policy isolation flows,
// only used by network policy functions
const NetPolIsolationCookie = 1147582955

const migrationEnvVar = "NODE_CNI"

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
	// nsMatchCache caches matches for namespaceSelectors; see selectNamespacesInternal
	nsMatchCache map[string]*npCacheEntry

	warnedPolicies  map[ktypes.UID]string
	skippedPolicies map[ktypes.UID]string
	// network policy needs to know pod ip to get updated and delete pod isolation flows.
	// since pod.Status.PodIP is not set during pod creation, we keep a separate cache of ips already known to sdn,
	// but not yet known to the apiserver. When pod.Status.PodIP is set, pod can be deleted from this map
	localPodIPs map[ktypes.UID]string
	// unProcessedVNIDs holds the vnid entries for which EnsureVNIDRules() is already invoked upon
	// pod setup even before AddNetNamespace() is invoked. This is possible when WaitAndGetVNID()
	// could return the vnid in the pod setup thread and then the setup thread continues, before
	// the AddNetNamespace() call runs in the handler thread. In such scenario populate the vnid
	// into unProcessedVNIDs in EnsureVNIDRules() method and it can be looked up later in
	// AddNetNamespace() method so that required nw policy flow rules programmed into OVS.
	unProcessedVNIDs sets.Int32

	// indicate if the node is running in SDN live migration mode
	inMigrationMode bool
}

// npNamespace tracks NetworkPolicy-related data for a Namespace
type npNamespace struct {
	name string
	vnid uint32

	// inUse tracks whether the namespace is in use by any pods on this node
	inUse bool

	// mustRecalculate is true if we need to recalculate policy flows/selectedIPs
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

	selectedIPs   []string
	selectsAllIPs bool

	affectsIngress bool
	ingressFlows   []string

	affectsEgress bool
	egressFlows   []string
}

// npCacheEntry caches information about matches for a LabelSelector
type npCacheEntry struct {
	selector labels.Selector
	matches  map[string]uint32
}

type flowDirection bool

const (
	ingressFlow flowDirection = true
	egressFlow  flowDirection = false
)

func NewNetworkPolicyPlugin() osdnPolicy {
	_, inMigration := os.LookupEnv(migrationEnvVar)
	return &networkPolicyPlugin{
		namespaces:       make(map[uint32]*npNamespace),
		namespacesByName: make(map[string]*npNamespace),

		nsMatchCache: make(map[string]*npCacheEntry),

		warnedPolicies:   make(map[ktypes.UID]string),
		skippedPolicies:  make(map[ktypes.UID]string),
		localPodIPs:      make(map[ktypes.UID]string),
		inMigrationMode:  inMigration,
		unProcessedVNIDs: sets.NewInt32(),
	}
}

func (np *networkPolicyPlugin) Name() string {
	return networkutils.NetworkPolicyPluginName
}

func (np *networkPolicyPlugin) SupportsVNIDs() bool {
	return true
}

func (np *networkPolicyPlugin) AllowDuplicateNetID() bool {
	return false
}

func (np *networkPolicyPlugin) Start(node *OsdnNode) error {
	np.lock.Lock()
	defer np.lock.Unlock()

	np.node = node
	np.vnids = newNodeVNIDMap(np, node.osdnClient)
	if err := np.vnids.Start(node.osdnInformers); err != nil {
		return err
	}

	otx := node.oc.NewTransaction()

	// Egress enforcement for pod-to-Service IP will happen after the packets are rewritten
	// by iptables and come back via table 25.
	otx.AddFlow("table=27, priority=300, ip, nw_dst=%s , actions=goto_table:30", node.networkInfo.ServiceNetwork.String())

	// Skip policy enforcement for replies
	otx.AddFlow("table=80, priority=200, ip, ct_state=+rpl, actions=output:NXM_NX_REG2[]")
	otx.AddFlow("table=27, priority=200, ip, ct_state=+rpl, actions=goto_table:30")

	// Register all pod-network-internal connections with conntrack, so we can later
	// allow replies to them to skip policy enforcement. (We don't do this for traffic
	// leaving the pod network, because those packets usually need to get processed by
	// iptables, but the kernel won't do that if we have already called ct(commit) on
	// them.)
	//
	// The dummy nat(src=0.0.0.0) ensures we handle tuple collisions; see
	// https://bugzilla.redhat.com/show_bug.cgi?id=1910378
	for _, scn := range np.node.networkInfo.ClusterNetworks {
		for _, dcn := range np.node.networkInfo.ClusterNetworks {
			otx.AddFlow("table=30, priority=100, ip, nw_src=%s, nw_dst=%s, ct_state=-rpl, actions=ct(commit,table=31)", scn.ClusterCIDR.String(), dcn.ClusterCIDR.String())
		}
	}

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

	namespaces, err := common.ListAllNamespaces(context.TODO(), np.node.kClient)
	if err != nil {
		return err
	}
	for _, ns := range namespaces {
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

	policies, err := common.ListAllNetworkPolicies(context.TODO(), np.node.kClient)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		vnid, err := np.vnids.getVNID(policy.Namespace)
		if err != nil {
			continue
		}
		npns := np.namespaces[vnid]
		np.updateNetworkPolicy(npns, policy)
	}

	return nil
}

func newNPNamespace(name string) *npNamespace {
	return &npNamespace{
		name:     name,
		policies: make(map[ktypes.UID]*npPolicy),
	}
}

func (np *networkPolicyPlugin) AddNetNamespace(netns *osdnv1.NetNamespace) {
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

	var needNsSync bool
	if np.unProcessedVNIDs.Has(int32(npns.vnid)) {
		needNsSync = true
		np.unProcessedVNIDs.Delete(int32(npns.vnid))
	}
	if needNsSync {
		npns.inUse = true
		np.syncNamespace(npns)
	}

	npns.gotNetNamespace = true
	if npns.gotNamespace {
		np.updateMatchCache(npns)
		np.refreshNamespaceNetworkPolicies()
	}
}

func (np *networkPolicyPlugin) UpdateNetNamespace(netns *osdnv1.NetNamespace, oldNetID uint32) {
	if netns.NetID != oldNetID {
		klog.Warningf("Got VNID change for namespace %s while using %s plugin", netns.NetName, networkutils.NetworkPolicyPluginName)
	}

	np.node.podManager.UpdateLocalMulticastRules(netns.NetID)
}

func (np *networkPolicyPlugin) DeleteNetNamespace(netns *osdnv1.NetNamespace) {
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

	np.unProcessedVNIDs.Delete(int32(npns.vnid))

	// We don't need to call refreshNetworkPolicies here; if the VNID doesn't get
	// reused then the stale flows won't hurt anything, and if it does get reused then
	// things will be cleaned up then. However, we do have to clean up the cache.
	np.updateMatchCache(npns)
}

func (np *networkPolicyPlugin) SetUpPod(pod *corev1.Pod, podIP string) error {
	np.lock.Lock()
	defer np.lock.Unlock()
	np.localPodIPs[pod.UID] = podIP

	syncTriggered := np.refreshPodNetworkPolicies(pod)
	// If network policy update is required for this pod, add isolation rules.
	// syncFlows (which was triggered by refreshPodNetworkPolicies) needs to hold np.lock.Lock()
	// therefore it's safe to add flows after it was triggered
	if syncTriggered {
		otx := np.node.oc.NewTransaction()
		// when a pod is created isolate the pod until the current network policy rules can be evaluated
		otx.AddFlow("table=27, priority=500, cookie=%d, ip, nw_src=%s, actions=drop", NetPolIsolationCookie, podIP)
		otx.AddFlow("table=80, priority=500, cookie=%d, ip, nw_dst=%s, actions=drop", NetPolIsolationCookie, podIP)
		if err := otx.Commit(); err != nil {
			return fmt.Errorf("error syncing OVS flows to isolate pods %v", err)
		}
	}
	return nil
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
		klog.Errorf("Error syncing OVS flows for namespace %q: %v", npns.name, err)
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
	// Remove the temporary flows added by SetUpPod now that all flows have been updated for new pods
	// All isolation flows can be deleted, since flows creation code uses np.lock
	otx.DeleteFlows("table=27, cookie=%d/-1", NetPolIsolationCookie)
	otx.DeleteFlows("table=80, cookie=%d/-1", NetPolIsolationCookie)
	if err := otx.Commit(); err != nil {
		klog.Errorf("Error syncing OVS flows: %v", err)
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
	otx.DeleteFlows("table=27, reg0=%d", npns.vnid)
	if !npns.inUse {
		return
	}

	np.generateNamespaceIngressFlows(otx, npns)
	np.generateNamespaceEgressFlows(otx, npns)
}

func (np *networkPolicyPlugin) generateNamespaceIngressFlows(otx ovs.Transaction, npns *npNamespace) {
	var hasIngressPolicies, allPodsIsolated bool

	// Add "allow" rules for all traffic allowed by a NetworkPolicy
	for _, npp := range npns.policies {
		if !npp.affectsIngress {
			continue
		}

		hasIngressPolicies = true
		if npp.selectsAllIPs {
			allPodsIsolated = true
		}

		for _, flow := range npp.ingressFlows {
			otx.AddFlow("table=80, priority=150, reg1=%d, %s actions=output:NXM_NX_REG2[]", npns.vnid, flow)
		}
	}

	switch {
	case allPodsIsolated:
		// Anything not allowed above is denied and will be rejected by the
		// "priority=0, actions=drop" rule.

	case !hasIngressPolicies:
		// All ingress traffic is accepted
		otx.AddFlow("table=80, priority=50, reg1=%d, actions=output:NXM_NX_REG2[]", npns.vnid)

	default:
		// Some (but not all) pods are isolated; write rules to reject remaining
		// traffic to the isolated pods.
		selectedIPs := sets.NewString()
		for _, npp := range npns.policies {
			if !npp.affectsIngress {
				continue
			}
			for _, ip := range npp.selectedIPs {
				if !selectedIPs.Has(ip) {
					selectedIPs.Insert(ip)
					otx.AddFlow("table=80, priority=100, reg1=%d, ip, nw_dst=%s, actions=drop", npns.vnid, ip)
				}
			}
		}

		// All remaining ingress traffic (ie, to non-isolated pods) is accepted
		otx.AddFlow("table=80, priority=50, reg1=%d, actions=output:NXM_NX_REG2[]", npns.vnid)
	}
}

func (np *networkPolicyPlugin) generateNamespaceEgressFlows(otx ovs.Transaction, npns *npNamespace) {
	var hasEgressPolicies, allPodsIsolated bool

	// Add "allow" rules for all traffic allowed by a NetworkPolicy
	for _, npp := range npns.policies {
		if !npp.affectsEgress {
			continue
		}

		hasEgressPolicies = true
		if npp.selectsAllIPs {
			allPodsIsolated = true
		}

		for _, flow := range npp.egressFlows {
			otx.AddFlow("table=27, priority=150, reg0=%d, %s actions=goto_table:30", npns.vnid, flow)
		}
	}

	switch {
	case allPodsIsolated:
		// Anything not allowed above is denied and will be rejected by the
		// "priority=0, actions=drop" rule.

	case !hasEgressPolicies:
		// All egress traffic is accepted
		otx.AddFlow("table=27, priority=50, reg0=%d, actions=goto_table:30", npns.vnid)

	default:
		// Some (but not all) pods are isolated; write rules to reject remaining
		// traffic to the isolated pods.
		selectedIPs := sets.NewString()
		for _, npp := range npns.policies {
			if !npp.affectsEgress {
				continue
			}
			for _, ip := range npp.selectedIPs {
				if !selectedIPs.Has(ip) {
					selectedIPs.Insert(ip)
					otx.AddFlow("table=27, priority=100, reg0=%d, ip, nw_src=%s, actions=drop", npns.vnid, ip)
				}
			}
		}

		// All remaining egress traffic (ie, to non-isolated pods) is accepted
		otx.AddFlow("table=27, priority=50, reg0=%d, actions=goto_table:30", npns.vnid)
	}
}

func (np *networkPolicyPlugin) skipIfTooManyFlows(policy *networkingv1.NetworkPolicy, numFlows int) bool {
	skip := numFlows >= 10000
	skippedVersion := np.skippedPolicies[policy.UID]

	warn := !skip && numFlows >= 1000
	warnedVersion := np.warnedPolicies[policy.UID]

	npRef := &corev1.ObjectReference{
		APIVersion: "networking.k8s.io/v1",
		Kind:       "NetworkPolicy",
		Namespace:  policy.Namespace,
		Name:       policy.Name,
		UID:        policy.UID,
	}

	switch {
	case skip && skippedVersion != policy.ResourceVersion:
		np.node.recorder.Eventf(npRef, corev1.EventTypeWarning,
			"NetworkPolicySize", "TooManyFlows",
			"This NetworkPolicy generates an extremely large number of OVS flows (%d) and so it will be ignored to prevent network degradation.", numFlows)
		np.skippedPolicies[policy.UID] = policy.ResourceVersion
		delete(np.warnedPolicies, policy.UID)
		klog.Warningf("Ignoring NetworkPolicy %s/%s because it generates an unreasonable number of flows (%d)",
			policy.Namespace, policy.Name, numFlows)

	case warn && warnedVersion != policy.ResourceVersion:
		np.node.recorder.Eventf(npRef, corev1.EventTypeWarning,
			"NetworkPolicySize", "TooManyFlows",
			"This NetworkPolicy generates a very large number of OVS flows (%d) and may degrade network performance.", numFlows)
		np.warnedPolicies[policy.UID] = policy.ResourceVersion
		delete(np.skippedPolicies, policy.UID)
		klog.Warningf("NetworkPolicy %s/%s generates a very large number of flows (%d)",
			policy.Namespace, policy.Name, numFlows)

	case !skip && !warn && (skippedVersion != "" || warnedVersion != ""):
		np.node.recorder.Eventf(npRef, corev1.EventTypeNormal,
			"NetworkPolicySize", "OK",
			"This NetworkPolicy now generates an acceptable number of OVS flows.")
		delete(np.skippedPolicies, policy.UID)
		delete(np.warnedPolicies, policy.UID)
	}

	return skip
}

func (np *networkPolicyPlugin) EnsureVNIDRules(vnid uint32) {
	np.lock.Lock()
	defer np.lock.Unlock()

	npns, exists := np.namespaces[vnid]
	if !exists {
		np.unProcessedVNIDs.Insert(int32(vnid))
		return
	}
	if npns.inUse {
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
		np.unProcessedVNIDs.Delete(int32(vnid))
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
		klog.Errorf("ValidateNetworkPolicy() failure! Invalid NamespaceSelector: %v", err)
		return
	}
	delete(np.nsMatchCache, selector.String())
}

func (np *networkPolicyPlugin) selectPodsFromNamespaces(nsLabelSel, podLabelSel *metav1.LabelSelector, dir flowDirection) []string {
	var peerFlows []string

	nsSel, err := metav1.LabelSelectorAsSelector(nsLabelSel)
	if err != nil {
		// Shouldn't happen
		klog.Errorf("ValidateNetworkPolicy() failure! Invalid NamespaceSelector: %v", err)
		return nil
	}

	podSel, err := metav1.LabelSelectorAsSelector(podLabelSel)
	if err != nil {
		// Shouldn't happen
		klog.Errorf("ValidateNetworkPolicy() failure! Invalid PodSelector: %v", err)
		return nil
	}

	nsLister := np.node.kubeInformers.Core().V1().Pods().Lister()
	for namespace := range np.selectNamespacesInternal(nsSel) {
		pods, err := nsLister.Pods(namespace).List(podSel)
		if err != nil {
			// Shouldn't happen
			klog.Errorf("Could not find matching pods in namespace %q: %v", namespace, err)
			continue
		}
		for _, pod := range pods {
			if np.isOnPodNetwork(pod) {
				if dir == ingressFlow {
					peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_src=%s, ", np.getPodIP(pod)))
				} else {
					peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_dst=%s, ", np.getPodIP(pod)))
				}
			}
		}
	}

	return peerFlows
}

func (np *networkPolicyPlugin) selectNamespaces(lsel *metav1.LabelSelector, dir flowDirection) []string {
	var peerFlows []string
	sel, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		// Shouldn't happen
		klog.Errorf("ValidateNetworkPolicy() failure! Invalid NamespaceSelector: %v", err)
		return peerFlows
	}

	namespaces := np.selectNamespacesInternal(sel)
	for _, vnid := range namespaces {
		if dir == ingressFlow {
			peerFlows = append(peerFlows, fmt.Sprintf("reg0=%d, ", vnid))
		} else {
			peerFlows = append(peerFlows, fmt.Sprintf("reg1=%d, ", vnid))
		}
	}
	return peerFlows
}

func (np *networkPolicyPlugin) selectPods(npns *npNamespace, lsel *metav1.LabelSelector) []string {
	ips := []string{}
	sel, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		// Shouldn't happen
		klog.Errorf("ValidateNetworkPolicy() failure! Invalid PodSelector: %v", err)
		return ips
	}

	pods, err := np.node.kubeInformers.Core().V1().Pods().Lister().Pods(npns.name).List(sel)
	if err != nil {
		// Shouldn't happen
		klog.Errorf("Could not find matching pods in namespace %q: %v", npns.name, err)
		return ips
	}
	for _, pod := range pods {
		if np.isOnPodNetwork(pod) {
			ips = append(ips, np.getPodIP(pod))
		}
	}
	return ips
}

// parsePortFlows parses the Ports of a NetworkPolicy, returning a list of
// distinct restrictions consisting of OpenFlow match rules, each one ending with a
// trailing "," (eg, "tcp, tp_dst=80, "). Every flow which is to be matched by the rule
// must match at least one of the returned restrictions. (If there are no ports specified,
// it returns the no-op restriction "".)
func (np *networkPolicyPlugin) parsePortFlows(policy *networkingv1.NetworkPolicy, ports []networkingv1.NetworkPolicyPort) []string {
	if len(ports) == 0 {
		// no restrictions based on port
		return []string{""}
	}

	portFlows := []string{}
	for _, port := range ports {
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
		} else if port.EndPort != nil {
			start := int(port.Port.IntVal)
			end := int(*port.EndPort)
			for _, portMask := range ranges.PortRangeToPortMasks(start, end) {
				portFlows = append(portFlows, fmt.Sprintf("%s, tp_dst=%s, ", protocol, portMask))
			}
		} else {
			portNum = int(port.Port.IntVal)
		}
		portFlows = append(portFlows, fmt.Sprintf("%s, tp_dst=%d, ", protocol, portNum))
	}

	return portFlows
}

// parsePeerFlows parses the From/To values of a NetworkPolicyRule, returning a list
// of distinct restrictions consisting of OpenFlow match rules, each one ending with a
// trailing "," (eg, "ip, nw_src=10.128.2.4, "). Every flow which is to be
// matched by the rule must match at least one of the returned restrictions. (If there are
// no peers specified, it returns the no-op restriction "".)
func (np *networkPolicyPlugin) parsePeerFlows(npns *npNamespace, npp *npPolicy, peers []networkingv1.NetworkPolicyPeer, dir flowDirection) []string {
	if len(peers) == 0 {
		// no restrictions based on peers
		return []string{""}
	}

	peerFlows := []string{}
	for _, peer := range peers {
		if peer.PodSelector != nil && peer.NamespaceSelector == nil {
			if dir == ingressFlow && (len(peer.PodSelector.MatchLabels) == 0 && len(peer.PodSelector.MatchExpressions) == 0) {
				// The PodSelector is empty, meaning it selects all pods in this namespace
				peerFlows = append(peerFlows, fmt.Sprintf("reg0=%d, ", npns.vnid))
				if np.inMigrationMode {
					npp.watchesOwnPods = true
					for _, ip := range np.selectPods(npns, peer.PodSelector) {
						peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_src=%s, ", ip))
					}
				}
			} else {
				npp.watchesOwnPods = true
				for _, ip := range np.selectPods(npns, peer.PodSelector) {
					if dir == ingressFlow {
						peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_src=%s, ", ip))
					} else {
						peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_dst=%s, ", ip))
					}
				}
			}
		} else if peer.NamespaceSelector != nil && peer.PodSelector == nil {
			if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
				// The NamespaceSelector is empty, meaning it selects all namespaces
				peerFlows = append(peerFlows, "")
			} else if dir == ingressFlow {
				// We can implement namespaceSelectors on ingress by just
				// checking the source VNID...
				npp.watchesNamespaces = true
				peerFlows = append(peerFlows, np.selectNamespaces(peer.NamespaceSelector, dir)...)
				if np.inMigrationMode {
					// In SDN live migration mode, we can't use source VNID to
					// distinguish namespaces for traffic from OVN nodes.
					// So instead we pretend the rule was a combined
					// namespaceSelector+podSelector rule with a match-all
					// podSelector, and generate per-pod-IP match rules.
					npp.watchesAllPods = true
					peerFlows = append(peerFlows, np.selectPodsFromNamespaces(peer.NamespaceSelector, &metav1.LabelSelector{}, dir)...)

					// If the host network namespace is selected, Add rules for
					// the OVN mp0 IP of each node.
					sel, _ := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
					if _, ok := np.nsMatchCache[sel.String()].matches[HostNetworkNamespace]; ok {
						for _, network := range np.node.networkInfo.ClusterNetworks {
							cidrIP := network.ClusterCIDR.IP
							cidrIP[3] = cidrIP[3] | 0x2
							maskLen, _ := network.ClusterCIDR.Mask.Size()
							// use a mask to match the OVN mp0 IP which is the second IP of each host subnet.
							mask := uint32(math.MaxUint32<<(32-maskLen) | math.MaxUint32>>(32-network.HostSubnetLength))
							flow := fmt.Sprintf("ip, nw_src=%s/%d.%d.%d.%d, ", cidrIP, (mask>>24)&0xff, (mask>>16)&0xff, (mask>>8)&0xff, mask&0xff)
							peerFlows = append(peerFlows, flow)
						}
					}
				}
			} else {
				// ... but for namespaceSelectors on egress, we can't just
				// check the destination VNID because we don't know that
				// yet. So instead we pretend the rule was a combined
				// namespaceSelector+podSelector rule with a match-all
				// podSelector, and generate per-pod-IP match rules.
				npp.watchesNamespaces = true
				npp.watchesAllPods = true
				peerFlows = append(peerFlows, np.selectPodsFromNamespaces(peer.NamespaceSelector, &metav1.LabelSelector{}, dir)...)
			}
		} else if peer.NamespaceSelector != nil && peer.PodSelector != nil {
			npp.watchesNamespaces = true
			npp.watchesAllPods = true
			peerFlows = append(peerFlows, np.selectPodsFromNamespaces(peer.NamespaceSelector, peer.PodSelector, dir)...)
		} else if peer.IPBlock != nil {
			// Network Policy has ipBlocks, allow traffic from/to those ips.
			if !utilnet.IsIPv4CIDRString(peer.IPBlock.CIDR) {
				// We don't support IPv6, so we don't need to do anything
				// to allow IPv6 CIDRs.
				continue
			}
			for _, cidr := range ranges.IPBlockToCIDRs(peer.IPBlock) {
				if dir == ingressFlow {
					peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_src=%s, ", cidr))
				} else {
					peerFlows = append(peerFlows, fmt.Sprintf("ip, nw_dst=%s, ", cidr))
				}
			}
		}
	}

	return peerFlows
}

// parseNetworkPolicy parses a NetworkPolicy into an npPolicy
func (np *networkPolicyPlugin) parseNetworkPolicy(npns *npNamespace, policy *networkingv1.NetworkPolicy) *npPolicy {
	npp := &npPolicy{policy: *policy}

	for _, ptype := range policy.Spec.PolicyTypes {
		if ptype == networkingv1.PolicyTypeIngress {
			npp.affectsIngress = true
		} else if ptype == networkingv1.PolicyTypeEgress {
			npp.affectsEgress = true
		}
	}

	var ingressTargetFlows, egressTargetFlows []string
	if len(policy.Spec.PodSelector.MatchLabels) > 0 || len(policy.Spec.PodSelector.MatchExpressions) > 0 {
		npp.watchesOwnPods = true
		npp.selectedIPs = np.selectPods(npns, &policy.Spec.PodSelector)
		for _, ip := range npp.selectedIPs {
			if npp.affectsIngress {
				ingressTargetFlows = append(ingressTargetFlows, fmt.Sprintf("ip, nw_dst=%s, ", ip))
			}
			if npp.affectsEgress {
				egressTargetFlows = append(egressTargetFlows, fmt.Sprintf("ip, nw_src=%s, ", ip))
			}
		}
	} else {
		npp.selectedIPs = nil
		npp.selectsAllIPs = true
		if npp.affectsIngress {
			ingressTargetFlows = []string{""}
		}
		if npp.affectsEgress {
			egressTargetFlows = []string{""}
		}
	}

	if npp.affectsIngress {
		for _, rule := range policy.Spec.Ingress {
			portFlows := np.parsePortFlows(policy, rule.Ports)
			peerFlows := np.parsePeerFlows(npns, npp, rule.From, ingressFlow)

			for _, destFlow := range ingressTargetFlows {
				for _, peerFlow := range peerFlows {
					for _, portFlow := range portFlows {
						npp.ingressFlows = append(npp.ingressFlows, fmt.Sprintf("%s%s%s", destFlow, peerFlow, portFlow))
					}
				}
			}
		}
		sort.Strings(npp.ingressFlows)
	}

	if npp.affectsEgress {
		for _, rule := range policy.Spec.Egress {
			portFlows := np.parsePortFlows(policy, rule.Ports)
			peerFlows := np.parsePeerFlows(npns, npp, rule.To, egressFlow)

			for _, srcFlow := range egressTargetFlows {
				for _, peerFlow := range peerFlows {
					for _, portFlow := range portFlows {
						npp.egressFlows = append(npp.egressFlows, fmt.Sprintf("%s%s%s", srcFlow, peerFlow, portFlow))
					}
				}
			}
		}
		sort.Strings(npp.egressFlows)
	}

	if np.skipIfTooManyFlows(&npp.policy, len(npp.ingressFlows)+len(npp.egressFlows)) {
		npp.ingressFlows = nil
		npp.egressFlows = nil
	}

	klog.V(5).Infof("Parsed NetworkPolicy: %#v", npp)
	return npp
}

// Cleans up after a NetworkPolicy that is being deleted
func (np *networkPolicyPlugin) cleanupNetworkPolicy(policy *networkingv1.NetworkPolicy) {
	for _, rule := range policy.Spec.Ingress {
		for _, peer := range rule.From {
			np.cleanupPeer(peer)
		}
	}
	for _, rule := range policy.Spec.Egress {
		for _, peer := range rule.To {
			np.cleanupPeer(peer)
		}
	}
}

func (np *networkPolicyPlugin) cleanupPeer(peer networkingv1.NetworkPolicyPeer) {
	if peer.NamespaceSelector != nil {
		if len(peer.NamespaceSelector.MatchLabels) != 0 || len(peer.NamespaceSelector.MatchExpressions) != 0 {
			// This is overzealous; there may still be other policies
			// with the same selector. But it's simple.
			np.flushMatchCache(peer.NamespaceSelector)
		}
	}
}

func (np *networkPolicyPlugin) updateNetworkPolicy(npns *npNamespace, policy *networkingv1.NetworkPolicy) bool {
	npp := np.parseNetworkPolicy(npns, policy)
	oldNPP, existed := npns.policies[policy.UID]
	npns.policies[policy.UID] = npp

	changed := !existed || !reflect.DeepEqual(oldNPP.ingressFlows, npp.ingressFlows) || !reflect.DeepEqual(oldNPP.egressFlows, npp.egressFlows) || !reflect.DeepEqual(oldNPP.selectedIPs, npp.selectedIPs) || oldNPP.selectsAllIPs != npp.selectsAllIPs
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
		klog.Errorf("Could not find VNID for NetworkPolicy %s/%s", policy.Namespace, policy.Name)
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
		klog.Errorf("Could not find VNID for NetworkPolicy %s/%s", policy.Namespace, policy.Name)
		return
	}

	np.lock.Lock()
	defer np.lock.Unlock()

	delete(np.warnedPolicies, policy.UID)
	delete(np.skippedPolicies, policy.UID)
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

func (np *networkPolicyPlugin) getPodIP(pod *corev1.Pod) string {
	if pod.Status.PodIP != "" {
		return pod.Status.PodIP
	}
	// empty string will be returned if both pod.Status.PodIP and np.localPodIPs[pod.UID] are empty
	return np.localPodIPs[pod.UID]
}

func (np *networkPolicyPlugin) isOnPodNetwork(pod *corev1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return np.getPodIP(pod) != ""
}

func (np *networkPolicyPlugin) handleAddOrUpdatePod(obj, old interface{}, eventType watch.EventType) {
	pod := obj.(*corev1.Pod)
	klog.V(5).Infof("Watch %s event for Pod %q", eventType, getPodFullName(pod))

	np.lock.Lock()
	defer np.lock.Unlock()

	if !np.isOnPodNetwork(pod) {
		return
	}

	if old != nil {
		oldPod := old.(*corev1.Pod)
		if oldPod.Status.PodIP == pod.Status.PodIP && reflect.DeepEqual(oldPod.Labels, pod.Labels) {
			return
		}
	}

	if np.localPodIPs[pod.UID] != "" && pod.Status.PodIP != "" {
		// cleanup local pod ip once pod.Status.PodIP is set
		delete(np.localPodIPs, pod.UID)
	}
	np.refreshPodNetworkPolicies(pod)
}

func (np *networkPolicyPlugin) handleDeletePod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	klog.V(5).Infof("Watch %s event for Pod %q", watch.Deleted, getPodFullName(pod))

	np.lock.Lock()
	defer np.lock.Unlock()
	delete(np.localPodIPs, pod.UID)

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

func (np *networkPolicyPlugin) refreshPodNetworkPolicies(pod *corev1.Pod) bool {
	syncTriggered := false
	podNs := np.namespacesByName[pod.Namespace]
	for _, npns := range np.namespaces {
		for _, npp := range npns.policies {
			if (npp.watchesOwnPods && npns == podNs) || npp.watchesAllPods {
				npns.mustRecalculate = true
			}
		}
		if npns.mustRecalculate && npns.inUse {
			syncTriggered = true
			np.syncNamespace(npns)
		}
	}
	return syncTriggered
}

func getPodFullName(pod *corev1.Pod) string {
	return fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
}
