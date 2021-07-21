// +build linux

package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	networkv1 "github.com/openshift/api/network/v1"
	networkclient "github.com/openshift/client-go/network/clientset/versioned"
	networkinformers "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/sdn/pkg/network"
	"github.com/openshift/sdn/pkg/network/common"
)

type firewallItem struct {
	ruleType networkv1.EgressNetworkPolicyRuleType
	net      *net.IPNet
}

type proxyEndpoints struct {
	endpoints *corev1.Endpoints
	blocked   bool
}

type proxyEndpointSlice struct {
	endpointslice *discoveryv1beta1.EndpointSlice
	blocked       bool
}

type proxyNamespace struct {
	global bool

	firewalls    map[ktypes.UID][]firewallItem
	activePolicy *ktypes.UID

	blockableEndpoints      map[ktypes.UID]*proxyEndpoints
	blockableEndpointSlices map[ktypes.UID]*proxyEndpointSlice
}

type OsdnProxy struct {
	sync.Mutex

	kClient          kubernetes.Interface
	kubeInformers    informers.SharedInformerFactory
	networkClient    networkclient.Interface
	networkInformers networkinformers.SharedInformerFactory
	networkInfo      *common.ParsedClusterNetwork
	egressDNS        *common.EgressDNS
	minSyncPeriod    time.Duration

	baseProxy HybridizableProxy

	// waitChan will be closed when both services and endpoints have
	// been synced in the proxy
	waitChan        chan<- bool
	servicesSynced  bool
	endpointsSynced bool

	namespaces map[string]*proxyNamespace
}

// Called by higher layers to create the proxy plugin instance
func New(kClient kubernetes.Interface,
	kubeInformers informers.SharedInformerFactory,
	networkClient networkclient.Interface,
	networkInformers networkinformers.SharedInformerFactory,
	minSyncPeriod time.Duration) (*OsdnProxy, error) {

	egressDNS, err := common.NewEgressDNS(true, false)
	if err != nil {
		return nil, err
	}
	return &OsdnProxy{
		kClient:          kClient,
		kubeInformers:    kubeInformers,
		networkClient:    networkClient,
		networkInformers: networkInformers,
		minSyncPeriod:    minSyncPeriod,
		egressDNS:        egressDNS,
		namespaces:       make(map[string]*proxyNamespace),
	}, nil
}

func (proxy *OsdnProxy) SetBaseProxies(mainProxy, unidlingProxy HybridizableProxy) {
	if unidlingProxy == nil {
		proxy.baseProxy = mainProxy
	} else {
		proxy.baseProxy = NewHybridProxier(
			mainProxy, unidlingProxy,
			proxy.minSyncPeriod,
			proxy.kubeInformers.Core().V1().Services().Lister(),
		)
	}
}

func (proxy *OsdnProxy) Start(waitChan chan<- bool) error {
	klog.Infof("Starting multitenant SDN proxy endpoint filter")

	var err error
	proxy.networkInfo, err = common.GetParsedClusterNetwork(proxy.networkClient)
	if err != nil {
		return fmt.Errorf("could not get network info: %s", err)
	}
	proxy.waitChan = waitChan

	policies, err := proxy.networkClient.NetworkV1().EgressNetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("could not get EgressNetworkPolicies: %s", err)
	}

	proxy.Lock()
	defer proxy.Unlock()

	for _, policy := range policies.Items {
		proxy.egressDNS.Add(policy)
		proxy.updateEgressNetworkPolicy(policy)
	}

	go utilwait.Forever(proxy.syncEgressDNSProxyFirewall, 0)
	proxy.watchEgressNetworkPolicies()
	proxy.watchNetNamespaces()
	return nil
}

func (proxy *OsdnProxy) ReloadIPTables() error {
	proxy.Sync()
	return nil
}

// Assumes lock is held
func (proxy *OsdnProxy) getNamespace(name string) *proxyNamespace {
	ns := proxy.namespaces[name]
	if ns == nil {
		ns = &proxyNamespace{
			firewalls:               make(map[ktypes.UID][]firewallItem),
			blockableEndpoints:      make(map[ktypes.UID]*proxyEndpoints),
			blockableEndpointSlices: make(map[ktypes.UID]*proxyEndpointSlice),
		}
		proxy.namespaces[name] = ns
	}
	return ns
}

// Assumes lock is held
func (proxy *OsdnProxy) maybeGarbageCollectNamespace(name string, ns *proxyNamespace) {
	if ns.global == false && len(ns.firewalls) == 0 &&
		len(ns.blockableEndpoints) == 0 && len(ns.blockableEndpointSlices) == 0 {
		delete(proxy.namespaces, name)
	}
}

func (proxy *OsdnProxy) watchEgressNetworkPolicies() {
	funcs := common.InformerFuncs(&networkv1.EgressNetworkPolicy{}, proxy.handleAddOrUpdateEgressNetworkPolicy, proxy.handleDeleteEgressNetworkPolicy)
	proxy.networkInformers.Network().V1().EgressNetworkPolicies().Informer().AddEventHandler(funcs)
}

func (proxy *OsdnProxy) handleAddOrUpdateEgressNetworkPolicy(obj, _ interface{}, eventType watch.EventType) {
	policy := obj.(*networkv1.EgressNetworkPolicy)
	klog.V(5).Infof("Watch %s event for EgressNetworkPolicy %s/%s", eventType, policy.Namespace, policy.Name)

	proxy.egressDNS.Delete(*policy)
	proxy.egressDNS.Add(*policy)

	proxy.Lock()
	defer proxy.Unlock()
	proxy.updateEgressNetworkPolicy(*policy)
}

func (proxy *OsdnProxy) handleDeleteEgressNetworkPolicy(obj interface{}) {
	policy := obj.(*networkv1.EgressNetworkPolicy)
	klog.V(5).Infof("Watch %s event for EgressNetworkPolicy %s/%s", watch.Deleted, policy.Namespace, policy.Name)

	proxy.egressDNS.Delete(*policy)
	policy.Spec.Egress = nil

	proxy.Lock()
	defer proxy.Unlock()
	proxy.updateEgressNetworkPolicy(*policy)
}

func (proxy *OsdnProxy) watchNetNamespaces() {
	funcs := common.InformerFuncs(&networkv1.NetNamespace{}, proxy.handleAddOrUpdateNetNamespace, proxy.handleDeleteNetNamespace)
	proxy.networkInformers.Network().V1().NetNamespaces().Informer().AddEventHandler(funcs)
}

func (proxy *OsdnProxy) handleAddOrUpdateNetNamespace(obj, _ interface{}, eventType watch.EventType) {
	netns := obj.(*networkv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", eventType, netns.Name)

	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(netns.Name)
	ns.global = (netns.NetID == network.GlobalVNID)
}

func (proxy *OsdnProxy) handleDeleteNetNamespace(obj interface{}) {
	netns := obj.(*networkv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", watch.Deleted, netns.Name)

	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.namespaces[netns.Name]
	if ns == nil {
		return
	}

	// The only part of netns we keep track of in ns is whether it is "global" or not.
	// If the netns no longer exists, then it is not global.
	ns.global = false
	proxy.maybeGarbageCollectNamespace(netns.Name, ns)
}

// Assumes lock is held
func (proxy *OsdnProxy) updateEgressNetworkPolicy(policy networkv1.EgressNetworkPolicy) {
	ns := proxy.getNamespace(policy.Namespace)
	if ns.global {
		// Firewall not allowed for global namespaces
		utilruntime.HandleError(fmt.Errorf("EgressNetworkPolicy in global network namespace (%s) is not allowed (%s); ignoring firewall rules", policy.Namespace, policy.Name))
		return
	}

	firewall := []firewallItem{}
	for _, rule := range policy.Spec.Egress {
		if len(rule.To.CIDRSelector) > 0 {
			selector := rule.To.CIDRSelector
			if selector == "0.0.0.0/32" {
				// ovscontroller.go already logs a warning about this
				selector = "0.0.0.0/0"
			}
			_, cidr, err := net.ParseCIDR(selector)
			if err != nil {
				// should have been caught by validation
				utilruntime.HandleError(fmt.Errorf("Illegal CIDR value %q in EgressNetworkPolicy rule for policy: %v", rule.To.CIDRSelector, policy.UID))
				continue
			}
			firewall = append(firewall, firewallItem{rule.Type, cidr})
		} else if len(rule.To.DNSName) > 0 {
			cidrs := proxy.egressDNS.GetNetCIDRs(rule.To.DNSName)
			for _, cidr := range cidrs {
				firewall = append(firewall, firewallItem{rule.Type, &cidr})
			}
		} else {
			// Should have been caught by validation
			utilruntime.HandleError(fmt.Errorf("Invalid EgressNetworkPolicy rule: %v for policy: %v", rule, policy.UID))
		}
	}

	// Add/Update/Delete firewall rules for the namespace
	if len(firewall) > 0 {
		ns.firewalls[policy.UID] = firewall
	} else {
		delete(ns.firewalls, policy.UID)
	}

	// Set active policy for the namespace
	if len(ns.firewalls) == 1 {
		for uid := range ns.firewalls {
			ns.activePolicy = &uid
			klog.Infof("Applied firewall egress network policy: %q to namespace: %q", uid, policy.Namespace)
		}
	} else {
		ns.activePolicy = nil

		if len(ns.firewalls) > 1 {
			// We only allow one policy per namespace otherwise it's hard to determine which policy to apply first
			utilruntime.HandleError(fmt.Errorf("Found multiple egress policies, dropping all firewall rules for namespace: %q", policy.Namespace))
		}
	}

	// Update endpoints and slices
	for _, pep := range ns.blockableEndpoints {
		wasBlocked := pep.blocked
		pep.blocked = proxy.endpointsBlocked(ns, pep.endpoints)
		switch {
		case wasBlocked && !pep.blocked:
			proxy.baseProxy.OnEndpointsAdd(pep.endpoints)
		case !wasBlocked && pep.blocked:
			proxy.baseProxy.OnEndpointsDelete(pep.endpoints)
		}
	}
	for _, pes := range ns.blockableEndpointSlices {
		wasBlocked := pes.blocked
		pes.blocked = proxy.endpointSliceBlocked(ns, pes.endpointslice)
		switch {
		case wasBlocked && !pes.blocked:
			proxy.baseProxy.OnEndpointSliceAdd(pes.endpointslice)
		case !wasBlocked && pes.blocked:
			proxy.baseProxy.OnEndpointSliceDelete(pes.endpointslice)
		}
	}

	if len(ns.firewalls) == 0 {
		proxy.maybeGarbageCollectNamespace(policy.Namespace, ns)
	}
}

// Returns true if ep contains at least one blockable (ie, non-local) endpoint.
// Assumes lock is held
func (proxy *OsdnProxy) endpointsBlockable(ns *proxyNamespace, ep *corev1.Endpoints) bool {
	for _, ss := range ep.Subsets {
		for _, addr := range ss.Addresses {
			ip := net.ParseIP(addr.IP)
			if !proxy.networkInfo.PodNetworkContains(ip) && !proxy.networkInfo.ServiceNetworkContains(ip) {
				return true
			}
		}
	}
	return false
}

// Returns true if slice contains at least one blockable (ie, non-local) endpoint
// Assumes lock is held
func (proxy *OsdnProxy) endpointSliceBlockable(ns *proxyNamespace, slice *discoveryv1beta1.EndpointSlice) bool {
	for _, ep := range slice.Endpoints {
		for _, addr := range ep.Addresses {
			ip := net.ParseIP(addr)
			if !proxy.networkInfo.PodNetworkContains(ip) && !proxy.networkInfo.ServiceNetworkContains(ip) {
				return true
			}
		}
	}
	return false
}

// Assumes lock is held
func (ns *proxyNamespace) firewallBlocks(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	for _, item := range ns.firewalls[*ns.activePolicy] {
		if item.net.Contains(ip) {
			return item.ruleType == networkv1.EgressNetworkPolicyRuleDeny
		}
	}
	return false
}

// Returns true if ep contains at least one endpoint that is blocked by current firewall rules
// Assumes lock is held
func (proxy *OsdnProxy) endpointsBlocked(ns *proxyNamespace, ep *corev1.Endpoints) bool {
	if len(ns.firewalls) == 0 {
		return false
	} else if ns.activePolicy == nil {
		// Block all connections if active policy is not set
		return true
	}

	for _, ss := range ep.Subsets {
		for _, addr := range ss.Addresses {
			if ns.firewallBlocks(addr.IP) {
				klog.Warningf("Endpoint '%s' in namespace '%s' has an endpoint pointing to firewalled destination (%s)", ep.Name, ep.Namespace, addr.IP)
				return true
			}
		}
	}
	return false
}

// Returns true if slice contains at least one endpoint that is blocked by current firewall rules
// Assumes lock is held
func (proxy *OsdnProxy) endpointSliceBlocked(ns *proxyNamespace, slice *discoveryv1beta1.EndpointSlice) bool {
	if len(ns.firewalls) == 0 {
		return false
	} else if ns.activePolicy == nil {
		// Block all connections if active policy is not set
		return true
	}

	for _, ep := range slice.Endpoints {
		for _, addr := range ep.Addresses {
			if ns.firewallBlocks(addr) {
				klog.Warningf("EndpointSlice '%s' in namespace '%s' has an endpoint pointing to firewalled destination (%s)", slice.Name, slice.Namespace, addr)
				return true
			}
		}
	}
	return false
}

// Assumes lock is held
func (proxy *OsdnProxy) checkInitialized() {
	if proxy.servicesSynced && proxy.endpointsSynced && proxy.waitChan != nil {
		klog.V(2).Info("openshift-sdn proxy services and endpoints initialized")
		close(proxy.waitChan)
		proxy.waitChan = nil
	}
}

func (proxy *OsdnProxy) OnEndpointsAdd(ep *corev1.Endpoints) {
	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(ep.Namespace)
	if proxy.endpointsBlockable(ns, ep) {
		pep := &proxyEndpoints{ep, proxy.endpointsBlocked(ns, ep)}
		ns.blockableEndpoints[ep.UID] = pep
		if pep.blocked {
			return
		}
	}

	proxy.baseProxy.OnEndpointsAdd(ep)
}

func (proxy *OsdnProxy) OnEndpointsUpdate(old, ep *corev1.Endpoints) {
	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(ep.Namespace)
	isBlockable := proxy.endpointsBlockable(ns, ep)
	isBlocked := isBlockable && proxy.endpointsBlocked(ns, ep)

	pep := ns.blockableEndpoints[ep.UID]
	if pep == nil {
		if !isBlockable {
			// Wasn't blockable before, still isn't
			proxy.baseProxy.OnEndpointsUpdate(old, ep)
			return
		}
		// Wasn't blockable before, but is now
		pep = &proxyEndpoints{ep, false}
		ns.blockableEndpoints[ep.UID] = pep
	}

	wasBlocked := pep.blocked
	pep.endpoints = ep
	pep.blocked = isBlocked

	switch {
	case wasBlocked && !isBlocked:
		proxy.baseProxy.OnEndpointsAdd(ep)
	case !wasBlocked && !isBlocked:
		proxy.baseProxy.OnEndpointsUpdate(old, ep)
	case !wasBlocked && isBlocked:
		proxy.baseProxy.OnEndpointsDelete(old)
	}

	if !isBlockable {
		delete(ns.blockableEndpoints, ep.UID)
	}
}

func (proxy *OsdnProxy) OnEndpointsDelete(ep *corev1.Endpoints) {
	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(ep.Namespace)
	if ns == nil {
		return
	}
	pep := ns.blockableEndpoints[ep.UID]
	if pep != nil {
		delete(ns.blockableEndpoints, ep.UID)
		proxy.maybeGarbageCollectNamespace(ep.Namespace, ns)
		if pep.blocked {
			return
		}
	}

	proxy.baseProxy.OnEndpointsDelete(ep)
}

func (proxy *OsdnProxy) OnEndpointsSynced() {
	proxy.baseProxy.OnEndpointsSynced()

	proxy.Lock()
	defer proxy.Unlock()

	proxy.endpointsSynced = true
	proxy.checkInitialized()
}

func (proxy *OsdnProxy) OnEndpointSliceAdd(slice *discoveryv1beta1.EndpointSlice) {
	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(slice.Namespace)
	if proxy.endpointSliceBlockable(ns, slice) {
		pes := &proxyEndpointSlice{slice, proxy.endpointSliceBlocked(ns, slice)}
		ns.blockableEndpointSlices[slice.UID] = pes
		if pes.blocked {
			return
		}
	}

	proxy.baseProxy.OnEndpointSliceAdd(slice)
}

func (proxy *OsdnProxy) OnEndpointSliceUpdate(old, slice *discoveryv1beta1.EndpointSlice) {
	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(slice.Namespace)
	isBlockable := proxy.endpointSliceBlockable(ns, slice)
	isBlocked := isBlockable && proxy.endpointSliceBlocked(ns, slice)

	pes := ns.blockableEndpointSlices[slice.UID]
	if pes == nil {
		if !isBlockable {
			// Wasn't blockable before, still isn't
			proxy.baseProxy.OnEndpointSliceUpdate(old, slice)
			return
		}
		// Wasn't blockable before, but is now
		pes = &proxyEndpointSlice{slice, false}
		ns.blockableEndpointSlices[slice.UID] = pes
	}

	wasBlocked := pes.blocked
	pes.endpointslice = slice
	pes.blocked = isBlocked

	switch {
	case wasBlocked && !isBlocked:
		proxy.baseProxy.OnEndpointSliceAdd(slice)
	case !wasBlocked && !isBlocked:
		proxy.baseProxy.OnEndpointSliceUpdate(old, slice)
	case !wasBlocked && isBlocked:
		proxy.baseProxy.OnEndpointSliceDelete(old)
	}

	if !isBlockable {
		delete(ns.blockableEndpointSlices, slice.UID)
	}
}

func (proxy *OsdnProxy) OnEndpointSliceDelete(slice *discoveryv1beta1.EndpointSlice) {
	proxy.Lock()
	defer proxy.Unlock()

	ns := proxy.getNamespace(slice.Namespace)
	if ns == nil {
		return
	}
	pes := ns.blockableEndpointSlices[slice.UID]
	if pes != nil {
		delete(ns.blockableEndpointSlices, slice.UID)
		proxy.maybeGarbageCollectNamespace(slice.Namespace, ns)
		if pes.blocked {
			return
		}
	}

	proxy.baseProxy.OnEndpointSliceDelete(slice)
}

func (proxy *OsdnProxy) OnEndpointSlicesSynced() {
	proxy.baseProxy.OnEndpointSlicesSynced()

	proxy.Lock()
	defer proxy.Unlock()

	proxy.endpointsSynced = true
	proxy.checkInitialized()
}

func (proxier *OsdnProxy) OnNodeAdd(node *corev1.Node) {
	proxier.baseProxy.OnNodeAdd(node)
}

func (proxier *OsdnProxy) OnNodeUpdate(oldNode, node *corev1.Node) {
	proxier.baseProxy.OnNodeUpdate(oldNode, node)
}

func (proxier *OsdnProxy) OnNodeDelete(node *corev1.Node) {
	proxier.baseProxy.OnNodeDelete(node)
}

func (proxier *OsdnProxy) OnNodeSynced() {
	proxier.baseProxy.OnNodeSynced()
}

func (proxy *OsdnProxy) OnServiceAdd(service *corev1.Service) {
	klog.V(4).Infof("sdn proxy: add svc %s/%s: %v", service.Namespace, service.Name, service)
	proxy.baseProxy.OnServiceAdd(service)
}

func (proxy *OsdnProxy) OnServiceUpdate(oldService, service *corev1.Service) {
	proxy.baseProxy.OnServiceUpdate(oldService, service)
}

func (proxy *OsdnProxy) OnServiceDelete(service *corev1.Service) {
	proxy.baseProxy.OnServiceDelete(service)
}

func (proxy *OsdnProxy) OnServiceSynced() {
	proxy.baseProxy.OnServiceSynced()

	proxy.Lock()
	defer proxy.Unlock()

	proxy.servicesSynced = true
	proxy.checkInitialized()
}

func (proxy *OsdnProxy) Sync() {
	proxy.baseProxy.Sync()
}

func (proxy *OsdnProxy) SyncLoop() {
	proxy.baseProxy.SyncLoop()
}

func (proxy *OsdnProxy) syncEgressDNSProxyFirewall() {
	policies, err := proxy.networkClient.NetworkV1().EgressNetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Could not get EgressNetworkPolicies: %v", err))
		return
	}

	go utilwait.Forever(proxy.egressDNS.Sync, 0)

	for {
		policyUpdates := <-proxy.egressDNS.Updates
		for _, policyUpdate := range policyUpdates {
			klog.V(5).Infof("Egress dns sync: update proxy firewall for policy: %v", policyUpdate.UID)

			policy, ok := getPolicy(policyUpdate.UID, policies)
			if !ok {
				policies, err = proxy.networkClient.NetworkV1().EgressNetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("Failed to update proxy firewall for policy: %v, Could not get EgressNetworkPolicies: %v", policyUpdate.UID, err))
					continue
				}

				policy, ok = getPolicy(policyUpdate.UID, policies)
				if !ok {
					klog.Warningf("Unable to update proxy firewall for policy: %v, policy not found", policyUpdate.UID)
					continue
				}
			}

			func() {
				proxy.Lock()
				defer proxy.Unlock()
				proxy.updateEgressNetworkPolicy(policy)
			}()
		}
	}
}

func getPolicy(policyUID ktypes.UID, policies *networkv1.EgressNetworkPolicyList) (networkv1.EgressNetworkPolicy, bool) {
	for _, p := range policies.Items {
		if p.UID == policyUID {
			return p, true
		}
	}
	return networkv1.EgressNetworkPolicy{}, false
}
