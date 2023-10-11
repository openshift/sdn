/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nftables

//
// NOTE: this needs to be tested in e2e since it uses nftables for everything.
//

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danwinship/nftables"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/conntrack"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/metaproxier"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	proxyutiliptables "k8s.io/kubernetes/pkg/proxy/util/iptables"
	"k8s.io/kubernetes/pkg/util/async"
	utilexec "k8s.io/utils/exec"
	netutils "k8s.io/utils/net"
	"k8s.io/utils/ptr"
)

const (
	// the nftables table
	kubeProxyTable = "kube-proxy"

	// service dispatch
	kubeServicesChain       = "services"
	kubeServiceIPsMap       = "service-ips"
	kubeServiceNodePortsMap = "service-nodeports"

	// set of IPs that accept NodePort traffic
	kubeNodePortIPsSet = "nodeport-ips"

	// handling for services with no endpoints
	kubeEndpointsCheckChain    = "endpoints-check"
	kubeNoEndpointServicesMap  = "no-endpoint-services"
	kubeNoEndpointNodePortsMap = "no-endpoint-nodeports"
	kubeRejectChain            = "reject-chain"

	// LoadBalancerSourceRanges handling
	kubeFirewallSet             = "firewall"
	kubeFirewallCheckChain      = "firewall-check"
	kubeFirewallAllowSet        = "firewall-allow"
	kubeFirewallAllowCheckChain = "firewall-allow-check"

	// masquerading
	kubeMarkMasqChain     = "mark-for-masquerade"
	kubeMasqueradingChain = "masquerading"

	// chain for special filtering rules
	kubeForwardChain = "forward"
)

const sysctlNFConntrackTCPBeLiberal = "net/netfilter/nf_conntrack_tcp_be_liberal"

// internal struct for string service information
type servicePortInfo struct {
	*proxy.BaseServicePortInfo
	// The following fields are computed and stored for performance reasons.
	nameString             string
	clusterPolicyChainName string
	localPolicyChainName   string
	externalChainName      string
}

// returns a new proxy.ServicePort which abstracts a serviceInfo
func newServiceInfo(port *v1.ServicePort, service *v1.Service, bsvcPortInfo *proxy.BaseServicePortInfo) proxy.ServicePort {
	svcPort := &servicePortInfo{BaseServicePortInfo: bsvcPortInfo}

	// Store the following for performance reasons.
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	svcPortName := proxy.ServicePortName{NamespacedName: svcName, Port: port.Name}
	svcPort.nameString = svcPortName.String()

	chainNameBase := servicePortChainNameBase(&svcPortName, strings.ToLower(string(svcPort.Protocol())))
	svcPort.clusterPolicyChainName = servicePortPolicyClusterChainNamePrefix + chainNameBase
	svcPort.localPolicyChainName = servicePortPolicyLocalChainNamePrefix + chainNameBase
	svcPort.externalChainName = serviceExternalChainNamePrefix + chainNameBase

	return svcPort
}

// internal struct for endpoints information
type endpointInfo struct {
	*proxy.BaseEndpointInfo

	chainName       string
	affinitySetName string
}

// returns a new proxy.Endpoint which abstracts a endpointInfo
func newEndpointInfo(baseInfo *proxy.BaseEndpointInfo, svcPortName *proxy.ServicePortName) proxy.Endpoint {
	chainNameBase := servicePortEndpointChainNameBase(svcPortName, strings.ToLower(string(svcPortName.Protocol)), baseInfo.Endpoint)
	return &endpointInfo{
		BaseEndpointInfo: baseInfo,
		chainName:        servicePortEndpointChainNamePrefix + chainNameBase,
		affinitySetName:  servicePortEndpointAffinityNamePrefix + chainNameBase,
	}
}

// Proxier is an nftables based proxy
type Proxier struct {
	ipFamily v1.IPFamily

	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since nftables was synced. For a single object,
	// changes are accumulated, i.e. previous is state from before all of them,
	// current is state after applying all of those.
	endpointsChanges *proxy.EndpointChangeTracker
	serviceChanges   *proxy.ServiceChangeTracker

	mu           sync.Mutex // protects the following fields
	svcPortMap   proxy.ServicePortMap
	endpointsMap proxy.EndpointsMap
	nodeLabels   map[string]string
	// endpointSlicesSynced, and servicesSynced are set to true
	// when corresponding objects are synced after startup. This is used to avoid
	// updating nftables with some partial data after kube-proxy restart.
	endpointSlicesSynced bool
	servicesSynced       bool
	initialized          int32
	syncRunner           *async.BoundedFrequencyRunner // governs calls to syncProxyRules
	syncPeriod           time.Duration

	staleChains sets.Set[string]

	// These are effectively const and do not need the mutex to be held.
	nftables       nftables.Interface
	masqueradeAll  bool
	masqueradeMark string
	exec           utilexec.Interface
	localDetector  proxyutiliptables.LocalTrafficDetector
	hostname       string
	nodeIP         net.IP
	recorder       events.EventRecorder

	serviceHealthServer healthcheck.ServiceHealthServer
	healthzServer       healthcheck.ProxierHealthUpdater

	// conntrackTCPLiberal indicates whether the system sets the kernel nf_conntrack_tcp_be_liberal
	conntrackTCPLiberal bool

	// nodePortAddresses selects the interfaces where nodePort works.
	nodePortAddresses *proxyutil.NodePortAddresses
	// networkInterfacer defines an interface for several net library functions.
	// Inject for test purpose.
	networkInterfacer proxyutil.NetworkInterfacer
}

// Proxier implements proxy.Provider
var _ proxy.Provider = &Proxier{}

// NewProxier returns a new nftables Proxier. Once a proxier is created, it will keep
// nftables up to date in the background and will not terminate if a particular nftables
// call fails.
func NewProxier(ipFamily v1.IPFamily,
	sysctl utilsysctl.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	masqueradeBit int,
	localDetector proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddressStrings []string,
) (*Proxier, error) {
	nodePortAddresses := proxyutil.NewNodePortAddresses(ipFamily, nodePortAddressStrings)

	// Be conservative in what you do, be liberal in what you accept from others.
	// If it's non-zero, we mark only out of window RST segments as INVALID.
	// Ref: https://docs.kernel.org/networking/nf_conntrack-sysctl.html
	conntrackTCPLiberal := false
	if val, err := sysctl.GetSysctl(sysctlNFConntrackTCPBeLiberal); err == nil && val != 0 {
		conntrackTCPLiberal = true
		klog.InfoS("nf_conntrack_tcp_be_liberal set, not installing DROP rules for INVALID packets")
	}

	// Generate the masquerade mark to use for SNAT rules.
	masqueradeValue := 1 << uint(masqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)
	klog.V(2).InfoS("Using nftables mark for masquerade", "ipFamily", ipFamily, "mark", masqueradeMark)

	serviceHealthServer := healthcheck.NewServiceHealthServer(hostname, recorder, nodePortAddresses, healthzServer)

	var nftablesFamily nftables.Family
	if ipFamily == v1.IPv4Protocol {
		nftablesFamily = nftables.IPv4Family
	} else {
		nftablesFamily = nftables.IPv6Family
	}
	nft, err := nftables.New(nftablesFamily, kubeProxyTable)
	if err != nil {
		return nil, err
	}

	proxier := &Proxier{
		ipFamily:            ipFamily,
		svcPortMap:          make(proxy.ServicePortMap),
		serviceChanges:      proxy.NewServiceChangeTracker(newServiceInfo, ipFamily, recorder, nil),
		endpointsMap:        make(proxy.EndpointsMap),
		endpointsChanges:    proxy.NewEndpointChangeTracker(hostname, newEndpointInfo, ipFamily, recorder, nil),
		syncPeriod:          syncPeriod,
		nftables:            nft,
		masqueradeAll:       masqueradeAll,
		masqueradeMark:      masqueradeMark,
		exec:                utilexec.New(),
		localDetector:       localDetector,
		hostname:            hostname,
		nodeIP:              nodeIP,
		recorder:            recorder,
		serviceHealthServer: serviceHealthServer,
		healthzServer:       healthzServer,
		nodePortAddresses:   nodePortAddresses,
		networkInterfacer:   proxyutil.RealNetwork{},
		conntrackTCPLiberal: conntrackTCPLiberal,
	}

	burstSyncs := 2
	klog.V(2).InfoS("NFTables sync params", "ipFamily", ipFamily, "minSyncPeriod", minSyncPeriod, "syncPeriod", syncPeriod, "burstSyncs", burstSyncs)
	proxier.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", proxier.syncProxyRules, minSyncPeriod, syncPeriod, burstSyncs)

	return proxier, nil
}

// NewDualStackProxier creates a MetaProxier instance, with IPv4 and IPv6 proxies.
func NewDualStackProxier(
	sysctl utilsysctl.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	masqueradeBit int,
	localDetectors [2]proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddresses []string,
) (proxy.Provider, error) {
	// Create an ipv4 instance of the single-stack proxier
	ipv4Proxier, err := NewProxier(v1.IPv4Protocol, sysctl,
		syncPeriod, minSyncPeriod, masqueradeAll, masqueradeBit, localDetectors[0], hostname,
		nodeIPs[v1.IPv4Protocol], recorder, healthzServer, nodePortAddresses)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
	}

	ipv6Proxier, err := NewProxier(v1.IPv6Protocol, sysctl,
		syncPeriod, minSyncPeriod, masqueradeAll, masqueradeBit, localDetectors[1], hostname,
		nodeIPs[v1.IPv6Protocol], recorder, healthzServer, nodePortAddresses)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 proxier: %v", err)
	}
	return metaproxier.NewMetaProxier(ipv4Proxier, ipv6Proxier), nil
}

// nftablesBaseChains lists our "base chains"; those that are directly connected to the
// netfilter hooks (e.g., "postrouting", "input", etc.), as opposed to "regular" chains,
// which are only run when a rule jumps to them. See
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains.
//
// These are set up from setupNFTables() and then not directly referenced by
// syncProxyRules().
//
// All of our base chains have names that are just "${type}-${hook}". e.g., "nat-prerouting".
type nftablesBaseChain struct {
	name      string
	chainType nftables.BaseChainType
	hook      nftables.BaseChainHook
	priority  string
}

// "dstnat" is "-100" but for some reason can only be specified in prerouting, even though
// you can call "dnat" from output, and you may want to order things relative to dnat in
// other chains. Anyway, we want our filtering rules to operate on pre-DNAT dest IPs, so
// our filter chains have to run before DNAT. For consistency, we don't use symbolic
// priority names on the other chains either.
var nftablesBaseChains = []nftablesBaseChain{
	{"filter-input", nftables.FilterType, nftables.InputHook, "-101" /* dstnat-1 */},
	{"filter-forward", nftables.FilterType, nftables.ForwardHook, "-101" /* dstnat-1 */},
	{"filter-output", nftables.FilterType, nftables.OutputHook, "-101" /* dstnat-1 */},
	{"nat-prerouting", nftables.NATType, nftables.PreroutingHook, "-100" /* dstnat */},
	{"nat-output", nftables.NATType, nftables.OutputHook, "-100" /* dstnat */},
	{"nat-postrouting", nftables.NATType, nftables.PostroutingHook, "100" /* srcnat */},
}

// nftablesJumpChains lists our top-level "regular chains" that are jumped to directly
// from one of the base chains. These are set up from setupNFTables(), and some of them
// are also referenced in syncProxyRules().
type nftablesJumpChain struct {
	dstChain  string
	srcChain  string
	extraArgs string
}

var nftablesJumpChains = []nftablesJumpChain{
	{kubeEndpointsCheckChain, "filter-input", "ct state new"},
	{kubeEndpointsCheckChain, "filter-forward", "ct state new"},
	{kubeEndpointsCheckChain, "filter-output", "ct state new"},

	{kubeForwardChain, "filter-forward", ""},

	{kubeFirewallCheckChain, "filter-input", "ct state new"},
	{kubeFirewallCheckChain, "filter-output", "ct state new"},
	{kubeFirewallCheckChain, "filter-forward", "ct state new"},

	{kubeServicesChain, "nat-output", ""},
	{kubeServicesChain, "nat-prerouting", ""},
	{kubeMasqueradingChain, "nat-postrouting", ""},
}

// ensureChain adds commands to tx to ensure that chain exists and doesn't contain
// anything from before this transaction.
func ensureChain(chain string, tx *nftables.Transaction, existing sets.Set[string]) {
	if existing.Has(chain) {
		return
	}
	tx.Add(&nftables.Chain{
		Name: chain,
	})
	tx.Flush(&nftables.Chain{
		Name: chain,
	})
	existing.Insert(chain)
}

func (proxier *Proxier) setupNFTables(tx *nftables.Transaction) {
	ipX := "ip"
	ipvX_addr := "ipv4_addr"
	noLocalhost := "ip daddr != 127.0.0.0/8"
	if proxier.ipFamily == v1.IPv6Protocol {
		ipX = "ip6"
		ipvX_addr = "ipv6_addr"
		noLocalhost = "ip6 daddr != ::1"
	}

	tx.Add(&nftables.Table{
		Comment: ptr.To("rules for kube-proxy"),
	})

	// Create and flush base chains
	for _, bc := range nftablesBaseChains {
		chain := &nftables.Chain{
			Name:     bc.name,
			Type:     ptr.To(bc.chainType),
			Hook:     ptr.To(bc.hook),
			Priority: ptr.To(nftables.BaseChainPriority(bc.priority)),
		}
		tx.Add(chain)
		tx.Flush(chain)
	}

	// Create and flush ordinary chains and add rules jumping to them
	existingChains := sets.New[string]()
	for _, c := range nftablesJumpChains {
		ensureChain(c.dstChain, tx, existingChains)
		tx.Add(&nftables.Rule{
			Chain: c.srcChain,
			Rule: nftables.Concat(
				c.extraArgs,
				"jump", c.dstChain,
			),
		})
	}

	// Ensure all of our other "top-level" chains exist
	for _, chain := range []string{kubeServicesChain, kubeForwardChain, kubeMasqueradingChain, kubeMarkMasqChain} {
		ensureChain(chain, tx, existingChains)
	}

	// Add the rules in the mark-for-masquerade and masquerading chains
	tx.Add(&nftables.Rule{
		Chain: kubeMarkMasqChain,
		Rule: nftables.Concat(
			"mark", "set", "mark", "or", proxier.masqueradeMark,
		),
	})

	tx.Add(&nftables.Rule{
		Chain: kubeMasqueradingChain,
		Rule: nftables.Concat(
			"mark", "and", proxier.masqueradeMark, "==", "0",
			"return",
		),
	})
	tx.Add(&nftables.Rule{
		Chain: kubeMasqueradingChain,
		Rule: nftables.Concat(
			"mark", "set", "mark", "xor", proxier.masqueradeMark,
		),
	})
	tx.Add(&nftables.Rule{
		Chain: kubeMasqueradingChain,
		Rule:  "masquerade fully-random",
	})

	// Drop the packets in INVALID state, which would potentially cause
	// unexpected connection reset if nf_conntrack_tcp_be_liberal is not set.
	// Ref: https://github.com/kubernetes/kubernetes/issues/74839
	// Ref: https://github.com/kubernetes/kubernetes/issues/117924
	if !proxier.conntrackTCPLiberal {
		tx.Add(&nftables.Rule{
			Chain: kubeForwardChain,
			Rule:  "ct state invalid drop",
		})
	}

	// Fill in nodeport-ips set if needed (or delete it if not). (We do "add+delete"
	// rather than just "delete" when we want to ensure the set doesn't exist, because
	// doing just "delete" would return an error if the set didn't exist.)
	tx.Add(&nftables.Set{
		Name:    kubeNodePortIPsSet,
		Type:    ipvX_addr,
		Comment: ptr.To("IPs that accept NodePort traffic"),
	})
	if proxier.nodePortAddresses.MatchAll() {
		tx.Delete(&nftables.Set{
			Name: kubeNodePortIPsSet,
		})
	} else {
		tx.Flush(&nftables.Set{
			Name: kubeNodePortIPsSet,
		})
		nodeIPs, _ := proxier.nodePortAddresses.GetNodeIPs(proxier.networkInterfacer)
		for _, ip := range nodeIPs {
			if ip.IsLoopback() {
				klog.ErrorS(nil, "--nodeport-addresses includes localhost but localhost NodePorts are not supported", "address", ip.String())
				continue
			}
			tx.Add(&nftables.Element{
				Set: kubeNodePortIPsSet,
				Key: []string{
					ip.String(),
				},
			})
		}
	}

	// Set up "no endpoints" drop/reject handling
	tx.Add(&nftables.Map{
		Name:    kubeNoEndpointServicesMap,
		Type:    ipvX_addr + " . inet_proto . inet_service : verdict",
		Comment: ptr.To("vmap to drop or reject packets to services with no endpoints"),
	})
	tx.Add(&nftables.Map{
		Name:    kubeNoEndpointNodePortsMap,
		Type:    "inet_proto . inet_service : verdict",
		Comment: ptr.To("vmap to drop or reject packets to service nodeports with no endpoints"),
	})

	tx.Add(&nftables.Chain{
		Name:    kubeRejectChain,
		Comment: ptr.To("helper for @no-endpoint-services / @no-endpoint-nodeports"),
	})
	tx.Flush(&nftables.Chain{
		Name: kubeRejectChain,
	})
	tx.Add(&nftables.Rule{
		Chain: kubeRejectChain,
		Rule:  "reject",
	})

	tx.Add(&nftables.Rule{
		Chain: kubeEndpointsCheckChain,
		Rule: nftables.Concat(
			ipX, "daddr", ".", "meta l4proto", ".", "th dport",
			"vmap", "@"+kubeNoEndpointServicesMap,
		),
	})

	if proxier.nodePortAddresses.MatchAll() {
		tx.Add(&nftables.Rule{
			Chain: kubeEndpointsCheckChain,
			Rule: nftables.Concat(
				"fib daddr type local",
				noLocalhost,
				"meta l4proto . th dport",
				"vmap", "@"+kubeNoEndpointNodePortsMap,
			),
		})
	} else {
		tx.Add(&nftables.Rule{
			Chain: kubeEndpointsCheckChain,
			Rule: nftables.Concat(
				ipX, "daddr", "@"+kubeNodePortIPsSet,
				"meta l4proto . th dport",
				"vmap", "@"+kubeNoEndpointNodePortsMap,
			),
		})
	}

	// Set up LoadBalancerSourceRanges firewalling
	tx.Add(&nftables.Set{
		Name:    kubeFirewallSet,
		Type:    ipvX_addr + " . inet_proto . inet_service",
		Comment: ptr.To("destinations that are subject to LoadBalancerSourceRanges"),
	})
	tx.Add(&nftables.Set{
		Name:    kubeFirewallAllowSet,
		Type:    ipvX_addr + " . inet_proto . inet_service . " + ipvX_addr,
		Flags:   []nftables.SetFlag{nftables.IntervalFlag},
		Comment: ptr.To("destinations+sources that are allowed by LoadBalancerSourceRanges"),
	})

	ensureChain(kubeFirewallCheckChain, tx, existingChains)
	ensureChain(kubeFirewallAllowCheckChain, tx, existingChains)
	tx.Add(&nftables.Rule{
		Chain: kubeFirewallCheckChain,
		Rule: nftables.Concat(
			ipX, "daddr", ".", "meta l4proto", ".", "th dport", "@"+kubeFirewallSet,
			"jump", kubeFirewallAllowCheckChain,
		),
	})
	tx.Add(&nftables.Rule{
		Chain: kubeFirewallAllowCheckChain,
		Rule: nftables.Concat(
			ipX, "daddr", ".", "meta l4proto", ".", "th dport", ".", ipX, "saddr", "@"+kubeFirewallAllowSet,
			"return",
		),
	})
	tx.Add(&nftables.Rule{
		Chain: kubeFirewallAllowCheckChain,
		Rule:  "drop",
	})

	// Set up service dispatch
	tx.Add(&nftables.Map{
		Name:    kubeServiceIPsMap,
		Type:    ipvX_addr + " . inet_proto . inet_service : verdict",
		Comment: ptr.To("ClusterIP, ExternalIP and LoadBalancer IP traffic"),
	})
	tx.Add(&nftables.Map{
		Name:    kubeServiceNodePortsMap,
		Type:    "inet_proto . inet_service : verdict",
		Comment: ptr.To("NodePort traffic"),
	})
	tx.Add(&nftables.Rule{
		Chain: kubeServicesChain,
		Rule:  nftables.Concat(
			ipX, "daddr", ".", "meta l4proto", ".", "th dport",
			"vmap", "@"+kubeServiceIPsMap,
		),
	})
	if proxier.nodePortAddresses.MatchAll() {
		tx.Add(&nftables.Rule{
			Chain: kubeServicesChain,
			Rule: nftables.Concat(
				"fib daddr type local",
				noLocalhost,
				"meta l4proto . th dport",
				"vmap", "@"+kubeServiceNodePortsMap,
			),
		})
	} else {
		tx.Add(&nftables.Rule{
			Chain: kubeServicesChain,
			Rule: nftables.Concat(
				ipX, "daddr @nodeport-ips",
				"meta l4proto . th dport",
				"vmap", "@"+kubeServiceNodePortsMap,
			),
		})
	}
}

// CleanupLeftovers removes all nftables rules and chains created by the Proxier
// It returns true if an error was encountered. Errors are logged.
func CleanupLeftovers() bool {
	var encounteredError bool

	// "delete" errors on ENOENT, but "add" is a no-op on EEXIST, so we can do
	// "add+delete" to get "delete but with no error if it didn't already exist".
	// We always clean up both IPv4 and IPv6.

	nft, err := nftables.New(nftables.IPv4Family, kubeProxyTable)
	if err == nil {
		tx := nft.NewTransaction()
		tx.Add(&nftables.Table{})
		tx.Delete(&nftables.Table{})
		err = nft.Run(context.TODO(), tx)
	}
	if err != nil {
		klog.ErrorS(err, "Error cleaning up nftables rules")
		encounteredError = true
	}

	nft, err = nftables.New(nftables.IPv6Family, kubeProxyTable)
	if err == nil {
		tx := nft.NewTransaction()
		tx.Add(&nftables.Table{})
		tx.Delete(&nftables.Table{})
		err = nft.Run(context.TODO(), tx)
	}
	if err != nil {
		klog.ErrorS(err, "Error cleaning up nftables rules")
		encounteredError = true
	}

	return encounteredError
}

// Sync is called to synchronize the proxier state to nftables as soon as possible.
func (proxier *Proxier) Sync() {
	if proxier.healthzServer != nil {
		proxier.healthzServer.QueuedUpdate()
	}
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	proxier.syncRunner.Run()
}

// SyncLoop runs periodic work.  This is expected to run as a goroutine or as the main loop of the app.  It does not return.
func (proxier *Proxier) SyncLoop() {
	// Update healthz timestamp at beginning in case Sync() never succeeds.
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated()
	}

	// synthesize "last change queued" time as the informers are syncing.
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	proxier.syncRunner.Loop(wait.NeverStop)
}

func (proxier *Proxier) setInitialized(value bool) {
	var initialized int32
	if value {
		initialized = 1
	}
	atomic.StoreInt32(&proxier.initialized, initialized)
}

func (proxier *Proxier) isInitialized() bool {
	return atomic.LoadInt32(&proxier.initialized) > 0
}

// OnServiceAdd is called whenever creation of new service object
// is observed.
func (proxier *Proxier) OnServiceAdd(service *v1.Service) {
	proxier.OnServiceUpdate(nil, service)
}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (proxier *Proxier) OnServiceUpdate(oldService, service *v1.Service) {
	if proxier.serviceChanges.Update(oldService, service) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (proxier *Proxier) OnServiceDelete(service *v1.Service) {
	proxier.OnServiceUpdate(service, nil)

}

// OnServiceSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *Proxier) OnServiceSynced() {
	proxier.mu.Lock()
	proxier.servicesSynced = true
	proxier.setInitialized(proxier.endpointSlicesSynced)
	proxier.mu.Unlock()

	// Sync unconditionally - this is called once per lifetime.
	proxier.syncProxyRules()
}

// OnEndpointSliceAdd is called whenever creation of a new endpoint slice object
// is observed.
func (proxier *Proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnEndpointSliceUpdate is called whenever modification of an existing endpoint
// slice object is observed.
func (proxier *Proxier) OnEndpointSliceUpdate(_, endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnEndpointSliceDelete is called whenever deletion of an existing endpoint slice
// object is observed.
func (proxier *Proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, true) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnEndpointSlicesSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *Proxier) OnEndpointSlicesSynced() {
	proxier.mu.Lock()
	proxier.endpointSlicesSynced = true
	proxier.setInitialized(proxier.servicesSynced)
	proxier.mu.Unlock()

	// Sync unconditionally - this is called once per lifetime.
	proxier.syncProxyRules()
}

// OnNodeAdd is called whenever creation of new node object
// is observed.
func (proxier *Proxier) OnNodeAdd(node *v1.Node) {
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node",
			"eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	if reflect.DeepEqual(proxier.nodeLabels, node.Labels) {
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = map[string]string{}
	for k, v := range node.Labels {
		proxier.nodeLabels[k] = v
	}
	proxier.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node labels", "labels", node.Labels)

	proxier.Sync()
}

// OnNodeUpdate is called whenever modification of an existing
// node object is observed.
func (proxier *Proxier) OnNodeUpdate(oldNode, node *v1.Node) {
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node",
			"eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	if reflect.DeepEqual(proxier.nodeLabels, node.Labels) {
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = map[string]string{}
	for k, v := range node.Labels {
		proxier.nodeLabels[k] = v
	}
	proxier.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node labels", "labels", node.Labels)

	proxier.Sync()
}

// OnNodeDelete is called whenever deletion of an existing node
// object is observed.
func (proxier *Proxier) OnNodeDelete(node *v1.Node) {
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node",
			"eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = nil
	proxier.mu.Unlock()

	proxier.Sync()
}

// OnNodeSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *Proxier) OnNodeSynced() {
}

const (
	// Maximum length of an nftables chain name. (FIXME: put this in danwinship/nftables)
	nftablesChainNameLengthMax = 128

	// Maximum length for one of our chain name prefixes, including the trailing
	// hyphen.
	chainNamePrefixLengthMax = 16

	// Maximum length of the string returned from servicePortChainNameBase or
	// servicePortEndpointChainNameBase.
	chainNameBaseLengthMax = nftablesChainNameLengthMax - chainNamePrefixLengthMax
)

const (
	servicePortPolicyClusterChainNamePrefix = "service-"
	servicePortPolicyLocalChainNamePrefix   = "local-"
	serviceExternalChainNamePrefix          = "external-"
	servicePortEndpointChainNamePrefix      = "endpoint-"
	servicePortEndpointAffinityNamePrefix   = "affinity-"
)

// servicePortChainNameBase returns the base name for a chain for the given ServicePort.
// This is something like "HASH-namespace/serviceName/protocol/portName", e.g,
// "ULMVA6XW-ns1/svc1/tcp/p80".
func servicePortChainNameBase(servicePortName *proxy.ServicePortName, protocol string) string {
	// nftables chains can contain the characters [A-Za-z0-9_./-] (but must start with
	// a letter, underscore, or dot).
	//
	// Namespace, Service, and Port names can contain [a-z0-9-] (with some additional
	// restrictions that aren't relevant here).
	//
	// Protocol is /(tcp|udp|sctp)/.
	//
	// Thus, we can safely use all Namespace names, Service names, protocol values,
	// and Port names directly in nftables chain names (though note that this assumes
	// that the chain name won't *start* with any of those strings, since that might
	// be illegal). We use "/" to separate the parts of the name, which is one of the
	// two characters allowed in a chain name that isn't allowed in our input strings.

	name := fmt.Sprintf("%s/%s/%s/%s",
		servicePortName.NamespacedName.Namespace,
		servicePortName.NamespacedName.Name,
		protocol,
		servicePortName.Port,
	)

	// Prefix the name with a hash of itself and then truncate to
	// chainNameBaseLengthMax. The hash ensures that (a) the name is still unique if
	// we have to truncate the end, and (b) it's visually distinguishable from other
	// chains that would otherwise have nearly identical names (e.g., different
	// endpoint chains for a given service that differ in only a single digit).
	hash := sha256.Sum256([]byte(name))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	name = encoded[:8] + "-" + name
	if len(name) > chainNameBaseLengthMax {
		name = name[:chainNameBaseLengthMax-3] + "..."
	}
	return name
}

// servicePortEndpointChainNameBase returns the suffix for chain names for the given endpoint
func servicePortEndpointChainNameBase(servicePortName *proxy.ServicePortName, protocol, endpoint string) string {
	// As above in servicePortChainNameBase: Namespace, Service, Port, Protocol, and
	// EndpointPort are all safe to copy into the chain name directly. But if
	// EndpointIP is IPv6 then it will contain colons, which aren't allowed in a chain
	// name. IPv6 IPs are also quite long, but we can't safely truncate them (e.g. to
	// only the final segment) because (especially for manually-created external
	// endpoints), we can't know for sure that any part of them is redundant.

	endpointIP, endpointPort, _ := net.SplitHostPort(endpoint)
	if strings.Contains(endpointIP, ":") {
		endpointIP = strings.ReplaceAll(endpointIP, ":", ".")
	}

	// As above, we use "/" to separate parts of the name, and "__" to separate the
	// "service" part from the "endpoint" part.
	name := fmt.Sprintf("%s/%s/%s/%s__%s/%s",
		servicePortName.NamespacedName.Namespace,
		servicePortName.NamespacedName.Name,
		protocol,
		servicePortName.Port,
		endpointIP,
		endpointPort,
	)

	// As above, prefix with a hash, and truncate.
	hash := sha256.Sum256([]byte(name))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	name = encoded[:8] + "-" + name
	if len(name) > chainNameBaseLengthMax {
		name = name[:chainNameBaseLengthMax-3] + "..."
	}
	return name
}

func isServiceChainName(chainString string) bool {
	// The chains returned from servicePortChainNameBase and
	// servicePortEndpointChainNameBase will always have at least one "/" in them.
	// (The chain prefix is at most 16 characters, the hash and surrounding hyphens
	// add another 10, and the Namespace name is at most 63, meaning the "/" between
	// Namespace and Name is at most 90 characters into the string, 12 characters
	// before the truncation point. Since none of our "stock" chain names use slashes,
	// we can distinguish them this way.

	return strings.Contains(chainString, "/")
}

func isAffinitySetName(set string) bool {
	return strings.HasPrefix(set, servicePortEndpointAffinityNamePrefix)
}

// This is where all of the nftables calls happen.
// This assumes proxier.mu is NOT held
func (proxier *Proxier) syncProxyRules() {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()

	// don't sync rules till we've received services and endpoints
	if !proxier.isInitialized() {
		klog.V(2).InfoS("Not syncing nftables until Services and Endpoints have been received from master")
		return
	}

	//
	// Below this point we will not return until we try to write the nftables rules.
	//

	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		metrics.SyncProxyRulesLatency.Observe(metrics.SinceInSeconds(start))
		klog.V(2).InfoS("SyncProxyRules complete", "elapsed", time.Since(start))
	}()

	serviceUpdateResult := proxier.svcPortMap.Update(proxier.serviceChanges)
	endpointUpdateResult := proxier.endpointsMap.Update(proxier.endpointsChanges)

	klog.V(2).InfoS("Syncing nftables rules")

	success := false
	defer func() {
		if !success {
			klog.InfoS("Sync failed", "retryingTime", proxier.syncPeriod)
			proxier.syncRunner.RetryAfter(proxier.syncPeriod)
		}
	}()

	// We need to use, eg, "ip daddr" for IPv4 but "ip6 daddr" for IPv6
	ipX := "ip"
	ipvX_addr := "ipv4_addr"
	if proxier.ipFamily == v1.IPv6Protocol {
		ipX = "ip6"
		ipvX_addr = "ipv6_addr"
	}

	tx := proxier.nftables.NewTransaction()
	proxier.setupNFTables(tx)

	// Belatedly delete any stale chains leftover from the previous transaction. By
	// doing Add first we ensure that the chain definitely exists, so the Delete won't
	// return an error.
	for chain := range proxier.staleChains {
		tx.Add(&nftables.Chain{
			Name: chain,
		})
		tx.Delete(&nftables.Chain{
			Name: chain,
		})
	}

	// We currently fully-rebuild our sets and maps on each resync
	tx.Flush(&nftables.Set{
		Name: kubeFirewallSet,
	})
	tx.Flush(&nftables.Set{
		Name: kubeFirewallAllowSet,
	})
	tx.Flush(&nftables.Map{
		Name: kubeNoEndpointServicesMap,
	})
	tx.Flush(&nftables.Map{
		Name: kubeNoEndpointNodePortsMap,
	})
	tx.Flush(&nftables.Map{
		Name: kubeServiceIPsMap,
	})
	tx.Flush(&nftables.Map{
		Name: kubeServiceNodePortsMap,
	})

	// Accumulate service/endpoint chains and affinity sets to keep.
	activeChains := sets.New[string]()
	activeAffinitySets := sets.New[string]()

	// Compute total number of endpoint chains across all services
	// to get a sense of how big the cluster is.
	totalEndpoints := 0
	for svcName := range proxier.svcPortMap {
		totalEndpoints += len(proxier.endpointsMap[svcName])
	}

	// These two variables are used to publish the sync_proxy_rules_no_endpoints_total
	// metric.
	serviceNoLocalEndpointsTotalInternal := 0
	serviceNoLocalEndpointsTotalExternal := 0

	// Build rules for each service-port.
	for svcName, svc := range proxier.svcPortMap {
		svcInfo, ok := svc.(*servicePortInfo)
		if !ok {
			klog.ErrorS(nil, "Failed to cast serviceInfo", "serviceName", svcName)
			continue
		}
		protocol := strings.ToLower(string(svcInfo.Protocol()))
		svcPortNameString := svcInfo.nameString

		// Figure out the endpoints for Cluster and Local traffic policy.
		// allLocallyReachableEndpoints is the set of all endpoints that can be routed to
		// from this node, given the service's traffic policies. hasEndpoints is true
		// if the service has any usable endpoints on any node, not just this one.
		allEndpoints := proxier.endpointsMap[svcName]
		clusterEndpoints, localEndpoints, allLocallyReachableEndpoints, hasEndpoints := proxy.CategorizeEndpoints(allEndpoints, svcInfo, proxier.nodeLabels)

		// Note the endpoint chains that will be used
		for _, ep := range allLocallyReachableEndpoints {
			if epInfo, ok := ep.(*endpointInfo); ok {
				ensureChain(epInfo.chainName, tx, activeChains)
			}
		}

		// clusterPolicyChain contains the endpoints used with "Cluster" traffic policy
		clusterPolicyChain := svcInfo.clusterPolicyChainName
		usesClusterPolicyChain := len(clusterEndpoints) > 0 && svcInfo.UsesClusterEndpoints()
		if usesClusterPolicyChain {
			ensureChain(clusterPolicyChain, tx, activeChains)
		}

		// localPolicyChain contains the endpoints used with "Local" traffic policy
		localPolicyChain := svcInfo.localPolicyChainName
		usesLocalPolicyChain := len(localEndpoints) > 0 && svcInfo.UsesLocalEndpoints()
		if usesLocalPolicyChain {
			ensureChain(localPolicyChain, tx, activeChains)
		}

		// internalPolicyChain is the chain containing the endpoints for
		// "internal" (ClusterIP) traffic. internalTrafficChain is the chain that
		// internal traffic is routed to (which is always the same as
		// internalPolicyChain). hasInternalEndpoints is true if we should
		// generate rules pointing to internalTrafficChain, or false if there are
		// no available internal endpoints.
		internalPolicyChain := clusterPolicyChain
		hasInternalEndpoints := hasEndpoints
		if svcInfo.InternalPolicyLocal() {
			internalPolicyChain = localPolicyChain
			if len(localEndpoints) == 0 {
				hasInternalEndpoints = false
			}
		}
		internalTrafficChain := internalPolicyChain

		// Similarly, externalPolicyChain is the chain containing the endpoints
		// for "external" (NodePort, LoadBalancer, and ExternalIP) traffic.
		// externalTrafficChain is the chain that external traffic is routed to
		// (which is always the service's "EXT" chain). hasExternalEndpoints is
		// true if there are endpoints that will be reached by external traffic.
		// (But we may still have to generate externalTrafficChain even if there
		// are no external endpoints, to ensure that the short-circuit rules for
		// local traffic are set up.)
		externalPolicyChain := clusterPolicyChain
		hasExternalEndpoints := hasEndpoints
		if svcInfo.ExternalPolicyLocal() {
			externalPolicyChain = localPolicyChain
			if len(localEndpoints) == 0 {
				hasExternalEndpoints = false
			}
		}
		externalTrafficChain := svcInfo.externalChainName // eventually jumps to externalPolicyChain

		// usesExternalTrafficChain is based on hasEndpoints, not hasExternalEndpoints,
		// because we need the local-traffic-short-circuiting rules even when there
		// are no externally-usable endpoints.
		usesExternalTrafficChain := hasEndpoints && svcInfo.ExternallyAccessible()
		if usesExternalTrafficChain {
			ensureChain(externalTrafficChain, tx, activeChains)
		}

		var internalTrafficFilterVerdict, externalTrafficFilterVerdict string
		if !hasEndpoints {
			// The service has no endpoints at all; hasInternalEndpoints and
			// hasExternalEndpoints will also be false, and we will not
			// generate any chains in the "nat" table for the service; only
			// rules in the "filter" table rejecting incoming packets for
			// the service's IPs.
			internalTrafficFilterVerdict = fmt.Sprintf("goto %s", kubeRejectChain)
			externalTrafficFilterVerdict = fmt.Sprintf("goto %s", kubeRejectChain)
		} else {
			if !hasInternalEndpoints {
				// The internalTrafficPolicy is "Local" but there are no local
				// endpoints. Traffic to the clusterIP will be dropped, but
				// external traffic may still be accepted.
				internalTrafficFilterVerdict = "drop"
				serviceNoLocalEndpointsTotalInternal++
			}
			if !hasExternalEndpoints {
				// The externalTrafficPolicy is "Local" but there are no
				// local endpoints. Traffic to "external" IPs from outside
				// the cluster will be dropped, but traffic from inside
				// the cluster may still be accepted.
				externalTrafficFilterVerdict = "drop"
				serviceNoLocalEndpointsTotalExternal++
			}
		}

		// Capture the clusterIP.
		if hasInternalEndpoints {
			tx.Add(&nftables.Element{
				Map: kubeServiceIPsMap,
				Key: []string{
					svcInfo.ClusterIP().String(),
					protocol,
					strconv.Itoa(svcInfo.Port()),
				},
				Value: []string{
					fmt.Sprintf("goto %s", internalTrafficChain),
				},
			})
		} else {
			// No endpoints.
			tx.Add(&nftables.Element{
				Map: kubeNoEndpointServicesMap,
				Key: []string{
					svcInfo.ClusterIP().String(),
					protocol,
					strconv.Itoa(svcInfo.Port()),
				},
				Value: []string{
					internalTrafficFilterVerdict,
				},
				Comment: &svcPortNameString,
			})
		}

		// Capture externalIPs.
		for _, externalIP := range svcInfo.ExternalIPStrings() {
			if hasEndpoints {
				// Send traffic bound for external IPs to the "external
				// destinations" chain.
				tx.Add(&nftables.Element{
					Map: kubeServiceIPsMap,
					Key: []string{
						externalIP,
						protocol,
						strconv.Itoa(svcInfo.Port()),
					},
					Value: []string{
						fmt.Sprintf("goto %s", externalTrafficChain),
					},
				})
			}
			if !hasExternalEndpoints {
				// Either no endpoints at all (REJECT) or no endpoints for
				// external traffic (DROP anything that didn't get
				// short-circuited by the EXT chain.)
				tx.Add(&nftables.Element{
					Map: kubeNoEndpointServicesMap,
					Key: []string{
						externalIP,
						protocol,
						strconv.Itoa(svcInfo.Port()),
					},
					Value: []string{
						externalTrafficFilterVerdict,
					},
					Comment: &svcPortNameString,
				})
			}
		}

		// Capture load-balancer ingress.
		for _, lbip := range svcInfo.LoadBalancerIPStrings() {
			if hasEndpoints {
				tx.Add(&nftables.Element{
					Map: kubeServiceIPsMap,
					Key: []string{
						lbip,
						protocol,
						strconv.Itoa(svcInfo.Port()),
					},
					Value: []string{
						fmt.Sprintf("goto %s", externalTrafficChain),
					},
				})
			}

			if len(svcInfo.LoadBalancerSourceRanges()) > 0 {
				tx.Add(&nftables.Element{
					Set: kubeFirewallSet,
					Key: []string{
						lbip,
						protocol,
						strconv.Itoa(svcInfo.Port()),
					},
					Comment: &svcPortNameString,
				})

				allowFromNode := false
				for _, src := range svcInfo.LoadBalancerSourceRanges() {
					_, cidr, _ := netutils.ParseCIDRSloppy(src)
					if cidr == nil {
						continue
					}
					tx.Add(&nftables.Element{
						Set: kubeFirewallAllowSet,
						Key: []string{
							lbip,
							protocol,
							strconv.Itoa(svcInfo.Port()),
							src,
						},
						Comment: &svcPortNameString,
					})
					if cidr.Contains(proxier.nodeIP) {
						allowFromNode = true
					}
				}
				// For VIP-like LBs, the VIP is often added as a local
				// address (via an IP route rule).  In that case, a request
				// from a node to the VIP will not hit the loadbalancer but
				// will loop back with the source IP set to the VIP.  We
				// need the following rules to allow requests from this node.
				if allowFromNode {
					tx.Add(&nftables.Element{
						Set: kubeFirewallAllowSet,
						Key: []string{
							lbip,
							protocol,
							strconv.Itoa(svcInfo.Port()),
							lbip,
						},
					})
				}
			}
		}
		if !hasExternalEndpoints {
			// Either no endpoints at all (REJECT) or no endpoints for
			// external traffic (DROP anything that didn't get short-circuited
			// by the EXT chain.)
			for _, lbip := range svcInfo.LoadBalancerIPStrings() {
				tx.Add(&nftables.Element{
					Map: kubeNoEndpointServicesMap,
					Key: []string{
						lbip,
						protocol,
						strconv.Itoa(svcInfo.Port()),
					},
					Value: []string{
						externalTrafficFilterVerdict,
					},
					Comment: &svcPortNameString,
				})
			}
		}

		// Capture nodeports.
		if svcInfo.NodePort() != 0 {
			if hasEndpoints {
				// Jump to the external destination chain.  For better or for
				// worse, nodeports are not subect to loadBalancerSourceRanges,
				// and we can't change that.
				tx.Add(&nftables.Element{
					Map: kubeServiceNodePortsMap,
					Key: []string{
						protocol,
						strconv.Itoa(svcInfo.NodePort()),
					},
					Value: []string{
						fmt.Sprintf("goto %s", externalTrafficChain),
					},
				})
			}
			if !hasExternalEndpoints {
				// Either no endpoints at all (REJECT) or no endpoints for
				// external traffic (DROP anything that didn't get
				// short-circuited by the EXT chain.)
				tx.Add(&nftables.Element{
					Map: kubeNoEndpointNodePortsMap,
					Key: []string{
						protocol,
						strconv.Itoa(svcInfo.NodePort()),
					},
					Value: []string{
						externalTrafficFilterVerdict,
					},
					Comment: &svcPortNameString,
				})
			}
		}

		// Set up internal traffic handling.
		if hasInternalEndpoints {
			if proxier.masqueradeAll {
				tx.Add(&nftables.Rule{
					Chain: internalTrafficChain,
					Rule: nftables.Concat(
						ipX, "daddr", svcInfo.ClusterIP(),
						protocol, "dport", svcInfo.Port(),
						"jump", kubeMarkMasqChain,
					),
				})
			} else if proxier.localDetector.IsImplemented() {
				// This masquerades off-cluster traffic to a service VIP. The
				// idea is that you can establish a static route for your
				// Service range, routing to any node, and that node will
				// bridge into the Service for you. Since that might bounce
				// off-node, we masquerade here.
				tx.Add(&nftables.Rule{
					Chain: internalTrafficChain,
					Rule: nftables.Concat(
						ipX, "daddr", svcInfo.ClusterIP(),
						protocol, "dport", svcInfo.Port(),
						proxier.localDetector.IfNotLocalNFT(),
						"jump", kubeMarkMasqChain,
					),
				})
			}
		}

		// Set up external traffic handling (if any "external" destinations are
		// enabled). All captured traffic for all external destinations should
		// jump to externalTrafficChain, which will handle some special cases and
		// then jump to externalPolicyChain.
		if usesExternalTrafficChain {
			if !svcInfo.ExternalPolicyLocal() {
				// If we are using non-local endpoints we need to masquerade,
				// in case we cross nodes.
				tx.Add(&nftables.Rule{
					Chain: externalTrafficChain,
					Rule: nftables.Concat(
						"jump", kubeMarkMasqChain,
					),
				})
			} else {
				// If we are only using same-node endpoints, we can retain the
				// source IP in most cases.

				if proxier.localDetector.IsImplemented() {
					// Treat all locally-originated pod -> external destination
					// traffic as a special-case.  It is subject to neither
					// form of traffic policy, which simulates going up-and-out
					// to an external load-balancer and coming back in.
					tx.Add(&nftables.Rule{
						Chain: externalTrafficChain,
						Rule: nftables.Concat(
							proxier.localDetector.IfLocalNFT(),
							"goto", clusterPolicyChain,
						),
						Comment: ptr.To("short-circuit pod traffic"),
					})
				}

				// Locally originated traffic (not a pod, but the host node)
				// still needs masquerade because the LBIP itself is a local
				// address, so that will be the chosen source IP.
				tx.Add(&nftables.Rule{
					Chain: externalTrafficChain,
					Rule: nftables.Concat(
						"fib", "saddr", "type", "local",
						"jump", kubeMarkMasqChain,
					),
					Comment: ptr.To("masquerade local traffic"),
				})

				// Redirect all src-type=LOCAL -> external destination to the
				// policy=cluster chain. This allows traffic originating
				// from the host to be redirected to the service correctly.
				tx.Add(&nftables.Rule{
					Chain: externalTrafficChain,
					Rule: nftables.Concat(
						"fib", "saddr", "type", "local",
						"goto", clusterPolicyChain,
					),
					Comment: ptr.To("short-circuit local traffic"),
				})
			}

			// Anything else falls thru to the appropriate policy chain.
			if hasExternalEndpoints {
				tx.Add(&nftables.Rule{
					Chain: externalTrafficChain,
					Rule: nftables.Concat(
						"goto", externalPolicyChain,
					),
				})
			}
		}

		if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
			// Generate the per-endpoint affinity sets
			for _, ep := range allLocallyReachableEndpoints {
				epInfo, ok := ep.(*endpointInfo)
				if !ok {
					klog.ErrorS(nil, "Failed to cast endpointsInfo", "endpointsInfo", ep)
					continue
				}

				// Create a set to store current affinity mappings. The
				// nft docs say "dynamic" is only needed for sets
				// containing stateful objects (eg counters), but (at
				// least on RHEL8) if we create the set without "dynamic",
				// it later gets mutated to have it, and then the next
				// attempt to tx.Add() it here fails because it looks like
				// we're trying to change the flags.
				tx.Add(&nftables.Set{
					Name: epInfo.affinitySetName,
					Type: ipvX_addr,
					Flags: []nftables.SetFlag{
						nftables.DynamicFlag,
						nftables.TimeoutFlag,
					},
					Timeout: ptr.To(time.Duration(svcInfo.StickyMaxAgeSeconds()) * time.Second),
				})
				activeAffinitySets.Insert(epInfo.affinitySetName)
			}
		}

		// If Cluster policy is in use, create the chain and create rules jumping
		// from clusterPolicyChain to the clusterEndpoints
		if usesClusterPolicyChain {
			proxier.writeServiceToEndpointRules(tx, svcPortNameString, svcInfo, clusterPolicyChain, clusterEndpoints)
		}

		// If Local policy is in use, create rules jumping from localPolicyChain
		// to the localEndpoints
		if usesLocalPolicyChain {
			proxier.writeServiceToEndpointRules(tx, svcPortNameString, svcInfo, localPolicyChain, localEndpoints)
		}

		// Generate the per-endpoint chains
		for _, ep := range allLocallyReachableEndpoints {
			epInfo, ok := ep.(*endpointInfo)
			if !ok {
				klog.ErrorS(nil, "Failed to cast endpointInfo", "endpointInfo", ep)
				continue
			}

			endpointChain := epInfo.chainName

			// Handle traffic that loops back to the originator with SNAT.
			tx.Add(&nftables.Rule{
				Chain: endpointChain,
				Rule: nftables.Concat(
					ipX, "saddr", epInfo.IP(),
					"jump", kubeMarkMasqChain,
				),
			})

			// Handle session affinity
			if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
				tx.Add(&nftables.Rule{
					Chain: endpointChain,
					Rule: nftables.Concat(
						"update", "@"+epInfo.affinitySetName,
						"{", ipX, "saddr", "}",
					),
				})
			}

			// DNAT to final destination.
			tx.Add(&nftables.Rule{
				Chain: endpointChain,
				Rule: nftables.Concat(
					"meta l4proto", protocol,
					"dnat to", epInfo.Endpoint,
				),
			})
		}
	}

	// Figure out which chains are now stale. Unfortunately, we can't delete them
	// right away because if there are map entries pointing to a chain, the chain
	// doesn't become deletable until a short amount of time *after* the map entry
	// is deleted. So we flush them now, and record that they need to be deleted
	// in the next sync.
	existingChains, err := proxier.nftables.List(context.TODO(), "chains")
	if err == nil {
		newStaleChains := sets.New[string]()
		for _, chain := range existingChains {
			if isServiceChainName(chain) && !activeChains.Has(chain) && !proxier.staleChains.Has(chain) {
				tx.Flush(&nftables.Chain{
					Name: chain,
				})
				newStaleChains.Insert(chain)
			}
		}
		proxier.staleChains = newStaleChains
	} else if !nftables.IsNotFound(err) {
		klog.ErrorS(err, "Failed to list nftables chains: stale chains will not be deleted")
		proxier.staleChains = nil
	}

	// OTOH, we can immediately delete any stale affinity sets
	existingSets, err := proxier.nftables.List(context.TODO(), "sets")
	if err == nil {
		for _, set := range existingSets {
			if isAffinitySetName(set) && !activeAffinitySets.Has(set) {
				tx.Delete(&nftables.Set{
					Name: set,
				})
			}
		}
	} else if !nftables.IsNotFound(err) {
		klog.ErrorS(err, "Failed to list nftables sets: stale affinity sets will not be deleted")
	}

	// Sync rules.
	klog.V(2).InfoS("Reloading service nftables data",
		"numServices", len(proxier.svcPortMap),
		"numEndpoints", totalEndpoints,
	)

	// FIXME
	klog.InfoS("Running nftables transaction", "transaction", tx.String())

	err = proxier.nftables.Run(context.TODO(), tx)
	if err != nil {
		klog.ErrorS(err, "nftables sync failed")
		metrics.IptablesRestoreFailuresTotal.Inc()
		return
	}
	success = true

	for name, lastChangeTriggerTimes := range endpointUpdateResult.LastChangeTriggerTimes {
		for _, lastChangeTriggerTime := range lastChangeTriggerTimes {
			latency := metrics.SinceInSeconds(lastChangeTriggerTime)
			metrics.NetworkProgrammingLatency.Observe(latency)
			klog.V(4).InfoS("Network programming", "endpoint", klog.KRef(name.Namespace, name.Name), "elapsed", latency)
		}
	}

	metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("internal").Set(float64(serviceNoLocalEndpointsTotalInternal))
	metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("external").Set(float64(serviceNoLocalEndpointsTotalExternal))
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated()
	}
	metrics.SyncProxyRulesLastTimestamp.SetToCurrentTime()

	// Update service healthchecks.  The endpoints list might include services that are
	// not "OnlyLocal", but the services list will not, and the serviceHealthServer
	// will just drop those endpoints.
	if err := proxier.serviceHealthServer.SyncServices(proxier.svcPortMap.HealthCheckNodePorts()); err != nil {
		klog.ErrorS(err, "Error syncing healthcheck services")
	}
	if err := proxier.serviceHealthServer.SyncEndpoints(proxier.endpointsMap.LocalReadyEndpoints()); err != nil {
		klog.ErrorS(err, "Error syncing healthcheck endpoints")
	}

	// Finish housekeeping, clear stale conntrack entries for UDP Services
	conntrack.CleanStaleEntries(proxier.ipFamily == v1.IPv6Protocol, proxier.exec, proxier.svcPortMap, serviceUpdateResult, endpointUpdateResult)
}

func (proxier *Proxier) writeServiceToEndpointRules(tx *nftables.Transaction, svcPortNameString string, svcInfo *servicePortInfo, svcChain string, endpoints []proxy.Endpoint) {
	// First write session affinity rules, if applicable.
	if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
		ipX := "ip"
		if proxier.ipFamily == v1.IPv6Protocol {
			ipX = "ip6"
		}

		for _, ep := range endpoints {
			epInfo, ok := ep.(*endpointInfo)
			if !ok {
				continue
			}

			tx.Add(&nftables.Rule{
				Chain: svcChain,
				Rule: nftables.Concat(
					ipX, "saddr", "@"+epInfo.affinitySetName,
					"goto", epInfo.chainName,
				),
			})
		}
	}

	// Now write loadbalancing rule
	var elements []string
	for i, ep := range endpoints {
		epInfo, ok := ep.(*endpointInfo)
		if !ok {
			continue
		}

		elements = append(elements,
			strconv.Itoa(i), ":", "goto", epInfo.chainName,
		)
		if i != len(endpoints)-1 {
			elements = append(elements, ",")
		}
	}
	tx.Add(&nftables.Rule{
		Chain: svcChain,
		Rule: nftables.Concat(
			"numgen random mod", len(endpoints), "vmap",
			"{", elements, "}",
		),
	})
}
