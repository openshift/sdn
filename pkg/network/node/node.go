package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	metrics "github.com/openshift/sdn/pkg/network/node/metrics"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	kubeletapi "k8s.io/cri-api/pkg/apis"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	kapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/core/v1/helper"
	ktypes "k8s.io/kubernetes/pkg/kubelet/types"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/util/iptables"
	kexec "k8s.io/utils/exec"

	osdnv1 "github.com/openshift/api/network/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/network/common/cniserver"
	"github.com/openshift/sdn/pkg/util/ovs"
)

type osdnPolicy interface {
	Name() string
	Start(node *OsdnNode) error
	SupportsVNIDs() bool
	AllowDuplicateNetID() bool

	AddNetNamespace(netns *osdnv1.NetNamespace)
	UpdateNetNamespace(netns *osdnv1.NetNamespace, oldNetID uint32)
	DeleteNetNamespace(netns *osdnv1.NetNamespace)

	SetUpPod(podIP string) error

	GetVNID(namespace string) (uint32, error)
	GetNamespaces(vnid uint32) []string
	GetMulticastEnabled(vnid uint32) bool

	EnsureVNIDRules(vnid uint32)
	SyncVNIDRules()
}

type OsdnNodeConfig struct {
	NodeName     string
	NodeIP       string
	PlatformType string

	OSDNClient osdnclient.Interface
	KClient    kubernetes.Interface
	Recorder   record.EventRecorder

	KubeInformers informers.SharedInformerFactory
	OSDNInformers osdninformers.SharedInformerFactory

	IPTables      iptables.Interface
	ProxyMode     kubeproxyconfig.ProxyMode
	MasqueradeBit *int32

	OverrideMTU uint32
	RoutableMTU uint32
}

type OsdnNode struct {
	policy           osdnPolicy
	kClient          kubernetes.Interface
	osdnClient       osdnclient.Interface
	recorder         record.EventRecorder
	oc               *ovsController
	networkInfo      *common.ParsedClusterNetwork
	podManager       *podManager
	ipt              iptables.Interface
	nodeIPTables     *NodeIPTables
	clusterCIDRs     []string
	localSubnetCIDR  string
	localGatewayCIDR string
	localIP          string
	hostName         string
	useConnTrack     bool
	masqueradeBit    uint32
	platformType     string
	overlayMTU       uint32
	routableMTU      uint32

	// Synchronizes operations on egressPolicies
	egressPoliciesLock sync.Mutex
	egressPolicies     map[uint32][]osdnv1.EgressNetworkPolicy
	egressDNS          *common.EgressDNS

	kubeInformers informers.SharedInformerFactory
	osdnInformers osdninformers.SharedInformerFactory

	// Holds runtime endpoint shim to make SDN <-> runtime communication
	runtimeService kubeletapi.RuntimeService

	egressIP *egressIPWatcher
}

// Called by higher layers to create the plugin SDN node instance
func New(c *OsdnNodeConfig) (*OsdnNode, error) {
	networkInfo, err := common.GetParsedClusterNetwork(c.OSDNClient)
	if err != nil {
		return nil, fmt.Errorf("could not get ClusterNetwork resource: %v", err)
	}

	if err := c.validateNodeIP(networkInfo); err != nil {
		return nil, err
	}

	var policy osdnPolicy
	var pluginId int
	var useConnTrack bool
	switch strings.ToLower(networkInfo.PluginName) {
	case networkutils.SingleTenantPluginName:
		policy = NewSingleTenantPlugin()
		pluginId = 0
	case networkutils.MultiTenantPluginName:
		policy = NewMultiTenantPlugin()
		pluginId = 1
		// Userspace proxy is incompatible with conntrack.
		if c.ProxyMode != kubeproxyconfig.ProxyModeUserspace {
			useConnTrack = true
		}
	case networkutils.NetworkPolicyPluginName:
		policy = NewNetworkPolicyPlugin()
		pluginId = 2
		useConnTrack = true
	default:
		return nil, fmt.Errorf("Unknown plugin name %q", networkInfo.PluginName)
	}

	if useConnTrack && c.ProxyMode == kubeproxyconfig.ProxyModeUserspace {
		return nil, fmt.Errorf("%q plugin is not compatible with proxy-mode %q", networkInfo.PluginName, c.ProxyMode)
	}

	klog.Infof("Initializing SDN node %q (%s) of type %q", c.NodeName, c.NodeIP, networkInfo.PluginName)

	ovsif, err := ovs.New(kexec.New(), Br0)
	if err != nil {
		return nil, err
	}
	oc := NewOVSController(ovsif, pluginId, useConnTrack, c.NodeIP)

	masqBit := uint32(0)
	if c.MasqueradeBit != nil {
		masqBit = uint32(*c.MasqueradeBit)
	}

	egressDNS, err := common.NewEgressDNS(true, false)
	if err != nil {
		return nil, err
	}

	overlayMTU := networkInfo.OverlayMTU
	routableMTU := uint32(0)
	if c.OverrideMTU != 0 {
		overlayMTU = c.OverrideMTU
		routableMTU = c.RoutableMTU
	}

	plugin := &OsdnNode{
		policy:         policy,
		kClient:        c.KClient,
		osdnClient:     c.OSDNClient,
		recorder:       c.Recorder,
		oc:             oc,
		networkInfo:    networkInfo,
		podManager:     newPodManager(c.KClient, policy, overlayMTU, routableMTU, oc),
		localIP:        c.NodeIP,
		hostName:       c.NodeName,
		useConnTrack:   useConnTrack,
		ipt:            c.IPTables,
		masqueradeBit:  masqBit,
		egressPolicies: make(map[uint32][]osdnv1.EgressNetworkPolicy),
		egressDNS:      egressDNS,
		kubeInformers:  c.KubeInformers,
		osdnInformers:  c.OSDNInformers,
		platformType:   c.PlatformType,
		overlayMTU:     overlayMTU,
		routableMTU:    routableMTU,
		egressIP:       newEgressIPWatcher(oc, common.PlatformUsesCloudEgressIP(c.PlatformType), c.NodeIP, c.MasqueradeBit),
	}

	metrics.RegisterMetrics()

	return plugin, nil
}

func (c *OsdnNodeConfig) validateNodeIP(networkInfo *common.ParsedClusterNetwork) error {
	if _, _, err := GetLinkDetails(c.NodeIP); err != nil {
		if err == ErrorNetworkInterfaceNotFound {
			err = fmt.Errorf("node IP %q is not a local/private address (hostname %q)", c.NodeIP, c.NodeName)
		}
		klog.Errorf("Unable to find network interface for node IP; some features will not work! (%v)", err)
	}

	hostIPNets, _, err := common.GetHostIPNetworks([]string{Tun0})
	if err != nil {
		return fmt.Errorf("failed to get host network information: %v", err)
	}
	if err := networkInfo.CheckHostNetworks(hostIPNets); err != nil {
		// checkHostNetworks() errors *should* be fatal, but we didn't used to check this, and we can't break (mostly-)working nodes on upgrade.
		klog.Errorf("Local networks conflict with SDN; this will eventually cause problems: %v", err)
	}

	return nil
}

var (
	ErrorNetworkInterfaceNotFound = fmt.Errorf("could not find network interface")
)

func GetLinkDetails(ip string) (netlink.Link, *net.IPNet, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			klog.Warningf("Could not get addresses of interface %q: %v", link.Attrs().Name, err)
			continue
		}

		for _, addr := range addrs {
			if addr.IP.String() == ip {
				_, ipNet, err := net.ParseCIDR(addr.IPNet.String())
				if err != nil {
					return nil, nil, fmt.Errorf("could not parse CIDR network from address %q: %v", ip, err)
				}
				return link, ipNet, nil
			}
		}
	}

	return nil, nil, ErrorNetworkInterfaceNotFound
}

func (node *OsdnNode) validateMTU() error {
	klog.V(2).Infof("Checking default interface MTU")

	// Get the interface with the default route
	// TODO(cdc) handle v6-only nodes
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		klog.Errorf("Could not list routes while validating MTU: %v. (Assuming MTU is valid.)", err)
		return nil
	}
	if len(routes) == 0 {
		klog.Errorf("Got no routes while validating MTU. (Assuming MTU is valid.)")
		return nil
	}

	const maxMTU = 65536
	interfaceMTU := maxMTU + 1
	for _, route := range routes {
		// Skip non-default routes
		if route.Dst != nil {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			klog.Errorf("Could not retrieve link id %d while validating MTU. (Assuming MTU is valid.)", route.LinkIndex)
			return nil
		}

		// we want to check the MTU only for the interface assigned to the node's primary ip
		found := false
		addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
		for _, address := range addresses {
			if node.localIP == address.IP.String() {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		mtu := link.Attrs().MTU
		if mtu > 0 && mtu < interfaceMTU {
			interfaceMTU = mtu
		}
	}
	if interfaceMTU > maxMTU {
		klog.Errorf("Unable to determine MTU while performing validation. (Assuming MTU is valid.)")
		return nil
	}

	if interfaceMTU < int(node.overlayMTU)+50 {
		return fmt.Errorf("interface MTU (%d) is too small for specified overlay MTU (%d)", interfaceMTU, node.overlayMTU)
	}
	return nil
}

func (node *OsdnNode) Start() error {
	klog.V(2).Infof("Starting openshift-sdn network plugin")

	var err error
	node.localSubnetCIDR, err = node.getLocalSubnet()
	if err != nil {
		return err
	}

	for _, cn := range node.networkInfo.ClusterNetworks {
		node.clusterCIDRs = append(node.clusterCIDRs, cn.ClusterCIDR.String())
	}

	node.nodeIPTables = newNodeIPTables(node.ipt, node.clusterCIDRs, !node.useConnTrack, node.networkInfo.VXLANPort, node.masqueradeBit)
	if err = node.nodeIPTables.Setup(); err != nil {
		return fmt.Errorf("failed to set up iptables: %v", err)
	}

	networkChanged, existingOFPodNetworks, err := node.SetupSDN()
	if err != nil {
		return fmt.Errorf("node SDN setup failed: %v", err)
	}

	hsw := newHostSubnetWatcher(node.oc, node.localIP, node.networkInfo)
	hsw.Start(node.osdnInformers)

	if err = node.policy.Start(node); err != nil {
		return err
	}
	if node.policy.SupportsVNIDs() {
		if err := node.SetupEgressNetworkPolicy(); err != nil {
			return err
		}
		if err := node.egressIP.Start(node.osdnInformers, node.kubeInformers, node.kClient, node.nodeIPTables); err != nil {
			return err
		}
	}
	if !node.useConnTrack {
		node.watchServices()
	}

	existingPodSandboxes, err := node.getSDNPodSandboxes()
	if err != nil {
		return err
	}

	if err = node.podManager.InitRunningPods(existingPodSandboxes, existingOFPodNetworks); err != nil {
		return err
	}

	klog.V(2).Infof("Starting openshift-sdn pod manager")
	if err := node.podManager.Start(cniserver.CNIServerRunDir, node.localSubnetCIDR,
		node.networkInfo.ClusterNetworks, node.networkInfo.ServiceNetwork, node.platformType); err != nil {
		return err
	}

	if networkChanged && len(existingOFPodNetworks) > 0 {
		err := node.reattachPods(existingPodSandboxes, existingOFPodNetworks)
		if err != nil {
			return err
		}
	}

	if err := node.FinishSetupSDN(); err != nil {
		return fmt.Errorf("could not complete SDN setup: %v", err)
	}

	if err := node.validateMTU(); err != nil {
		return err
	}

	go kwait.Forever(node.policy.SyncVNIDRules, time.Hour)
	go kwait.Forever(func() {
		metrics.GatherPeriodicMetrics()
		node.oc.ovs.UpdateOVSMetrics()
	}, time.Minute*2)

	return nil
}

// reattachPods takes an array containing the information about pods that had been
// attached to the OVS bridge before restart, and either reattaches or kills each of the
// corresponding pods.
func (node *OsdnNode) reattachPods(existingPodSandboxes map[string]*kruntimeapi.PodSandbox, existingOFPodNetworks map[string]podNetworkInfo) error {
	for sandboxID, podInfo := range existingOFPodNetworks {
		sandbox, ok := existingPodSandboxes[sandboxID]
		if !ok {
			klog.V(5).Infof("Sandbox for pod with IP %s no longer exists", podInfo.ip)
			continue
		}
		if _, err := netlink.LinkByName(podInfo.vethName); err != nil {
			klog.Infof("Interface %s for pod '%s/%s' no longer exists", podInfo.vethName, sandbox.Metadata.Namespace, sandbox.Metadata.Name)
			continue
		}

		req := &cniserver.PodRequest{
			Command:      cniserver.CNI_ADD,
			PodNamespace: sandbox.Metadata.Namespace,
			PodName:      sandbox.Metadata.Name,
			SandboxID:    sandboxID,
			HostVeth:     podInfo.vethName,
			AssignedIP:   podInfo.ip,
			Result:       make(chan *cniserver.PodResult),
		}
		klog.Infof("Reattaching pod '%s/%s' to SDN", req.PodNamespace, req.PodName)
		// NB: we don't need to worry about locking here because the cniserver
		// isn't running for real yet.
		if _, err := node.podManager.handleCNIRequest(req); err == nil {
			delete(existingPodSandboxes, sandboxID)
		} else {
			klog.Warningf("Could not reattach pod '%s/%s' to SDN: %v", req.PodNamespace, req.PodName, err)
		}
	}

	// Kill any remaining pods in another thread, after letting SDN startup proceed
	go node.killFailedPods(existingPodSandboxes)

	return nil
}

func (node *OsdnNode) killFailedPods(failed map[string]*kruntimeapi.PodSandbox) {
	// Kill pods we couldn't recover; they will get restarted and then
	// we'll be able to set them up correctly
	for _, sandbox := range failed {
		podRef := &corev1.ObjectReference{Kind: "Pod", Name: sandbox.Metadata.Name, Namespace: sandbox.Metadata.Namespace, UID: types.UID(sandbox.Metadata.Uid)}
		node.recorder.Eventf(podRef, corev1.EventTypeWarning, "NetworkFailed", "The pod's network interface has been lost and the pod will be stopped.")

		klog.V(5).Infof("Killing pod '%s/%s' sandbox", podRef.Namespace, podRef.Name)
		if err := node.runtimeService.StopPodSandbox(sandbox.Id); err != nil {
			klog.Warningf("Failed to kill pod '%s/%s' sandbox: %v", podRef.Namespace, podRef.Name, err)
		}
	}
}

// FIXME: this should eventually go into kubelet via a CNI UPDATE/CHANGE action
// See https://github.com/containernetworking/cni/issues/89
func (node *OsdnNode) UpdatePod(pod corev1.Pod) error {
	filter := &kruntimeapi.PodSandboxFilter{
		LabelSelector: map[string]string{ktypes.KubernetesPodUIDLabel: string(pod.UID)},
	}
	sandboxID, err := node.getPodSandboxID(filter)
	if err != nil {
		return err
	}

	req := &cniserver.PodRequest{
		Command:      cniserver.CNI_UPDATE,
		PodNamespace: pod.Namespace,
		PodName:      pod.Name,
		SandboxID:    sandboxID,
		Result:       make(chan *cniserver.PodResult),
	}

	// Send request and wait for the result
	_, err = node.podManager.handleCNIRequest(req)
	return err
}

func (node *OsdnNode) GetRunningPods(namespace string) ([]corev1.Pod, error) {
	podList, err := common.ListPodsInNodeAndNamespace(context.TODO(), node.kClient, node.hostName, namespace)
	if err != nil {
		return nil, err
	}

	// Filter running pods
	pods := []corev1.Pod{}
	for _, pod := range podList {
		if pod.Status.Phase == corev1.PodRunning {
			pods = append(pods, *pod)
		}
	}
	return pods, nil
}

func isServiceChanged(oldsvc, newsvc *corev1.Service) bool {
	if len(oldsvc.Spec.Ports) == len(newsvc.Spec.Ports) {
		for i := range oldsvc.Spec.Ports {
			if oldsvc.Spec.Ports[i].Protocol != newsvc.Spec.Ports[i].Protocol ||
				oldsvc.Spec.Ports[i].Port != newsvc.Spec.Ports[i].Port {
				return true
			}
		}
		return false
	}
	return true
}

func (node *OsdnNode) watchServices() {
	funcs := common.InformerFuncs(&kapi.Service{}, node.handleAddOrUpdateService, node.handleDeleteService)
	node.kubeInformers.Core().V1().Services().Informer().AddEventHandler(funcs)
}

func (node *OsdnNode) handleAddOrUpdateService(obj, oldObj interface{}, eventType watch.EventType) {
	serv := obj.(*corev1.Service)
	// Ignore headless/external services
	if !helper.IsServiceIPSet(serv) {
		return
	}

	klog.V(5).Infof("Watch %s event for Service %q", eventType, serv.Name)
	oldServ, exists := oldObj.(*corev1.Service)
	if exists {
		if !isServiceChanged(oldServ, serv) {
			return
		}
		node.DeleteServiceRules(oldServ)
	}

	netid, err := node.policy.GetVNID(serv.Namespace)
	if err != nil {
		klog.Errorf("Skipped adding service rules for serviceEvent: %v, Error: %v", eventType, err)
		return
	}

	node.AddServiceRules(serv, netid)
	node.policy.EnsureVNIDRules(netid)
}

func (node *OsdnNode) handleDeleteService(obj interface{}) {
	serv := obj.(*corev1.Service)
	// Ignore headless/external services
	if !helper.IsServiceIPSet(serv) {
		return
	}

	klog.V(5).Infof("Watch %s event for Service %q", watch.Deleted, serv.Name)
	node.DeleteServiceRules(serv)
}

func (node *OsdnNode) ReloadIPTables() error {
	return node.nodeIPTables.syncIPTableRules()
}
