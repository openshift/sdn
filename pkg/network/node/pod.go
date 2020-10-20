// +build linux

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/containernetworking/cni/pkg/types/current"

	networkv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/network/node/cniserver"
	metrics "github.com/openshift/sdn/pkg/network/node/metrics"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/klog/v2"
	kcontainer "k8s.io/kubernetes/pkg/kubelet/container"
	kbandwidth "k8s.io/kubernetes/pkg/util/bandwidth"

	"github.com/containernetworking/cni/pkg/invoke"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
)

const (
	podInterfaceName               = "eth0"
	hostLocalDataDir               = "/var/lib/cni/networks"
	containerLocalCniPluginsBinDir = "/usr/bin/cni"
)

type podHandler interface {
	setup(req *cniserver.PodRequest) (cnitypes.Result, *runningPod, error)
	update(req *cniserver.PodRequest) (uint32, error)
	teardown(req *cniserver.PodRequest) error
}

type runningPod struct {
	vnid   uint32
	ofport int
}

type podManager struct {
	// Common stuff used for both live and testing code
	podHandler podHandler
	cniServer  *cniserver.CNIServer
	// Request queue for pod operations incoming from the CNIServer
	requests chan (*cniserver.PodRequest)
	// Tracks pod info for updates
	runningPods     map[string]*runningPod
	runningPodsLock sync.Mutex

	// Live pod setup/teardown stuff not used in testing code
	kClient kubernetes.Interface
	policy  osdnPolicy
	mtu     uint32
	ovs     *ovsController

	// Things only accessed through the processCNIRequests() goroutine
	// and thus can be set from Start()
	ipamConfig []byte
}

// Creates a new live podManager; used by node code0
func newPodManager(kClient kubernetes.Interface, policy osdnPolicy, mtu uint32, ovs *ovsController) *podManager {
	pm := newDefaultPodManager()
	pm.kClient = kClient
	pm.policy = policy
	pm.mtu = mtu
	pm.podHandler = pm
	pm.ovs = ovs
	return pm
}

// Creates a new basic podManager; used by testcases
func newDefaultPodManager() *podManager {
	return &podManager{
		runningPods: make(map[string]*runningPod),
		requests:    make(chan *cniserver.PodRequest, 20),
	}
}

// Generates a CNI IPAM config from a given node cluster and local subnet that
// CNI 'host-local' IPAM plugin will use to create an IP address lease for the
// container
func getIPAMConfig(clusterNetworks []common.ParsedClusterNetworkEntry, localSubnet string) ([]byte, error) {
	nodeNet, err := cnitypes.ParseCIDR(localSubnet)
	if err != nil {
		return nil, fmt.Errorf("error parsing node network '%s': %v", localSubnet, err)
	}

	type hostLocalIPAM struct {
		Type    string           `json:"type"`
		Subnet  cnitypes.IPNet   `json:"subnet"`
		Routes  []cnitypes.Route `json:"routes"`
		DataDir string           `json:"dataDir"`
	}

	type cniNetworkConfig struct {
		CNIVersion string         `json:"cniVersion"`
		Name       string         `json:"name"`
		Type       string         `json:"type"`
		IPAM       *hostLocalIPAM `json:"ipam"`
	}

	_, mcnet, _ := net.ParseCIDR("224.0.0.0/4")

	routes := []cnitypes.Route{
		{
			//Default route
			Dst: net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.IPMask(net.IPv4zero),
			},
			GW: common.GenerateDefaultGateway(nodeNet),
		},
		{
			//Multicast
			Dst: *mcnet,
		},
	}

	for _, cn := range clusterNetworks {
		routes = append(routes, cnitypes.Route{Dst: *cn.ClusterCIDR})
	}

	return json.Marshal(&cniNetworkConfig{
		CNIVersion: "0.3.1",
		Name:       "openshift-sdn",
		Type:       "openshift-sdn",
		IPAM: &hostLocalIPAM{
			Type:    "host-local",
			DataDir: hostLocalDataDir,
			Subnet: cnitypes.IPNet{
				IP:   nodeNet.IP,
				Mask: nodeNet.Mask,
			},
			Routes: routes,
		},
	})
}

// Start the CNI server and start processing requests from it
func (m *podManager) Start(rundir string, localSubnetCIDR string, clusterNetworks []common.ParsedClusterNetworkEntry, serviceNetworkCIDR string) error {
	var err error
	if m.ipamConfig, err = getIPAMConfig(clusterNetworks, localSubnetCIDR); err != nil {
		return err
	}

	go m.processCNIRequests()

	m.cniServer = cniserver.NewCNIServer(rundir, &cniserver.Config{MTU: m.mtu, ServiceNetworkCIDR: serviceNetworkCIDR})
	return m.cniServer.Start(m.handleCNIRequest)
}

func (m *podManager) InitRunningPods(existingPodSandboxes map[string]*kruntimeapi.PodSandbox, existingOFPodNetworks map[string]podNetworkInfo) error {
	m.runningPodsLock.Lock()
	defer m.runningPodsLock.Unlock()

	for _, sandbox := range existingPodSandboxes {
		sKey := getPodKey(sandbox.Metadata.Namespace, sandbox.Metadata.Name)

		vnid, err := m.policy.GetVNID(sandbox.Metadata.Namespace)
		if err != nil {
			klog.Warningf("No VNID for pod %s", sKey)
			continue
		}

		podNetworkInfo, ok := existingOFPodNetworks[sandbox.Id]
		if !ok {
			klog.Warningf("No network information for pod %s", sKey)
			continue
		}

		m.runningPods[sKey] = &runningPod{vnid: vnid, ofport: podNetworkInfo.ofport}
	}

	klog.V(5).Infof("Finished initializing podManager with running pods at start-up")
	return nil
}

// Returns a key for use with the runningPods map
func getPodKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func (m *podManager) getPod(request *cniserver.PodRequest) *runningPod {
	return m.runningPods[getPodKey(request.PodNamespace, request.PodName)]
}

// Add a request to the podManager CNI request queue
func (m *podManager) addRequest(request *cniserver.PodRequest) {
	m.requests <- request
}

// Wait for and return the result of a pod request
func (m *podManager) waitRequest(request *cniserver.PodRequest) *cniserver.PodResult {
	return <-request.Result
}

// Enqueue incoming pod requests from the CNI server, wait on the result,
// and return that result to the CNI client
func (m *podManager) handleCNIRequest(request *cniserver.PodRequest) ([]byte, error) {
	klog.V(5).Infof("Dispatching pod network request %v", request)
	m.addRequest(request)
	result := m.waitRequest(request)
	klog.V(5).Infof("Returning pod network request %v, result %s err %v", request, string(result.Response), result.Err)
	return result.Response, result.Err
}

func (m *podManager) updateLocalMulticastRulesWithLock(vnid uint32) {
	var ofports []int
	enabled := m.policy.GetMulticastEnabled(vnid)
	if enabled {
		for _, pod := range m.runningPods {
			if pod.vnid == vnid {
				ofports = append(ofports, pod.ofport)
			}
		}
	}

	if err := m.ovs.UpdateLocalMulticastFlows(vnid, enabled, ofports); err != nil {
		utilruntime.HandleError(fmt.Errorf("Error updating OVS multicast flows for VNID %d: %v", vnid, err))

	}
}

// Update multicast OVS rules for the given vnid
func (m *podManager) UpdateLocalMulticastRules(vnid uint32) {
	m.runningPodsLock.Lock()
	defer m.runningPodsLock.Unlock()
	m.updateLocalMulticastRulesWithLock(vnid)
}

// Process all CNI requests from the request queue serially.  Our OVS interaction
// and scripts currently cannot run in parallel, and doing so greatly complicates
// setup/teardown logic
func (m *podManager) processCNIRequests() {
	for request := range m.requests {
		result := m.processRequest(request)
		request.Result <- result
	}
	panic("stopped processing CNI pod requests!")
}

func (m *podManager) processRequest(request *cniserver.PodRequest) *cniserver.PodResult {
	m.runningPodsLock.Lock()
	defer m.runningPodsLock.Unlock()

	pk := getPodKey(request.PodNamespace, request.PodName)
	result := &cniserver.PodResult{}
	switch request.Command {
	case cniserver.CNI_ADD:
		ipamResult, runningPod, err := m.podHandler.setup(request)
		if ipamResult != nil {
			result.Response, err = json.Marshal(ipamResult)
			if err == nil {
				m.runningPods[pk] = runningPod
				if m.ovs != nil {
					m.updateLocalMulticastRulesWithLock(runningPod.vnid)
				}
			}
		}
		if err != nil {
			klog.Warningf("CNI_ADD %s failed: %v", pk, err)
			metrics.PodOperationsErrors.WithLabelValues(metrics.PodOperationSetup).Inc()
			result.Err = err
		}
	case cniserver.CNI_UPDATE:
		vnid, err := m.podHandler.update(request)
		if err == nil {
			if runningPod, exists := m.runningPods[pk]; exists {
				runningPod.vnid = vnid
			}
		} else {
			klog.Warningf("CNI_UPDATE %s failed: %v", pk, err)
		}
		result.Err = err
	case cniserver.CNI_DEL:
		if runningPod, exists := m.runningPods[pk]; exists {
			delete(m.runningPods, pk)
			if m.ovs != nil {
				m.updateLocalMulticastRulesWithLock(runningPod.vnid)
			}
		}
		result.Err = m.podHandler.teardown(request)
		if result.Err != nil {
			klog.Warningf("CNI_DEL %s failed: %v", pk, result.Err)
			metrics.PodOperationsErrors.WithLabelValues(metrics.PodOperationTeardown).Inc()
		}
	default:
		result.Err = fmt.Errorf("unhandled CNI request %v", request.Command)
	}
	return result
}

// Adds a macvlan interface to a container, if requested, for use with the egress router feature
func maybeAddMacvlan(pod *corev1.Pod, netns string) error {
	annotation, ok := pod.Annotations[networkv1.AssignMacvlanAnnotation]
	if !ok || annotation == "false" {
		return nil
	}

	privileged := false
	for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			privileged = true
			break
		}
	}
	if !privileged {
		return fmt.Errorf("pod has %q annotation but is not privileged", networkv1.AssignMacvlanAnnotation)
	}

	var iface netlink.Link
	var err error
	if annotation == "true" {
		// Find interface with the default route
		routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("failed to read routes: %v", err)
		}

		for _, r := range routes {
			if r.Dst == nil {
				iface, err = netlink.LinkByIndex(r.LinkIndex)
				if err != nil {
					return fmt.Errorf("failed to get default route interface: %v", err)
				}
			}
		}
		if iface == nil {
			return fmt.Errorf("failed to find default route interface")
		}
	} else {
		iface, err = netlink.LinkByName(annotation)
		if err != nil {
			return fmt.Errorf("pod annotation %q is neither 'true' nor the name of a local network interface", networkv1.AssignMacvlanAnnotation)
		}
	}

	// Note that this use of ns is safe because it doesn't call Do() or WithNetNSPath()

	podNs, err := ns.GetNS(netns)
	if err != nil {
		return fmt.Errorf("could not open netns %q: %v", netns, err)
	}
	defer podNs.Close()

	err = netlink.LinkAdd(&netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         iface.Attrs().MTU,
			Name:        "macvlan0",
			ParentIndex: iface.Attrs().Index,
			Namespace:   netlink.NsFd(podNs.Fd()),
		},
		Mode: netlink.MACVLAN_MODE_PRIVATE,
	})
	if err != nil {
		return fmt.Errorf("failed to create macvlan interface: %v", err)
	}
	return nil
}

func createIPAMArgs(netnsPath string, action cniserver.CNICommand, id string) *invoke.Args {
	return &invoke.Args{
		Command:     string(action),
		ContainerID: id,
		NetNS:       netnsPath,
		IfName:      podInterfaceName,
		Path:        containerLocalCniPluginsBinDir,
	}
}

// Run CNI IPAM allocation for the container and return the allocated IP address
func (m *podManager) ipamAdd(netnsPath string, id string) (*current.Result, net.IP, error) {
	if netnsPath == "" {
		return nil, nil, fmt.Errorf("netns required for CNI_ADD")
	}

	args := createIPAMArgs(netnsPath, cniserver.CNI_ADD, id)
	r, err := invoke.ExecPluginWithResult(containerLocalCniPluginsBinDir+"/osdn-host-local", m.ipamConfig, args)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run CNI IPAM ADD: %v", err)
	}

	// We gave the IPAM plugin 0.3.1 config, so the plugin must return a 0.3.1 result
	result, err := current.GetResult(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CNI IPAM ADD result: %v", err)
	}
	if len(result.IPs) == 0 {
		return nil, nil, fmt.Errorf("failed to obtain IP address from CNI IPAM")
	}

	return result, result.IPs[0].Address.IP, nil
}

// Run CNI IPAM release for the container
func (m *podManager) ipamDel(id string) error {
	args := createIPAMArgs("", cniserver.CNI_DEL, id)
	err := invoke.ExecPluginWithoutResult(containerLocalCniPluginsBinDir+"/osdn-host-local", m.ipamConfig, args)
	if err != nil {
		return fmt.Errorf("failed to run CNI IPAM DEL: %v", err)
	}
	return nil
}

func setupPodBandwidth(ovs *ovsController, pod *corev1.Pod, hostVeth, sandboxID string) error {
	ingressVal, egressVal, err := kbandwidth.ExtractPodBandwidthResources(pod.Annotations)
	if err != nil {
		return fmt.Errorf("failed to parse pod bandwidth: %v", err)
	}

	ingressBPS := int64(-1)
	egressBPS := int64(-1)
	if ingressVal != nil {
		ingressBPS = ingressVal.Value()

		l, err := netlink.LinkByName(hostVeth)
		if err != nil {
			return fmt.Errorf("failed to find host veth interface %s: %v", hostVeth, err)
		}
		err = netlink.LinkSetTxQLen(l, 1000)
		if err != nil {
			return fmt.Errorf("failed to set host veth txqlen: %v", err)
		}
	}
	if egressVal != nil {
		egressBPS = egressVal.Value()
	}

	return ovs.SetPodBandwidth(hostVeth, sandboxID, ingressBPS, egressBPS)
}

func vnidToString(vnid uint32) string {
	return strconv.FormatUint(uint64(vnid), 10)
}

// podIsExited returns true if the pod is exited (all containers inside are exited).
func podIsExited(p *kcontainer.Pod) bool {
	for _, c := range p.Containers {
		if c.State != kcontainer.ContainerStateExited {
			return false
		}
	}
	return true
}

// Set up all networking (host/container veth, OVS flows, IPAM, loopback, etc)
func (m *podManager) setup(req *cniserver.PodRequest) (cnitypes.Result, *runningPod, error) {
	defer metrics.PodOperationsLatency.WithLabelValues(metrics.PodOperationSetup).Observe(metrics.SinceInMicroseconds(time.Now()))

	// Release any IPAM allocations if the setup failed
	var success bool
	defer func() {
		if !success {
			m.ipamDel(req.SandboxID)
		}
	}()

	v1Pod, err := m.kClient.CoreV1().Pods(req.PodNamespace).Get(context.TODO(), req.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	var ipamResult cnitypes.Result
	podIP := net.ParseIP(req.AssignedIP)
	if podIP == nil {
		ipamResult, podIP, err = m.ipamAdd(req.Netns, req.SandboxID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to run IPAM for %v: %v", req.SandboxID, err)
		}
		if err := maybeAddMacvlan(v1Pod, req.Netns); err != nil {
			return nil, nil, err
		}
	}

	vnid, err := m.policy.GetVNID(req.PodNamespace)
	if err != nil {
		return nil, nil, err
	}

	ofport, err := m.ovs.SetUpPod(req.SandboxID, req.HostVeth, podIP, vnid)
	if err != nil {
		return nil, nil, err
	}
	if err := setupPodBandwidth(m.ovs, v1Pod, req.HostVeth, req.SandboxID); err != nil {
		return nil, nil, err
	}

	m.policy.EnsureVNIDRules(vnid)
	success = true
	klog.Infof("CNI_ADD %s/%s got IP %s, ofport %d", req.PodNamespace, req.PodName, podIP, ofport)
	return ipamResult, &runningPod{vnid: vnid, ofport: ofport}, nil
}

// Update OVS flows when something (like the pod's namespace VNID) changes
func (m *podManager) update(req *cniserver.PodRequest) (uint32, error) {
	vnid, err := m.policy.GetVNID(req.PodNamespace)
	if err != nil {
		return 0, err
	}

	if err := m.ovs.UpdatePod(req.SandboxID, vnid); err != nil {
		return 0, err
	}
	klog.Infof("CNI_UPDATE %s/%s", req.PodNamespace, req.PodName)
	return vnid, nil
}

// Clean up all pod networking (clear OVS flows, release IPAM lease, remove host/container veth)
func (m *podManager) teardown(req *cniserver.PodRequest) error {
	defer metrics.PodOperationsLatency.WithLabelValues(metrics.PodOperationTeardown).Observe(metrics.SinceInMicroseconds(time.Now()))

	errList := []error{}

	if err := m.ovs.TearDownPod(req.SandboxID); err != nil {
		errList = append(errList, err)
	}

	if err := m.ipamDel(req.SandboxID); err != nil {
		errList = append(errList, err)
	}

	if len(errList) > 0 {
		return kerrors.NewAggregate(errList)
	}

	klog.Infof("CNI_DEL %s/%s", req.PodNamespace, req.PodName)
	return nil
}
