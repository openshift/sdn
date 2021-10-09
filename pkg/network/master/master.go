package master

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
	kclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	osdnv1 "github.com/openshift/api/network/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
	osdninformersv1 "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	masterutil "github.com/openshift/sdn/pkg/network/master/util"
)

const (
	tun0 = "tun0"
)

type OsdnMaster struct {
	kClient     kclientset.Interface
	osdnClient  osdnclient.Interface
	networkInfo *common.ParsedClusterNetwork
	vnids       *masterVNIDMap

	nodeInformer         kcoreinformers.NodeInformer
	namespaceInformer    kcoreinformers.NamespaceInformer
	hostSubnetInformer   osdninformersv1.HostSubnetInformer
	netNamespaceInformer osdninformersv1.NetNamespaceInformer
	egressNetPolInformer osdninformersv1.EgressNetworkPolicyInformer

	// Used for allocating subnets in order
	subnetAllocator *masterutil.SubnetAllocator

	// Holds Node IP used in creating host subnet for a node
	hostSubnetNodeIPs map[ktypes.UID]string
}

func Start(kClient kclientset.Interface,
	kubeInformers informers.SharedInformerFactory,
	osdnClient osdnclient.Interface,
	osdnInformers osdninformers.SharedInformerFactory) error {
	klog.Infof("Initializing SDN master")

	networkInfo, err := common.GetParsedClusterNetwork(osdnClient)
	if err != nil {
		return err
	}

	master := &OsdnMaster{
		kClient:     kClient,
		osdnClient:  osdnClient,
		networkInfo: networkInfo,

		nodeInformer:         kubeInformers.Core().V1().Nodes(),
		namespaceInformer:    kubeInformers.Core().V1().Namespaces(),
		hostSubnetInformer:   osdnInformers.Network().V1().HostSubnets(),
		netNamespaceInformer: osdnInformers.Network().V1().NetNamespaces(),
		egressNetPolInformer: osdnInformers.Network().V1().EgressNetworkPolicies(),

		hostSubnetNodeIPs: map[ktypes.UID]string{},
	}

	if err = master.checkClusterNetworkAgainstLocalNetworks(); err != nil {
		return err
	}
	if err = master.checkClusterNetworkAgainstClusterObjects(); err != nil {
		klog.Errorf("Cluster contains objects incompatible with ClusterNetwork: %v", err)
	}

	// FIXME: this is required to register informers for the types we care about to ensure the informers are started.
	// FIXME: restructure this controller to add event handlers in Start() before returning, instead of inside startSubSystems.
	master.nodeInformer.Informer().GetController()
	master.namespaceInformer.Informer().GetController()
	master.hostSubnetInformer.Informer().GetController()
	master.netNamespaceInformer.Informer().GetController()
	master.egressNetPolInformer.Informer().GetController()

	go master.startSubSystems(master.networkInfo.PluginName)

	return nil
}

func (master *OsdnMaster) startSubSystems(pluginName string) {
	// Wait for informer sync
	if !cache.WaitForCacheSync(wait.NeverStop,
		master.nodeInformer.Informer().GetController().HasSynced,
		master.namespaceInformer.Informer().GetController().HasSynced,
		master.hostSubnetInformer.Informer().GetController().HasSynced,
		master.netNamespaceInformer.Informer().GetController().HasSynced,
		master.egressNetPolInformer.Informer().GetController().HasSynced) {
		klog.Fatalf("failed to sync SDN master informers")
	}

	if err := master.startSubnetMaster(); err != nil {
		klog.Fatalf("failed to start subnet master: %v", err)
	}

	switch pluginName {
	case networkutils.MultiTenantPluginName:
		master.vnids = newMasterVNIDMap(true)
	case networkutils.NetworkPolicyPluginName:
		master.vnids = newMasterVNIDMap(false)
	}
	if master.vnids != nil {
		if err := master.startVNIDMaster(); err != nil {
			klog.Fatalf("failed to start VNID master: %v", err)
		}
	}

	eim := newEgressIPManager()
	eim.Start(master.osdnClient, master.hostSubnetInformer, master.netNamespaceInformer, master.nodeInformer)
	enp := newEgressNetworkPolicyManager()
	enp.start(master.egressNetPolInformer)
}

func (master *OsdnMaster) checkClusterNetworkAgainstLocalNetworks() error {
	hostIPNets, _, err := common.GetHostIPNetworks([]string{tun0})
	if err != nil {
		return err
	}
	return master.networkInfo.CheckHostNetworks(hostIPNets)
}

func (master *OsdnMaster) checkClusterNetworkAgainstClusterObjects() error {
	var subnets []osdnv1.HostSubnet
	var pods []corev1.Pod
	var services []corev1.Service
	if subnetList, err := master.osdnClient.NetworkV1().HostSubnets().List(context.TODO(), metav1.ListOptions{}); err == nil {
		subnets = subnetList.Items
	}
	if podList, err := master.kClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{}); err == nil {
		pods = podList.Items
	}
	if serviceList, err := master.kClient.CoreV1().Services(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{}); err == nil {
		services = serviceList.Items
	}

	return master.networkInfo.CheckClusterObjects(subnets, pods, services)
}
