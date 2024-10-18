package master

import (
	"context"

	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
	kclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	cloudnetworkclient "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformer "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	cloudnetworkinformerv1 "github.com/openshift/client-go/cloudnetwork/informers/externalversions/cloudnetwork/v1"
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
	kClient            kclientset.Interface
	osdnClient         osdnclient.Interface
	cloudNetworkClient cloudnetworkclient.Interface
	networkInfo        *common.ParsedClusterNetwork
	vnids              *masterVNIDMap

	nodeInformer                 kcoreinformers.NodeInformer
	namespaceInformer            kcoreinformers.NamespaceInformer
	hostSubnetInformer           osdninformersv1.HostSubnetInformer
	netNamespaceInformer         osdninformersv1.NetNamespaceInformer
	cloudPrivateIPConfigInformer cloudnetworkinformerv1.CloudPrivateIPConfigInformer
	egressNetPolInformer         osdninformersv1.EgressNetworkPolicyInformer

	// Used for allocating subnets in order
	subnetAllocator *masterutil.SubnetAllocator

	// Holds Node IP used in creating host subnet for a node
	hostSubnetNodeIPs map[ktypes.UID]string
}

func Start(kClient kclientset.Interface,
	kubeInformers informers.SharedInformerFactory,
	osdnClient osdnclient.Interface,
	osdnInformers osdninformers.SharedInformerFactory,
	cloudNetworkClient cloudnetworkclient.Interface,
	cloudNetworkInformer cloudnetworkinformer.SharedInformerFactory) error {
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

	if cloudNetworkClient != nil {
		master.cloudNetworkClient = cloudNetworkClient
		master.cloudPrivateIPConfigInformer = cloudNetworkInformer.Cloud().V1().CloudPrivateIPConfigs()
		master.cloudPrivateIPConfigInformer.Informer().GetController()
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
	if master.cloudNetworkClient != nil && !cache.WaitForCacheSync(wait.NeverStop, master.cloudPrivateIPConfigInformer.Informer().HasSynced) {
		klog.Fatalf("failed to sync CloudPrivateIPConfig informer")
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

	eim := newEgressIPManager(master.cloudNetworkClient != nil, "")
	eim.Start(master.kClient, master.osdnClient, master.cloudNetworkClient, master.cloudPrivateIPConfigInformer, master.hostSubnetInformer, master.netNamespaceInformer, master.nodeInformer)
	enp := newEgressNetworkPolicyManager()
	enp.start(master.egressNetPolInformer)
}

func (master *OsdnMaster) checkClusterNetworkAgainstLocalNetworks() error {
	// During live migration, ignore ovn-k8s-mp0 when it run on a node using ovnkube as CNI.
	hostIPNets, _, err := common.GetHostIPNetworks([]string{tun0, "ovn-k8s-mp0"})
	if err != nil {
		return err
	}
	return master.networkInfo.CheckHostNetworks(hostIPNets)
}

func (master *OsdnMaster) checkClusterNetworkAgainstClusterObjects() error {
	subnets, err := common.ListAllHostSubnets(context.TODO(), master.osdnClient)
	if err != nil {
		klog.Warningf("Failed to list subnets: %v", err)
	}

	pods, err := common.ListAllPods(context.TODO(), master.kClient)
	if err != nil {
		klog.Warningf("Failed to list pods: %v", err)
	}

	services, err := common.ListAllServices(context.TODO(), master.kClient)
	if err != nil {
		klog.Warningf("Failed to list services: %v", err)
	}

	return master.networkInfo.CheckClusterObjects(subnets, pods, services)
}
