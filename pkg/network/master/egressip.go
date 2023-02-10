package master

import (
	"context"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	osdcnv1 "github.com/openshift/api/cloudnetwork/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	cloudnetworkclient "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformerv1 "github.com/openshift/client-go/cloudnetwork/informers/externalversions/cloudnetwork/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
)

type egressIPManager struct {
	sync.Mutex

	tracker                      *common.EgressIPTracker
	osdnClient                   osdnclient.Interface
	cloudNetworkClient           cloudnetworkclient.Interface
	hostSubnetInformer           osdninformers.HostSubnetInformer
	nodeInformer                 kcoreinformers.NodeInformer
	cloudPrivateIPConfigInformer cloudnetworkinformerv1.CloudPrivateIPConfigInformer

	cloudPrivateIPConfigCreationQueueLock sync.Mutex
	cloudPrivateIPConfigCreationQueue     map[string]osdcnv1.CloudPrivateIPConfig

	updatePending bool
	updatedAgain  bool

	monitorNodes map[string]*egressNode
	stop         chan struct{}
}

type egressNode struct {
	ip      string
	sdnIP   string
	name    string
	offline bool
	retries int
}

func newEgressIPManager(cloudEgressIP bool, localIP string) *egressIPManager {
	eim := &egressIPManager{}
	eim.tracker = common.NewEgressIPTracker(eim, cloudEgressIP, localIP)
	return eim
}

func (eim *egressIPManager) Start(kubeClient kubernetes.Interface,
	osdnClient osdnclient.Interface,
	cloudNetworkClient cloudnetworkclient.Interface,
	cloudPrivateIPConfigInformer cloudnetworkinformerv1.CloudPrivateIPConfigInformer,
	hostSubnetInformer osdninformers.HostSubnetInformer,
	netNamespaceInformer osdninformers.NetNamespaceInformer,
	nodeInformer kcoreinformers.NodeInformer) {

	eim.osdnClient = osdnClient
	eim.hostSubnetInformer = hostSubnetInformer
	eim.nodeInformer = nodeInformer

	if eim.tracker.CloudEgressIP {
		eim.cloudNetworkClient = cloudNetworkClient
		eim.cloudPrivateIPConfigInformer = cloudPrivateIPConfigInformer
		eim.cloudPrivateIPConfigCreationQueue = make(map[string]osdcnv1.CloudPrivateIPConfig)
		eim.watchCloudPrivateIPConfig(cloudPrivateIPConfigInformer)
		eim.tracker.Start(kubeClient, hostSubnetInformer, netNamespaceInformer, nodeInformer)
		return
	}

	eim.tracker.Start(nil, hostSubnetInformer, netNamespaceInformer, nil)
}

func (eim *egressIPManager) watchCloudPrivateIPConfig(cloudPrivateIPConfigInformer cloudnetworkinformerv1.CloudPrivateIPConfigInformer) {
	funcs := common.InformerFuncs(&osdcnv1.CloudPrivateIPConfig{}, nil, eim.handleDeleteCloudPrivateIPConfig)
	eim.cloudPrivateIPConfigInformer.Informer().AddEventHandler(funcs)
}

func (eim *egressIPManager) handleDeleteCloudPrivateIPConfig(obj interface{}) {
	eim.cloudPrivateIPConfigCreationQueueLock.Lock()
	defer eim.cloudPrivateIPConfigCreationQueueLock.Unlock()
	cloudPrivateIPConfig := obj.(*osdcnv1.CloudPrivateIPConfig)
	// Note: we can be assured that when we receive the delete event everything
	// must have been cleaned up on the cloud controller's side, because of the
	// utilization of the finalizer.
	if queuedCloudPrivateIPConfig, exists := eim.cloudPrivateIPConfigCreationQueue[cloudPrivateIPConfig.Name]; exists {
		klog.Infof("CloudPrivateIPConfig: %s has been deleted, processing its queued creation item", cloudPrivateIPConfig.Name)
		// Retry the creation, just in case the object has not been fully
		// cleaned up in the API server at this point.
		err := retry.OnError(retry.DefaultBackoff, func(err error) bool {
			return kerrors.IsAlreadyExists(err)
		}, func() error {
			_, err := eim.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Create(context.TODO(), &queuedCloudPrivateIPConfig, metav1.CreateOptions{})
			return err
		})
		if err != nil {
			klog.Errorf("Error creating queued CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfig.Name, err)
		} else {
			delete(eim.cloudPrivateIPConfigCreationQueue, cloudPrivateIPConfig.Name)
		}
	}
}

func (eim *egressIPManager) UpdateEgressCIDRs() {
	eim.Lock()
	defer eim.Unlock()

	// Coalesce multiple "UpdateEgressCIDRs" notifications into one by queueing
	// the update to happen a little bit later in a goroutine, and postponing that
	// update any time we get another "UpdateEgressCIDRs".

	if eim.updatePending {
		eim.updatedAgain = true
	} else {
		eim.updatePending = true
		go utilwait.PollInfinite(time.Second, eim.maybeDoUpdateEgressCIDRs)
	}
}

func (eim *egressIPManager) maybeDoUpdateEgressCIDRs() (bool, error) {
	eim.Lock()
	defer eim.Unlock()

	if eim.updatedAgain {
		eim.updatedAgain = false
		return false, nil
	}
	eim.updatePending = false

	// At this point it has been at least 1 second since the last "UpdateEgressCIDRs"
	// notification, so things are stable.
	//
	// ReallocateEgressIPs() will figure out what HostSubnets either can have new
	// egress IPs added to them, or need to have egress IPs removed from them, and
	// returns a map from node name to the new EgressIPs value, for each changed
	// HostSubnet.
	//
	// If a HostSubnet's EgressCIDRs changes while we are processing the reallocation,
	// we won't process that until this reallocation is complete.

	allocation := eim.tracker.ReallocateEgressIPs()
	monitorNodes := make(map[string]*egressNode, len(allocation))
	for nodeName, egressIPs := range allocation {
		resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			hs, err := eim.hostSubnetInformer.Lister().Get(nodeName)
			if err != nil {
				return err
			}

			if node := eim.monitorNodes[hs.HostIP]; node != nil {
				monitorNodes[hs.HostIP] = node
			} else {
				_, cidr, _ := net.ParseCIDR(hs.Subnet)
				sdnIP := common.GenerateDefaultGateway(cidr).String()
				monitorNodes[hs.HostIP] = &egressNode{ip: hs.HostIP, sdnIP: sdnIP, name: nodeName}
			}

			oldIPs := sets.NewString(common.HSEgressIPsToStrings(hs.EgressIPs)...)
			newIPs := sets.NewString(egressIPs...)
			if !oldIPs.Equal(newIPs) {
				hs.EgressIPs = common.StringsToHSEgressIPs(egressIPs)
				_, err = eim.osdnClient.NetworkV1().HostSubnets().Update(context.TODO(), hs, metav1.UpdateOptions{})
			}
			return err
		})
		if resultErr != nil {
			klog.Errorf("Could not update HostSubnet EgressIPs: %v", resultErr)
		}
	}

	eim.monitorNodes = monitorNodes
	if len(monitorNodes) > 0 {
		if eim.stop == nil {
			eim.stop = make(chan struct{})
			go eim.poll(eim.stop)
		}
	} else {
		if eim.stop != nil {
			close(eim.stop)
			eim.stop = nil
		}
	}

	return true, nil
}

const (
	maxRetries = 2
)

func (eim *egressIPManager) poll(stop chan struct{}) {
	retry := false
	for {
		select {
		case <-stop:
			return
		default:
		}

		start := time.Now()
		retry, err := eim.check(retry)
		if err != nil {
			klog.Warningf("Node may have been deleted or not exist anymore")
		}
		if !retry {
			// If less than common.DefaultPollInterval has passed since start, then sleep until it has
			time.Sleep(start.Add(common.DefaultPollInterval).Sub(time.Now()))
		}
	}
}

func nodeIsReady(node *corev1.Node) bool {
	nodeReady := true
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			if cond.Status == corev1.ConditionFalse || cond.Status == corev1.ConditionUnknown {
				nodeReady = false
			}
		}
	}
	return nodeReady
}

func (eim *egressIPManager) check(retrying bool) (bool, error) {
	var timeout time.Duration
	if retrying {
		timeout = common.RepollInterval
	} else {
		timeout = common.DefaultPollInterval
	}

	needRetry := false
	for _, node := range eim.monitorNodes {
		if retrying && node.retries == 0 {
			continue
		}

		nn, err := eim.nodeInformer.Lister().Get(node.name)
		if err != nil {
			return false, err
		}

		if !nodeIsReady(nn) {
			klog.Warningf("Node %s is not Ready, marking it offline...", node.name)
			node.offline = true
			eim.tracker.SetNodeOffline(node.ip, true)
			// continue to process other nodes in the list when we encounter a not Ready node
			continue
		}

		online := eim.tracker.Ping(node.sdnIP, timeout)
		if node.offline && online {
			klog.Infof("Node %s is back online", node.ip)
			node.offline = false
			eim.tracker.SetNodeOffline(node.ip, false)
		} else if !node.offline && !online {
			node.retries++
			if node.retries > maxRetries {
				klog.Warningf("Node %s is offline", node.ip)
				node.retries = 0
				node.offline = true
				eim.tracker.SetNodeOffline(node.ip, true)
			} else {
				klog.V(2).Infof("Node %s may be offline... retrying", node.ip)
				needRetry = true
			}
		}
	}

	return needRetry, nil
}

func (eim *egressIPManager) Synced() {
}

// ClaimEgressIP will create the CloudPrivateIPConfig object. There is one
// tricky condition which we will need to handle, namely: when moving one egress
// IP from node A to node B. In that event: we will process the removal from
// node A before the add to node B, this can however take a bit of time (namely:
// the time taken for the cloud controller to process and execute the event and
// the cloud API to perform the action). Given that CloudPrivateIPConfig is
// keyed by IP address: we won't be able to create the assignment to node B
// until the previous assignment to node A has been fully removed. We thus need
// to "queue" the create event and execute it once we observe the complete
// removal of the delete using our informer.
func (eim *egressIPManager) ClaimEgressIP(vnid uint32, egressIP, nodeIP, sdnIP string, nodeOffline bool) {
	if !eim.tracker.CloudEgressIP {
		return
	}
	eim.cloudPrivateIPConfigCreationQueueLock.Lock()
	defer eim.cloudPrivateIPConfigCreationQueueLock.Unlock()
	if nodeName := eim.tracker.GetNodeNameByNodeIP(nodeIP); nodeName != "" {
		cloudPrivateIPConfig := osdcnv1.CloudPrivateIPConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: egressIP,
			},
			Spec: osdcnv1.CloudPrivateIPConfigSpec{
				Node: nodeName,
			},
		}
		if existingCloudPrivateIPConfig, err := eim.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Create(context.TODO(), &cloudPrivateIPConfig, metav1.CreateOptions{}); err != nil {
			if kerrors.IsAlreadyExists(err) && existingCloudPrivateIPConfig.Spec.Node != nodeName {
				klog.Infof("CloudPrivateIPConfig: %s is being moved and still exists, enqueuing its creation", egressIP)
				eim.cloudPrivateIPConfigCreationQueue[egressIP] = cloudPrivateIPConfig
			} else {
				klog.Errorf("Error creating CloudPrivateIPConfig: %s, err: %v", egressIP, err)
			}
		}
	}
}

// ReleaseEgressIP will delete the CloudPrivateIPConfig object, essentially
// un-assigning the egressIP from the node associated with nodeIP, in the cloud.
// We however need to cancel any item on the creation queue if it is being
// deleted. This would technically mean that the egress IP we are waiting on for
// assignment has already been deleted from the existing node, which might be
// probable during an upgrade where all nodes are rebooted sequentially and any
// egress IP assignment might not last very long.
func (eim *egressIPManager) ReleaseEgressIP(egressIP, nodeIP string) {
	if !eim.tracker.CloudEgressIP {
		return
	}
	eim.cloudPrivateIPConfigCreationQueueLock.Lock()
	defer eim.cloudPrivateIPConfigCreationQueueLock.Unlock()
	if err := eim.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Delete(context.TODO(), egressIP, metav1.DeleteOptions{}); err != nil {
		klog.Errorf("Error deleting CloudPrivateIPConfig: %s, err: %v", egressIP, err)
	}
	if _, exists := eim.cloudPrivateIPConfigCreationQueue[egressIP]; exists {
		klog.Infof("Processing removal for CloudPrivateIPConfig: %s, deleting it's queued creation item", egressIP)
		delete(eim.cloudPrivateIPConfigCreationQueue, egressIP)
	}
}

func (eim *egressIPManager) SetNamespaceEgressNormal(vnid uint32) {
}

func (eim *egressIPManager) SetNamespaceEgressDropped(vnid uint32) {
}

func (eim *egressIPManager) SetNamespaceEgressViaEgressIPs(vnid uint32, activeEgressIPs []common.EgressIPAssignment) {
}
