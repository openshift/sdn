package master

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/util/retry"

	networkclient "github.com/openshift/client-go/network/clientset/versioned"
	networkinformers "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
)

type egressIPManager struct {
	sync.Mutex

	tracker            *common.EgressIPTracker
	networkClient      networkclient.Interface
	hostSubnetInformer networkinformers.HostSubnetInformer

	updatePending bool
	updatedAgain  bool
}

func newEgressIPManager() *egressIPManager {
	eim := &egressIPManager{}
	eim.tracker = common.NewEgressIPTracker(eim)
	return eim
}

func (eim *egressIPManager) Start(networkClient networkclient.Interface, hostSubnetInformer networkinformers.HostSubnetInformer, netNamespaceInformer networkinformers.NetNamespaceInformer, nodeInformer kcoreinformers.NodeInformer) {
	eim.networkClient = networkClient
	eim.hostSubnetInformer = hostSubnetInformer
	eim.tracker.Start(hostSubnetInformer, netNamespaceInformer, nodeInformer)
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
	eim.tracker.Lock()
	defer eim.tracker.Unlock()
	newMonitorNodes := make(map[string]*common.NodeEgress, len(allocation))
	oldMonitorNodes := eim.tracker.GetMonitorNodes()
	for nodeName, egressIPs := range allocation {
		resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			hs, err := eim.hostSubnetInformer.Lister().Get(nodeName)
			if err != nil {
				return err
			}

			if node := oldMonitorNodes[hs.HostIP]; node != nil {
				newMonitorNodes[hs.HostIP] = node
			} else {
				newMonitorNodes[hs.HostIP] = &common.NodeEgress{NodeIP: hs.HostIP, NodeName: nodeName}
			}

			oldIPs := sets.NewString(common.HSEgressIPsToStrings(hs.EgressIPs)...)
			newIPs := sets.NewString(egressIPs...)
			if !oldIPs.Equal(newIPs) {
				hs.EgressIPs = common.StringsToHSEgressIPs(egressIPs)
				_, err = eim.networkClient.NetworkV1().HostSubnets().Update(context.TODO(), hs, metav1.UpdateOptions{})
			}
			return err
		})
		if resultErr != nil {
			utilruntime.HandleError(fmt.Errorf("Could not update HostSubnet EgressIPs: %v", resultErr))
		}
	}

	eim.tracker.SetMonitorNodes(newMonitorNodes)
	return true, nil
}

func (eim *egressIPManager) Synced() {
}

func (eim *egressIPManager) ClaimEgressIP(vnid uint32, egressIP, nodeIP, nodeName string) {
}

func (eim *egressIPManager) ReleaseEgressIP(egressIP, nodeIP string) {
}

func (eim *egressIPManager) SetNamespaceEgressNormal(vnid uint32) {
}

func (eim *egressIPManager) SetNamespaceEgressDropped(vnid uint32) {
}

func (eim *egressIPManager) SetNamespaceEgressViaEgressIPs(vnid uint32, activeEgressIPs []common.EgressIPAssignment) {
}
