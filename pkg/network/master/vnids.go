package master

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	osdnv1 "github.com/openshift/api/network/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdnapihelpers "github.com/openshift/library-go/pkg/network/networkapihelpers"
	"github.com/openshift/sdn/pkg/network/common"
	pnetid "github.com/openshift/sdn/pkg/network/master/netid"
)

type masterVNIDMap struct {
	// Synchronizes assign, revoke and update VNID
	lock         sync.Mutex
	ids          map[string]uint32
	netIDManager *pnetid.Allocator

	allowRenumbering bool
}

func newMasterVNIDMap(allowRenumbering bool) *masterVNIDMap {
	netIDRange, err := pnetid.NewNetIDRange(common.MinVNID, common.MaxVNID)
	if err != nil {
		panic(err)
	}

	return &masterVNIDMap{
		netIDManager:     pnetid.NewInMemory(netIDRange),
		ids:              make(map[string]uint32),
		allowRenumbering: allowRenumbering,
	}
}

func (vmap *masterVNIDMap) getVNID(name string) (uint32, bool) {
	id, found := vmap.ids[name]
	return id, found
}

func (vmap *masterVNIDMap) setVNID(name string, id uint32) {
	vmap.ids[name] = id
}

func (vmap *masterVNIDMap) unsetVNID(name string) (uint32, bool) {
	id, found := vmap.ids[name]
	delete(vmap.ids, name)
	return id, found
}

func (vmap *masterVNIDMap) getVNIDCount(id uint32) int {
	count := 0
	for _, netid := range vmap.ids {
		if id == netid {
			count = count + 1
		}
	}
	return count
}

func (vmap *masterVNIDMap) markAllocatedNetID(netid uint32) error {
	// Skip GlobalVNID, not part of netID allocation range
	if netid < common.MinVNID {
		return nil
	}

	switch err := vmap.netIDManager.Allocate(netid); err {
	case nil: // Expected normal case
	case pnetid.ErrAllocated: // Expected when project networks are joined
	default:
		return fmt.Errorf("unable to allocate netid %d: %v", netid, err)
	}
	return nil
}

func (vmap *masterVNIDMap) allocateNetID(nsName string) (uint32, bool, error) {
	// Nothing to do if the netid is in the vnid map
	exists := false
	if netid, found := vmap.getVNID(nsName); found {
		exists = true
		return netid, exists, nil
	}

	// NetNamespace not found, so allocate new NetID
	var netid uint32
	if nsName == metav1.NamespaceDefault {
		netid = common.GlobalVNID
	} else {
		var err error
		netid, err = vmap.netIDManager.AllocateNext()
		if err != nil {
			return 0, exists, err
		}
	}

	vmap.setVNID(nsName, netid)
	klog.Infof("Allocated netid %d for namespace %q", netid, nsName)
	return netid, exists, nil
}

func (vmap *masterVNIDMap) releaseNetID(nsName string) error {
	// Remove NetID from vnid map
	netid, found := vmap.unsetVNID(nsName)
	if !found {
		return fmt.Errorf("netid not found for namespace %q", nsName)
	}

	// Skip common.GlobalVNID as it is not part of NetID allocation
	if netid == common.GlobalVNID {
		return nil
	}

	// Check if this netid is used by any other namespaces
	// If not, then release the netid
	if count := vmap.getVNIDCount(netid); count == 0 {
		if err := vmap.netIDManager.Release(netid); err != nil {
			return fmt.Errorf("error while releasing netid %d for namespace %q, %v", netid, nsName, err)
		}
		klog.Infof("Released netid %d for namespace %q", netid, nsName)
	} else {
		klog.V(5).Infof("netid %d for namespace %q is still in use", netid, nsName)
	}
	return nil
}

func (vmap *masterVNIDMap) updateNetID(nsName string, action osdnapihelpers.PodNetworkAction, args string) (uint32, error) {
	var netid uint32
	allocated := false

	// Check if the given namespace exists or not
	oldnetid, found := vmap.getVNID(nsName)
	if !found {
		return 0, fmt.Errorf("netid not found for namespace %q", nsName)
	}

	// Determine new network ID
	switch action {
	case osdnapihelpers.GlobalPodNetwork:
		netid = common.GlobalVNID
	case osdnapihelpers.JoinPodNetwork:
		joinNsName := args
		var found bool
		if netid, found = vmap.getVNID(joinNsName); !found {
			return 0, fmt.Errorf("netid not found for namespace %q", joinNsName)
		}
	case osdnapihelpers.IsolatePodNetwork:
		if nsName == corev1.NamespaceDefault {
			return 0, fmt.Errorf("network isolation for namespace %q is not allowed", nsName)
		}
		// Check if the given namespace is already isolated
		if count := vmap.getVNIDCount(oldnetid); count == 1 {
			return oldnetid, nil
		}

		var err error
		netid, err = vmap.netIDManager.AllocateNext()
		if err != nil {
			return 0, err
		}
		allocated = true
	default:
		return 0, fmt.Errorf("invalid pod network action: %v", action)
	}

	// Release old network ID
	if err := vmap.releaseNetID(nsName); err != nil {
		if allocated {
			vmap.netIDManager.Release(netid)
		}
		return 0, err
	}

	// Set new network ID
	vmap.setVNID(nsName, netid)
	klog.Infof("Updated netid %d for namespace %q", netid, nsName)
	return netid, nil
}

// assignVNID, revokeVNID and updateVNID methods updates in-memory structs and persists etcd objects
func (vmap *masterVNIDMap) assignVNID(osdnClient osdnclient.Interface, nsName string) error {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	netid, exists, err := vmap.allocateNetID(nsName)
	if err != nil {
		return err
	}

	if !exists {
		// Create NetNamespace Object and update vnid map
		netns := &osdnv1.NetNamespace{
			TypeMeta:   metav1.TypeMeta{Kind: "NetNamespace"},
			ObjectMeta: metav1.ObjectMeta{Name: nsName},
			NetName:    nsName,
			NetID:      netid,
		}
		if _, err := osdnClient.NetworkV1().NetNamespaces().Create(context.TODO(), netns, metav1.CreateOptions{}); err != nil {
			if er := vmap.releaseNetID(nsName); er != nil {
				klog.Errorf("Could not release NetID: %v", er)
			}
			return err
		}
	}
	return nil
}

func (vmap *masterVNIDMap) revokeVNID(osdnClient osdnclient.Interface, nsName string) error {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	// Delete NetNamespace object
	if err := osdnClient.NetworkV1().NetNamespaces().Delete(context.TODO(), nsName, metav1.DeleteOptions{}); err != nil {
		// If the netnamespace is already deleted, emit a warning and move forward
		if kapierrors.IsNotFound(err) {
			klog.Warningf("Could not find the netnamespace %s: Must be already deleted.", nsName)
		} else {
			return err
		}
	}

	if err := vmap.releaseNetID(nsName); err != nil {
		return err
	}
	return nil
}

func (vmap *masterVNIDMap) updateVNID(osdnClient osdnclient.Interface, origNetns *osdnv1.NetNamespace) error {
	// Informer cache should not be mutated, so get a copy of the object
	netns := origNetns.DeepCopy()

	action, args, err := osdnapihelpers.GetChangePodNetworkAnnotation(netns)
	if err == osdnapihelpers.ErrorPodNetworkAnnotationNotFound {
		// Nothing to update
		return nil
	} else if !vmap.allowRenumbering {
		osdnapihelpers.DeleteChangePodNetworkAnnotation(netns)
		_, _ = osdnClient.NetworkV1().NetNamespaces().Update(context.TODO(), netns, metav1.UpdateOptions{})
		return fmt.Errorf("network plugin does not allow NetNamespace renumbering")
	}

	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	netid, err := vmap.updateNetID(netns.NetName, action, args)
	if err != nil {
		return err
	}
	netns.NetID = netid
	osdnapihelpers.DeleteChangePodNetworkAnnotation(netns)

	if _, err := osdnClient.NetworkV1().NetNamespaces().Update(context.TODO(), netns, metav1.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

//--------------------- Master methods ----------------------

func (master *OsdnMaster) startVNIDMaster() error {
	if err := master.initNetIDAllocator(); err != nil {
		return err
	}

	master.watchNamespaces()
	master.watchNetNamespaces()

	return nil
}

func (master *OsdnMaster) initNetIDAllocator() error {
	netnsList, err := master.osdnClient.NetworkV1().NetNamespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, netns := range netnsList.Items {
		if err := master.vnids.markAllocatedNetID(netns.NetID); err != nil {
			klog.Errorf("Error marking allocated VNID: %v", err)
		}
		master.vnids.setVNID(netns.Name, netns.NetID)
	}

	return nil
}

func (master *OsdnMaster) watchNamespaces() {
	funcs := common.InformerFuncs(&corev1.Namespace{}, master.handleAddOrUpdateNamespace, master.handleDeleteNamespace)
	master.namespaceInformer.Informer().AddEventHandler(funcs)
}

func (master *OsdnMaster) handleAddOrUpdateNamespace(obj, _ interface{}, eventType watch.EventType) {
	ns := obj.(*corev1.Namespace)
	klog.V(5).Infof("Watch %s event for Namespace %q", eventType, ns.Name)

	if err := master.vnids.assignVNID(master.osdnClient, ns.Name); err != nil {
		klog.Errorf("Error assigning netid: %v", err)
	}
}

func (master *OsdnMaster) handleDeleteNamespace(obj interface{}) {
	ns := obj.(*corev1.Namespace)
	klog.V(5).Infof("Watch %s event for Namespace %q", watch.Deleted, ns.Name)
	if err := master.vnids.revokeVNID(master.osdnClient, ns.Name); err != nil {
		klog.Errorf("Error revoking netid: %v", err)
	}
}

func (master *OsdnMaster) watchNetNamespaces() {
	funcs := common.InformerFuncs(&osdnv1.NetNamespace{}, master.handleAddOrUpdateNetNamespace, nil)
	master.netNamespaceInformer.Informer().AddEventHandler(funcs)
}

func (master *OsdnMaster) handleAddOrUpdateNetNamespace(obj, _ interface{}, eventType watch.EventType) {
	netns := obj.(*osdnv1.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", eventType, netns.Name)

	if err := master.vnids.updateVNID(master.osdnClient, netns); err != nil {
		klog.Errorf("Error updating netid: %v", err)
	}
}
