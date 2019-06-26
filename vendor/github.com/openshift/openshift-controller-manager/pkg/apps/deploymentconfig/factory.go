package deploymentconfig

import (
	"fmt"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
	kclientset "k8s.io/client-go/kubernetes"
	kv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	kcontroller "k8s.io/kubernetes/pkg/controller"

	appsv1 "github.com/openshift/api/apps/v1"
	appsv1client "github.com/openshift/client-go/apps/clientset/versioned"
	appsv1informer "github.com/openshift/client-go/apps/informers/externalversions/apps/v1"
	metrics "github.com/openshift/openshift-controller-manager/pkg/apps/metrics/prometheus"
)

// NewDeploymentConfigController creates a new DeploymentConfigController.
func NewDeploymentConfigController(
	dcInformer appsv1informer.DeploymentConfigInformer,
	rcInformer kcoreinformers.ReplicationControllerInformer,
	appsClientset appsv1client.Interface,
	kubeClientset kclientset.Interface,
) *DeploymentConfigController {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&kv1core.EventSinkImpl{Interface: kubeClientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(legacyscheme.Scheme, v1.EventSource{Component: "deploymentconfig-controller"})

	c := &DeploymentConfigController{
		appsClient: appsClientset.AppsV1(),
		kubeClient: kubeClientset.CoreV1(),

		queue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),

		rcLister:       rcInformer.Lister(),
		rcListerSynced: rcInformer.Informer().HasSynced,
		rcControl: RealRCControl{
			KubeClient: kubeClientset,
			Recorder:   recorder,
		},

		recorder: recorder,
	}

	c.dcLister = dcInformer.Lister()
	dcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addDeploymentConfig,
		UpdateFunc: c.updateDeploymentConfig,
		DeleteFunc: c.deleteDeploymentConfig,
	})
	c.dcStoreSynced = dcInformer.Informer().HasSynced
	c.dcIndex = dcInformer.Informer().GetIndexer()

	rcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: c.updateReplicationController,
		DeleteFunc: c.deleteReplicationController,
	})

	return c
}

// Run begins watching and syncing.
func (c *DeploymentConfigController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting deploymentconfig controller")

	// Wait for the rc and dc stores to sync before starting any work in this controller.
	if !cache.WaitForCacheSync(stopCh, c.dcStoreSynced, c.rcListerSynced) {
		return
	}

	klog.Info("deploymentconfig controller caches are synced. Starting workers.")

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	metrics.InitializeMetricsCollector(c.rcLister)

	<-stopCh

	klog.Infof("Shutting down deploymentconfig controller")
}

func (c *DeploymentConfigController) addDeploymentConfig(obj interface{}) {
	dc := obj.(*appsv1.DeploymentConfig)
	klog.V(4).Infof("Adding deployment config %s/%s", dc.Namespace, dc.Name)
	c.enqueueDeploymentConfig(dc)
}

func (c *DeploymentConfigController) updateDeploymentConfig(old, cur interface{}) {
	newDc := cur.(*appsv1.DeploymentConfig)
	oldDc := old.(*appsv1.DeploymentConfig)

	klog.V(4).Infof("Updating deployment config %s/%s", oldDc.Namespace, oldDc.Name)
	c.enqueueDeploymentConfig(newDc)
}

func (c *DeploymentConfigController) deleteDeploymentConfig(obj interface{}) {
	dc, ok := obj.(*appsv1.DeploymentConfig)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %+v", obj))
			return
		}
		dc, ok = tombstone.Obj.(*appsv1.DeploymentConfig)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a deployment config: %+v", obj))
			return
		}
	}
	klog.V(4).Infof("Deleting deployment config %s/%s", dc.Namespace, dc.Name)
	c.enqueueDeploymentConfig(dc)
}

func (c *DeploymentConfigController) getConfigForController(rc *v1.ReplicationController) (*appsv1.DeploymentConfig, error) {
	dcName := rc.Annotations[appsv1.DeploymentConfigAnnotation]
	obj, exists, err := c.dcIndex.GetByKey(rc.Namespace + "/" + dcName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(schema.GroupResource{Group: appsv1.GroupName, Resource: "deploymentconfig"}, dcName)
	}
	return obj.(*appsv1.DeploymentConfig), nil
}

// updateReplicationController figures out which deploymentconfig is managing this replication
// controller and requeues the deployment config.
func (c *DeploymentConfigController) updateReplicationController(old, cur interface{}) {
	curRC := cur.(*v1.ReplicationController)
	oldRC := old.(*v1.ReplicationController)

	// We can safely ignore periodic re-lists on RCs as we react to periodic re-lists of DCs
	if curRC.ResourceVersion == oldRC.ResourceVersion {
		return
	}

	if dc, err := c.getConfigForController(curRC); err == nil && dc != nil {
		c.enqueueDeploymentConfig(dc)
	}
}

// deleteReplicationController enqueues the deployment that manages a replicationcontroller when
// the replicationcontroller is deleted. obj could be an *v1.ReplicationController, or
// a DeletionFinalStateUnknown marker item.
func (c *DeploymentConfigController) deleteReplicationController(obj interface{}) {
	rc, ok := obj.(*v1.ReplicationController)

	// When a delete is dropped, the relist will notice a pod in the store not
	// in the list, leading to the insertion of a tombstone object which contains
	// the deleted key/value.
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		rc, ok = tombstone.Obj.(*v1.ReplicationController)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a replication controller %#v", obj))
			return
		}
	}
	if dc, err := c.getConfigForController(rc); err == nil && dc != nil {
		c.enqueueDeploymentConfig(dc)
	}
}

func (c *DeploymentConfigController) enqueueDeploymentConfig(dc *appsv1.DeploymentConfig) {
	key, err := kcontroller.KeyFunc(dc)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", dc, err))
		return
	}
	c.queue.Add(key)
}

func (c *DeploymentConfigController) worker() {
	for {
		if quit := c.work(); quit {
			return
		}
	}
}

func (c *DeploymentConfigController) work() bool {
	key, quit := c.queue.Get()
	if quit {
		return true
	}
	defer c.queue.Done(key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key.(string))
	if err != nil {
		utilruntime.HandleError(err)
		return false
	}
	dc, err := c.dcLister.DeploymentConfigs(namespace).Get(name)
	if errors.IsNotFound(err) {
		return false
	}
	if err != nil {
		utilruntime.HandleError(err)
		return false
	}

	err = c.Handle(dc)
	c.handleErr(err, key)

	return false
}
