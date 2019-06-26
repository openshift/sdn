package controller

import (
	"errors"
	"fmt"
	"time"

	"k8s.io/klog"

	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	kcontroller "k8s.io/kubernetes/pkg/controller"

	imagev1 "github.com/openshift/api/image/v1"
	imagev1typedclient "github.com/openshift/client-go/image/clientset/versioned/typed/image/v1"
	imagev1lister "github.com/openshift/client-go/image/listers/image/v1"
	"github.com/openshift/library-go/pkg/image/imageutil"
	metrics "github.com/openshift/openshift-controller-manager/pkg/image/metrics/prometheus"
)

var ErrNotImportable = errors.New("requested image cannot be imported")

// Notifier provides information about when the controller makes a decision
type Notifier interface {
	// Importing is invoked when the controller is going to import an image stream
	Importing(stream *imagev1.ImageStream)
}

type ImageStreamController struct {
	// image stream client
	client imagev1typedclient.ImageV1Interface

	// queue contains replication controllers that need to be synced.
	queue workqueue.RateLimitingInterface

	syncHandler func(isKey string) error

	// lister can list/get image streams from a shared informer's cache
	lister imagev1lister.ImageStreamLister
	// listerSynced makes sure the is store is synced before reconciling streams
	listerSynced cache.InformerSynced

	// notifier informs other controllers that an import is being performed
	notifier Notifier

	// importCounter counts successful and failed imports for metric collection
	importCounter *ImportMetricCounter
}

func (c *ImageStreamController) SetNotifier(n Notifier) {
	c.notifier = n
}

// Run begins watching and syncing.
func (c *ImageStreamController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting image stream controller")

	// Wait for the stream store to sync before starting any work in this controller.
	if !cache.WaitForCacheSync(stopCh, c.listerSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	metrics.InitializeImportCollector(false, c.importCounter.Collect)

	<-stopCh
	klog.Infof("Shutting down image stream controller")
}

func (c *ImageStreamController) addImageStream(obj interface{}) {
	if stream, ok := obj.(*imagev1.ImageStream); ok {
		c.enqueueImageStream(stream)
	}
}

func (c *ImageStreamController) updateImageStream(old, cur interface{}) {
	curStream, ok := cur.(*imagev1.ImageStream)
	if !ok {
		return
	}
	oldStream, ok := old.(*imagev1.ImageStream)
	if !ok {
		return
	}
	// we only compare resource version, since deeper inspection if a stream
	// needs to be re-imported happens in syncImageStream
	//
	// FIXME: this will only be ever true on cache resync
	if curStream.ResourceVersion == oldStream.ResourceVersion {
		return
	}
	c.enqueueImageStream(curStream)
}

func (c *ImageStreamController) enqueueImageStream(stream *imagev1.ImageStream) {
	key, err := kcontroller.KeyFunc(stream)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for image stream %#v: %v", stream, err))
		return
	}
	c.queue.Add(key)
}

func (c *ImageStreamController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ImageStreamController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncHandler(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Error syncing image stream %q: %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}

func (c *ImageStreamController) syncImageStream(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing image stream %q (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	stream, err := c.lister.ImageStreams(namespace).Get(name)
	if apierrs.IsNotFound(err) {
		klog.V(4).Infof("ImageStream has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	klog.V(3).Infof("Queued import of stream %s/%s...", stream.Namespace, stream.Name)
	result, err := handleImageStream(stream, c.client.RESTClient(), c.notifier)
	c.importCounter.Increment(result, err)
	return err
}

// tagImportable is true if the given TagReference is importable by this controller
func tagImportable(tagRef imagev1.TagReference) bool {
	return !(tagRef.From == nil || tagRef.From.Kind != "DockerImage" || tagRef.Reference)
}

// tagNeedsImport is true if the observed tag generation for this tag is older than the
// specified tag generation (if no tag generation is specified, the controller does not
// need to import this tag).
func tagNeedsImport(stream *imagev1.ImageStream, tagRef imagev1.TagReference, importWhenGenerationNil bool) bool {
	if !tagImportable(tagRef) {
		return false
	}
	if tagRef.Generation == nil {
		return importWhenGenerationNil
	}
	return *tagRef.Generation > latestObservedTagGeneration(stream, tagRef.Name)
}

// latestObservedTagGeneration returns the generation value for the given tag that has been observed by the controller
// monitoring the image stream. If the tag has not been observed, the generation is zero.
func latestObservedTagGeneration(stream *imagev1.ImageStream, tag string) int64 {
	tagEvents, ok := imageutil.StatusHasTag(stream, tag)
	if !ok {
		return 0
	}

	// find the most recent generation
	lastGen := int64(0)
	if items := tagEvents.Items; len(items) > 0 {
		tagEvent := items[0]
		if tagEvent.Generation > lastGen {
			lastGen = tagEvent.Generation
		}
	}
	for _, condition := range tagEvents.Conditions {
		if condition.Type != imagev1.ImportSuccess {
			continue
		}
		if condition.Generation > lastGen {
			lastGen = condition.Generation
		}
		break
	}
	return lastGen
}

// needsImport returns true if the provided image stream should have tags imported. Partial is returned
// as true if the spec.dockerImageRepository does not need to be refreshed (if only tags have to be imported).
func needsImport(stream *imagev1.ImageStream) (ok bool, partial bool) {
	if stream.Annotations == nil || len(stream.Annotations[imagev1.DockerImageRepositoryCheckAnnotation]) == 0 {
		if len(stream.Spec.DockerImageRepository) > 0 {
			return true, false
		}
		// for backwards compatibility, if any of our tags are importable, trigger a partial import when the
		// annotation is cleared.
		for _, tagRef := range stream.Spec.Tags {
			if tagImportable(tagRef) {
				return true, true
			}
		}
	}
	// find any tags with a newer generation than their status
	for _, tagRef := range stream.Spec.Tags {
		if tagNeedsImport(stream, tagRef, false) {
			return true, true
		}
	}
	return false, false
}

// Processes the given image stream, looking for streams that have DockerImageRepository
// set but have not yet been marked as "ready". If transient errors occur, err is returned but
// the image stream is not modified (so it will be tried again later). If a permanent
// failure occurs the image is marked with an annotation and conditions are set on the status
// tags. The tags of the original spec image are left as is (those are updated through status).
//
// There are 3 scenarios:
//
// 1. spec.DockerImageRepository defined without any tags results in all tags being imported
//    from upstream image repository
//
// 2. spec.DockerImageRepository + tags defined - import all tags from upstream image repository,
//    and all the specified which (if name matches) will overwrite the default ones.
//    Additionally:
//    for kind == DockerImage import or reference underlying image, exact tag (not provided means latest),
//    for kind != DockerImage reference tag from the same or other ImageStream
//
// 3. spec.DockerImageRepository not defined - import tags per each definition.
//
// Notifier, if passed, will be invoked if the stream is going to be imported.
func handleImageStream(
	stream *imagev1.ImageStream,
	client rest.Interface,
	notifier Notifier,
) (*imagev1.ImageStreamImport, error) {
	ok, partial := needsImport(stream)
	if !ok {
		return nil, nil
	}
	klog.V(3).Infof("Importing stream %s/%s partial=%t...", stream.Namespace, stream.Name, partial)

	if notifier != nil {
		notifier.Importing(stream)
	}

	isi := &imagev1.ImageStreamImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:            stream.Name,
			Namespace:       stream.Namespace,
			ResourceVersion: stream.ResourceVersion,
			UID:             stream.UID,
		},
		Spec: imagev1.ImageStreamImportSpec{Import: true},
	}
	for _, tagRef := range stream.Spec.Tags {
		if tagImportable(tagRef) &&
			(tagNeedsImport(stream, tagRef, true) || !partial) {
			isi.Spec.Images = append(isi.Spec.Images, imagev1.ImageImportSpec{
				From:            corev1.ObjectReference{Kind: "DockerImage", Name: tagRef.From.Name},
				To:              &corev1.LocalObjectReference{Name: tagRef.Name},
				ImportPolicy:    tagRef.ImportPolicy,
				ReferencePolicy: tagRef.ReferencePolicy,
			})
		}
	}
	if repo := stream.Spec.DockerImageRepository; !partial && len(repo) > 0 {
		insecure := stream.Annotations[imagev1.InsecureRepositoryAnnotation] == "true"
		isi.Spec.Repository = &imagev1.RepositoryImportSpec{
			From:         corev1.ObjectReference{Kind: "DockerImage", Name: repo},
			ImportPolicy: imagev1.TagImportPolicy{Insecure: insecure},
		}
	}
	if isi.Spec.Repository == nil && len(isi.Spec.Images) == 0 {
		klog.V(4).Infof("Did not find any tags or repository needing import")
		return nil, nil
	}
	// use RESTClient directly here to be able to extend request timeout
	result := &imagev1.ImageStreamImport{}
	err := client.Post().
		Namespace(stream.Namespace).
		Resource(imagev1.Resource("imagestreamimports").Resource).
		Body(isi).
		// this instructs the api server to allow our request to take up to an hour - chosen as a high boundary
		Timeout(time.Hour).
		Do().
		Into(result)
	if err != nil {
		if apierrs.IsNotFound(err) && isStatusErrorKind(err, "imageStream") {
			return result, ErrNotImportable
		}
		klog.V(4).Infof("Import stream %s/%s partial=%t error: %v", stream.Namespace, stream.Name, partial, err)
		return result, err
	}

	klog.V(5).Infof("Import stream %s/%s partial=%t import: %#v", stream.Namespace, stream.Name, partial, result.Status.Import)
	return result, nil
}

// isStatusErrorKind returns true if this error describes the provided kind.
func isStatusErrorKind(err error, kind string) bool {
	if s, ok := err.(apierrs.APIStatus); ok {
		if details := s.Status().Details; details != nil {
			return kind == details.Kind
		}
	}
	return false
}
