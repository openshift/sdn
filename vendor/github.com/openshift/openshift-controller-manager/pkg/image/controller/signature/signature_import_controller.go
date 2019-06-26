package signature

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/kubernetes/pkg/controller"

	imagev1 "github.com/openshift/api/image/v1"
	imagev1client "github.com/openshift/client-go/image/clientset/versioned"
	imagev1informer "github.com/openshift/client-go/image/informers/externalversions/image/v1"
	imagev1lister "github.com/openshift/client-go/image/listers/image/v1"
)

type SignatureDownloader interface {
	DownloadImageSignatures(*imagev1.Image) ([]imagev1.ImageSignature, error)
}

type SignatureImportController struct {
	imageClient imagev1client.Interface
	imageLister imagev1lister.ImageLister

	imageHasSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	// signatureImportLimit limits amount of signatures we will import.
	// By default this is set to 3 signatures.
	signatureImportLimit int

	fetcher SignatureDownloader
}

func NewSignatureImportController(ctx context.Context, imageClient imagev1client.Interface, imageInformer imagev1informer.ImageInformer, resyncInterval, fetchTimeout time.Duration, limit int) *SignatureImportController {
	controller := &SignatureImportController{
		queue:                workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		imageClient:          imageClient,
		imageLister:          imageInformer.Lister(),
		imageHasSynced:       imageInformer.Informer().HasSynced,
		signatureImportLimit: limit,
	}
	controller.fetcher = NewContainerImageSignatureDownloader(ctx, fetchTimeout)

	imageInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			image := obj.(*imagev1.Image)
			klog.V(4).Infof("Adding image %s", image.Name)
			controller.enqueueImage(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			image := cur.(*imagev1.Image)
			klog.V(4).Infof("Updating image %s", image.Name)
			controller.enqueueImage(cur)
		},
	}, resyncInterval)

	return controller
}

func (s *SignatureImportController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer s.queue.ShutDown()

	if !cache.WaitForCacheSync(stopCh, s.imageHasSynced) {
		return
	}

	klog.V(5).Infof("Starting workers")
	for i := 0; i < workers; i++ {
		go wait.Until(s.worker, time.Second, stopCh)
	}
	<-stopCh
	klog.V(1).Infof("Shutting down")

}

func (s *SignatureImportController) worker() {
	for {
		if !s.work() {
			return
		}
	}
}

// work returns true if the worker thread should continue
func (s *SignatureImportController) work() bool {
	key, quit := s.queue.Get()
	if quit {
		return false
	}
	defer s.queue.Done(key)

	err := s.syncImageSignatures(key.(string))
	if err != nil {
		if _, ok := err.(GetSignaturesError); !ok {
			utilruntime.HandleError(fmt.Errorf("error syncing image %s, it will be retried: %v", key.(string), err))
		}

		if s.queue.NumRequeues(key) < 5 {
			s.queue.AddRateLimited(key)
		}
		return true
	}

	s.queue.Forget(key)
	return true
}

func (s *SignatureImportController) enqueueImage(obj interface{}) {
	_, ok := obj.(*imagev1.Image)
	if !ok {
		return
	}
	key, err := controller.KeyFunc(obj)
	if err != nil {
		klog.Errorf("Couldn't get key for object %+v: %v", obj, err)
		return
	}
	s.queue.Add(key)
}

func (s *SignatureImportController) syncImageSignatures(key string) error {
	klog.V(4).Infof("Initiating download of signatures for %s", key)
	image, err := s.imageLister.Get(key)
	if err != nil {
		klog.V(4).Infof("Unable to get image %v: %v", key, err)
		return err
	}

	if image.Annotations[imagev1.ManagedByOpenShiftAnnotation] == "true" {
		klog.V(4).Infof("Skipping downloading signatures for image %s because it's a managed image", image.Name)
		return nil
	}

	currentSignatures, err := s.fetcher.DownloadImageSignatures(image)
	if err != nil {
		klog.V(4).Infof("Failed to fetch image %s signatures: %v", image.Name, err)
		return err
	}

	// Having no signatures means no-op (we don't remove stored signatures when
	// the sig-store no longer have them).
	if len(currentSignatures) == 0 {
		klog.V(4).Infof("No signatures downloaded for %s", image.Name)
		return nil
	}

	newImage := image.DeepCopy()
	shouldUpdate := false

	// Only add new signatures, do not override existing stored signatures as that
	// can void their verification status.
	for _, c := range currentSignatures {
		found := false
		for _, s := range newImage.Signatures {
			if s.Name == c.Name {
				found = true
				break
			}
		}
		if !found {
			newImage.Signatures = append(newImage.Signatures, c)
			shouldUpdate = true
		}
	}

	if len(newImage.Signatures) > s.signatureImportLimit {
		klog.V(2).Infof("Image %s reached signature limit (max:%d, want:%d)", newImage.Name, s.signatureImportLimit, len(newImage.Signatures))
		return nil
	}

	// Avoid unnecessary updates to images.
	if !shouldUpdate {
		return nil
	}
	klog.V(4).Infof("Image %s now has %d signatures", newImage.Name, len(newImage.Signatures))

	_, err = s.imageClient.ImageV1().Images().Update(newImage)
	return err
}
