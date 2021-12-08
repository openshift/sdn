package openshift_sdn_controller

import (
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformer "github.com/openshift/client-go/network/informers/externalversions"
)

const defaultInformerResyncPeriod = 10 * time.Minute

type controllerContext struct {
	kubernetesClient    kubernetes.Interface
	kubernetesInformers informers.SharedInformerFactory
	osdnClient          osdnclient.Interface
	osdnInformers       osdninformer.SharedInformerFactory
}

func newControllerContext(platformType string, clientConfig *rest.Config) (*controllerContext, error) {
	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	osdnClient, err := osdnclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	networkControllerContext := &controllerContext{
		kubernetesClient:    kubeClient,
		kubernetesInformers: informers.NewSharedInformerFactory(kubeClient, defaultInformerResyncPeriod),
		osdnClient:          osdnClient,
		osdnInformers:       osdninformer.NewSharedInformerFactory(osdnClient, defaultInformerResyncPeriod),
	}

	return networkControllerContext, nil
}

func (c *controllerContext) StartInformers() {
	c.kubernetesInformers.Start(nil)
	c.osdnInformers.Start(nil)
}
