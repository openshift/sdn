package openshift_sdn_controller

import (
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	networkclient "github.com/openshift/client-go/network/clientset/versioned"
	networkinformer "github.com/openshift/client-go/network/informers/externalversions"
)

const defaultInformerResyncPeriod = 10 * time.Minute

type controllerContext struct {
	kubernetesClient    kubernetes.Interface
	kubernetesInformers informers.SharedInformerFactory
	networkClient       networkclient.Interface
	networkInformers    networkinformer.SharedInformerFactory
}

func newControllerContext(clientConfig *rest.Config) (*controllerContext, error) {
	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	networkClient, err := networkclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	networkControllerContext := &controllerContext{
		kubernetesClient:    kubeClient,
		kubernetesInformers: informers.NewSharedInformerFactory(kubeClient, defaultInformerResyncPeriod),
		networkClient:       networkClient,
		networkInformers:    networkinformer.NewSharedInformerFactory(networkClient, defaultInformerResyncPeriod),
	}

	return networkControllerContext, nil
}

func (c *controllerContext) StartInformers() {
	c.kubernetesInformers.Start(nil)
	c.networkInformers.Start(nil)
}
