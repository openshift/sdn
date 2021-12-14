package openshift_sdn_controller

import (
	"time"

	cloudnetworkclient "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformer "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformer "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/sdn/pkg/network/common"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const defaultInformerResyncPeriod = 10 * time.Minute

type controllerContext struct {
	kubernetesClient     kubernetes.Interface
	kubernetesInformers  informers.SharedInformerFactory
	osdnClient           osdnclient.Interface
	osdnInformers        osdninformer.SharedInformerFactory
	cloudNetworkClient   cloudnetworkclient.Interface
	cloudNetworkInformer cloudnetworkinformer.SharedInformerFactory
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

	if common.PlatformUsesCloudEgressIP(platformType) {
		cloudNetworkClient, err := cloudnetworkclient.NewForConfig(clientConfig)
		if err != nil {
			return nil, err
		}
		networkControllerContext.cloudNetworkClient = cloudNetworkClient
		networkControllerContext.cloudNetworkInformer = cloudnetworkinformer.NewSharedInformerFactory(cloudNetworkClient, defaultInformerResyncPeriod)
	}

	return networkControllerContext, nil
}

func (c *controllerContext) StartInformers() {
	c.kubernetesInformers.Start(nil)
	c.osdnInformers.Start(nil)
	if c.cloudNetworkInformer != nil {
		c.cloudNetworkInformer.Start(nil)
	}
}
