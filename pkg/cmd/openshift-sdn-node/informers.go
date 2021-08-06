package openshift_sdn_node

import (
	"net"
	"net/http"
	"time"

	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	kinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/proxy/apis"
)

var defaultInformerResyncPeriod = 30 * time.Minute

// informers is a small bag of data that holds our informers
type informers struct {
	kubeClient kubernetes.Interface
	osdnClient osdnclient.Interface

	kubeInformers kinformers.SharedInformerFactory
	osdnInformers osdninformers.SharedInformerFactory
}

// buildInformers creates all the informer factories.
func (sdn *openShiftSDN) buildInformers() error {
	kubeConfig, err := getInClusterConfig()
	if err != nil {
		return err
	}

	protoKubeConfig := rest.CopyConfig(kubeConfig)
	protoKubeConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	protoKubeConfig.ContentType = "application/vnd.kubernetes.protobuf"

	kubeClient, err := kubernetes.NewForConfig(protoKubeConfig)
	if err != nil {
		return err
	}
	osdnClient, err := osdnclient.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}
	noProxyName, err := labels.NewRequirement(apis.LabelServiceProxyName, selection.DoesNotExist, nil)
	if err != nil {
		return err
	}
	noHeadlessEndpoints, err := labels.NewRequirement(corev1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		return err
	}
	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

	kubeInformers := kinformers.NewSharedInformerFactoryWithOptions(kubeClient, sdn.proxyConfig.IPTables.SyncPeriod.Duration,
		kinformers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = labelSelector.String()
		}))

	osdnInformers := osdninformers.NewSharedInformerFactory(osdnClient, defaultInformerResyncPeriod)

	sdn.informers = &informers{
		kubeClient: kubeClient,
		osdnClient: osdnClient,

		kubeInformers: kubeInformers,
		osdnInformers: osdnInformers,
	}
	return nil
}

// start starts the informers.
func (i *informers) start(stopCh <-chan struct{}) {
	i.kubeInformers.Start(stopCh)
	i.osdnInformers.Start(stopCh)
}

// getInClusterConfig loads in-cluster config, then applies default overrides.
func getInClusterConfig() (*rest.Config, error) {
	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	applyClientConnectionOverrides(clientConfig)
	clientConfig.WrapTransport = defaultClientTransport

	return clientConfig, nil
}

// defaultClientTransport sets defaults for a client Transport that are suitable
// for use by infrastructure components.
func defaultClientTransport(rt http.RoundTripper) http.RoundTripper {
	transport, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}

	// TODO: this should be configured by the caller, not in this method.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.Dial = dialer.Dial
	// Hold open more internal idle connections
	// TODO: this should be configured by the caller, not in this method.
	transport.MaxIdleConnsPerHost = 100
	return transport
}

// applyClientConnectionOverrides updates a kubeConfig with default overrides
func applyClientConnectionOverrides(kubeConfig *rest.Config) {
	kubeConfig.QPS = 10.0
	kubeConfig.Burst = 20
}
