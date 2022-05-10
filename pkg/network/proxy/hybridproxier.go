package proxy

import (
	"sync"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/util/async"

	unidlingapi "github.com/openshift/api/unidling/v1alpha1"
)

// HybridizableProxy is an extra interface we layer on top of Provider
type HybridizableProxy interface {
	proxy.Provider

	SyncProxyRules()
	SetSyncRunner(b *async.BoundedFrequencyRunner)

	ReloadIPTables()
}

// hybridProxierService is our cached state for a given Service/Endpoints.
//
// A running Service can be in one of three states:
//
//   - Not Idled (known to the mainProxy but not the unidlingProxy). A Not Idled Service
//     becomes Idled when its Service gets annotated and its Endpoints is empty. (Both
//     conditions must be true.)
//
//   - Idled (known to the unidlingProxy but not the mainProxy). An Idled Service becomes
//     Unidling when either its Service annotation is removed or its Endpoints become
//     non-empty.
//
//   - Unidling (the Service and Endpoints are known to the mainProxy, and the Endpoints
//     are known to the unidling proxy). While a Service is Unidling, Endpoints events are
//     sent to both proxies (so the unidling proxy socket can redirect its connection to
//     the correct place). An Unidling Service becomes Not Idled if its Endpoints are
//     deleted, or else the next time it receives an Endpoints event more than 1 minute
//     after becoming Unidling. (Alternatively it could also become Idled again.)
type hybridProxierService struct {
	// whether the Service/Endpoints are known to us
	knownService   bool
	knownEndpoints bool

	// cached info about the Service/Endpoints
	serviceHasIdleAnnotation bool
	emptyEndpoints           *corev1.Endpoints

	// idling/unidling state
	isIdled   bool
	unidledAt *time.Time
}

const unidlingEndpointsLag = time.Minute

func (hsvc *hybridProxierService) shouldBeIdled() bool {
	return hsvc.serviceHasIdleAnnotation && hsvc.emptyEndpoints != nil
}

func (hsvc *hybridProxierService) unidlingProxyWantsEndpoints() bool {
	return hsvc.isIdled || (hsvc.unidledAt != nil && time.Since(*hsvc.unidledAt) < unidlingEndpointsLag)
}

func (hsvc *hybridProxierService) unidlingPeriodHasExpired() bool {
	return hsvc.unidledAt != nil && !hsvc.unidlingProxyWantsEndpoints()
}

// HybridProxier runs an unidling proxy and a primary proxy at the same time,
// delegating idled services to the unidling proxy and other services to the
// primary proxy.
type HybridProxier struct {
	mainProxy     HybridizableProxy
	unidlingProxy HybridizableProxy

	serviceLister corev1listers.ServiceLister
	syncRunner    *async.BoundedFrequencyRunner

	serviceLock sync.Mutex
	services    map[types.NamespacedName]*hybridProxierService
}

func NewHybridProxier(
	mainProxy HybridizableProxy,
	unidlingProxy HybridizableProxy,
	minSyncPeriod time.Duration,
	serviceLister corev1listers.ServiceLister,
) *HybridProxier {
	p := &HybridProxier{
		mainProxy:     mainProxy,
		unidlingProxy: unidlingProxy,

		serviceLister: serviceLister,

		services: make(map[types.NamespacedName]*hybridProxierService),
	}

	p.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", p.syncProxyRules, minSyncPeriod, time.Hour, 4)

	// Hackery abound: we want to make sure that changes are applied
	// to both proxies at approximately the same time. That means that we
	// need to stop the two proxy's independent loops and take them over.
	mainProxy.SetSyncRunner(p.syncRunner)
	unidlingProxy.SetSyncRunner(p.syncRunner)

	return p
}

func (proxier *HybridProxier) OnNodeAdd(node *corev1.Node) {
	proxier.mainProxy.OnNodeAdd(node)
}

func (proxier *HybridProxier) OnNodeUpdate(oldNode, node *corev1.Node) {
	proxier.mainProxy.OnNodeUpdate(oldNode, node)
}

func (proxier *HybridProxier) OnNodeDelete(node *corev1.Node) {
	proxier.mainProxy.OnNodeDelete(node)
}

func (proxier *HybridProxier) OnNodeSynced() {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

// getService locks p.serviceLock and then gets/creates the hybridProxierService for
// svcName. You must call p.releaseService(name) to unlock p.serviceLock.
func (p *HybridProxier) getService(svcName types.NamespacedName) *hybridProxierService {
	p.serviceLock.Lock()
	// caller must call p.releaseService to unlock p.serviceLock

	hsvc := p.services[svcName]
	if hsvc == nil {
		hsvc = &hybridProxierService{}
		p.services[svcName] = hsvc
	}
	return hsvc
}

// releaseService deletes the hybridProxierService for svcName if it is no longer needed,
// and unlocks p.serviceLock.
func (p *HybridProxier) releaseService(svcName types.NamespacedName) {
	defer p.serviceLock.Unlock()

	hsvc := p.services[svcName]
	if hsvc == nil {
		return
	}

	// If necessary, switch the service to the other proxy
	if hsvc.knownService && (hsvc.shouldBeIdled() != hsvc.isIdled) {
		service, err := p.serviceLister.Services(svcName.Namespace).Get(svcName.Name)
		if err != nil {
			klog.Errorf("Error while getting service %s from cache: %v", svcName, err)
			return
		}

		if hsvc.shouldBeIdled() {
			klog.Infof("switching svc %s to unidling proxy", svcName)
			p.mainProxy.OnServiceDelete(service)
			p.unidlingProxy.OnServiceAdd(service)
			if !hsvc.unidlingProxyWantsEndpoints() {
				p.unidlingProxy.(config.EndpointsHandler).OnEndpointsAdd(hsvc.emptyEndpoints)
			}
			hsvc.isIdled = true
			hsvc.unidledAt = nil
		} else {
			klog.Infof("switching svc %s to main proxy", svcName)
			p.unidlingProxy.OnServiceDelete(service)
			p.mainProxy.OnServiceAdd(service)
			hsvc.isIdled = false
			now := time.Now()
			hsvc.unidledAt = &now
		}
	}

	if !hsvc.knownService && !hsvc.knownEndpoints {
		delete(p.services, svcName)
	}
}

func serviceHasIdleAnnotation(service *corev1.Service) bool {
	_, annotationSet := service.Annotations[unidlingapi.IdledAtAnnotation]
	return annotationSet
}

func (p *HybridProxier) OnServiceAdd(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = true
	hsvc.serviceHasIdleAnnotation = serviceHasIdleAnnotation(service)

	// Services should never actually be created pre-idled. But if we do end up
	// getting an OnServiceAdd for an already-idle Service due to dropped/compressed
	// events, then releaseService() will fix this up.
	klog.V(6).Infof("add svc %s in main proxy", svcName)
	p.mainProxy.OnServiceAdd(service)
}

func (p *HybridProxier) OnServiceUpdate(oldService, service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.serviceHasIdleAnnotation = serviceHasIdleAnnotation(service)

	if hsvc.isIdled == hsvc.shouldBeIdled() {
		// Send the Update to the proxy that already knows about the service
		if hsvc.isIdled {
			klog.V(6).Infof("update svc %s in unidling proxy", svcName)
			p.unidlingProxy.OnServiceUpdate(oldService, service)
		} else {
			klog.V(6).Infof("update svc %s in main proxy", svcName)
			p.mainProxy.OnServiceUpdate(oldService, service)
		}
	}
	// otherwise, releaseService will deal with deleting the service from one proxy
	// and adding it to the other.
}

func (p *HybridProxier) OnServiceDelete(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = false
	hsvc.serviceHasIdleAnnotation = false

	if hsvc.isIdled {
		klog.V(6).Infof("del svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceDelete(service)
	} else {
		klog.V(6).Infof("del svc %s in main proxy", svcName)
		p.mainProxy.OnServiceDelete(service)
	}
}

func (p *HybridProxier) OnServiceSynced() {
	p.unidlingProxy.OnServiceSynced()
	p.mainProxy.OnServiceSynced()
}

func (p *HybridProxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	panic("not reached")
}

func (p *HybridProxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	panic("not reached")
}

func (p *HybridProxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	panic("not reached")
}

func (p *HybridProxier) OnEndpointsSynced() {
	panic("not reached")
}

func endpointSliceServiceName(slice *discoveryv1.EndpointSlice) string {
	serviceName := slice.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		klog.Warningf("EndpointSlice %s/%s has no %q label",
			slice.Namespace, slice.Name, discoveryv1.LabelServiceName)
		return slice.Name
	}
	return serviceName
}

func sliceToEndpoints(slice *discoveryv1.EndpointSlice) *corev1.Endpoints {
	if slice == nil {
		return nil
	}

	endpoints := &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: slice.ObjectMeta,
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{},
				Ports:     []corev1.EndpointPort{},
			},
		},
	}
	endpoints.Name = endpointSliceServiceName(slice)
	for _, ep := range slice.Endpoints {
		addr := corev1.EndpointAddress{
			NodeName:  ep.NodeName,
			TargetRef: ep.TargetRef,
		}
		if ep.Hostname != nil {
			addr.Hostname = *ep.Hostname
		}
		for _, ip := range ep.Addresses {
			addr.IP = ip
			endpoints.Subsets[0].Addresses = append(endpoints.Subsets[0].Addresses, addr)
		}
	}
	for _, slicePort := range slice.Ports {
		port := corev1.EndpointPort{AppProtocol: slicePort.AppProtocol}
		if slicePort.Name != nil {
			port.Name = *slicePort.Name
		}
		if slicePort.Port != nil {
			port.Port = *slicePort.Port
		}
		if slicePort.Protocol != nil {
			port.Protocol = *slicePort.Protocol
		}
		endpoints.Subsets[0].Ports = append(endpoints.Subsets[0].Ports, port)
	}

	return endpoints
}

func endpointsIfEmptySlice(slice *discoveryv1.EndpointSlice) *corev1.Endpoints {
	for _, ep := range slice.Endpoints {
		if len(ep.Addresses) > 0 {
			return nil
		}
	}
	return sliceToEndpoints(slice)
}

func (p *HybridProxier) OnEndpointSliceAdd(slice *discoveryv1.EndpointSlice) {
	svcName := types.NamespacedName{Namespace: slice.Namespace, Name: endpointSliceServiceName(slice)}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints = true
	hsvc.emptyEndpoints = endpointsIfEmptySlice(slice)

	klog.V(6).Infof("hybrid proxy: add slice %s", svcName)
	p.mainProxy.OnEndpointSliceAdd(slice)
	if hsvc.unidlingProxyWantsEndpoints() {
		p.unidlingProxy.(config.EndpointsHandler).OnEndpointsAdd(sliceToEndpoints(slice))
	}
}

func (p *HybridProxier) OnEndpointSliceUpdate(oldSlice, slice *discoveryv1.EndpointSlice) {
	svcName := types.NamespacedName{Namespace: slice.Namespace, Name: endpointSliceServiceName(slice)}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.emptyEndpoints = endpointsIfEmptySlice(slice)

	klog.V(6).Infof("hybrid proxy: update slice %s", svcName)
	p.mainProxy.OnEndpointSliceUpdate(oldSlice, slice)
	if hsvc.unidlingProxyWantsEndpoints() {
		p.unidlingProxy.(config.EndpointsHandler).OnEndpointsUpdate(sliceToEndpoints(oldSlice), sliceToEndpoints(slice))
	} else if hsvc.unidlingPeriodHasExpired() {
		p.unidlingProxy.(config.EndpointsHandler).OnEndpointsDelete(sliceToEndpoints(oldSlice))
		hsvc.unidledAt = nil
	}
}

func (p *HybridProxier) OnEndpointSliceDelete(slice *discoveryv1.EndpointSlice) {
	svcName := types.NamespacedName{Namespace: slice.Namespace, Name: endpointSliceServiceName(slice)}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints = false
	hsvc.emptyEndpoints = nil

	klog.V(6).Infof("hybrid proxy: del slice %s", svcName)
	p.mainProxy.OnEndpointSliceDelete(slice)
	if hsvc.unidlingProxyWantsEndpoints() {
		p.unidlingProxy.(config.EndpointsHandler).OnEndpointsDelete(sliceToEndpoints(slice))
		hsvc.unidledAt = nil
	}
}

func (p *HybridProxier) OnEndpointSlicesSynced() {
	klog.V(6).Infof("hybrid proxy: endpointslices synced")
	p.unidlingProxy.(config.EndpointsHandler).OnEndpointsSynced()
	p.mainProxy.OnEndpointSlicesSynced()
}

// Sync is called to synchronize the proxier state to iptables
// this doesn't take immediate effect - rather, it requests that the
// BoundedFrequencyRunner call syncProxyRules()
func (p *HybridProxier) Sync() {
	p.syncRunner.Run()
}

// syncProxyRules actually applies the proxy rules to the node.
// It is called by our SyncRunner.
// We do this so that we can guarantee that changes are applied to both
// proxies, especially when unidling a newly-awoken service.
func (p *HybridProxier) syncProxyRules() {
	klog.V(3).Infof("syncProxyRules start")

	p.mainProxy.SyncProxyRules()
	p.unidlingProxy.SyncProxyRules()

	klog.V(3).Infof("syncProxyRules finished")
}

// SyncLoop runs periodic work.  This is expected to run as a goroutine or as the main loop of the app.  It does not return.
func (p *HybridProxier) SyncLoop() {
	// All this does is start our syncRunner, since we pass it *back* in to
	// the mainProxy
	p.mainProxy.SyncLoop()
}

func (p *HybridProxier) SyncProxyRules() {
}

func (p *HybridProxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
}

func (p *HybridProxier) ReloadIPTables() {
	p.mainProxy.ReloadIPTables()
	p.unidlingProxy.ReloadIPTables()
}
