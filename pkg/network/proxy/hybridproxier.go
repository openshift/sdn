package proxy

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/util/async"

	unidlingapi "github.com/openshift/api/unidling/v1alpha1"
)

// HybridizableProxy is an extra interface we layer on top of Provider
type HybridizableProxy interface {
	proxy.Provider

	SyncProxyRules()
	SetSyncRunner(b *async.BoundedFrequencyRunner)
}

// hybridProxierService is our cached state for a given Service/Endpoints
type hybridProxierService struct {
	knownService   bool
	knownEndpoints bool

	usingUserspace      bool
	switchedToUserspace bool
}

// HybridProxier runs an unidling proxy and a primary proxy at the same time,
// delegating idled services to the unidling proxy and other services to the
// primary proxy.
type HybridProxier struct {
	proxyconfig.NoopEndpointSliceHandler

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
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

func (proxier *HybridProxier) OnNodeUpdate(oldNode, node *corev1.Node) {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

func (proxier *HybridProxier) OnNodeDelete(node *corev1.Node) {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
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

	if !hsvc.knownService && !hsvc.knownEndpoints {
		delete(p.services, svcName)
	}
}

func (p *HybridProxier) OnServiceAdd(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = true

	// since this is an Add, we know the service isn't already in another
	// proxy, so don't bother trying to remove like on an update
	if hsvc.usingUserspace {
		klog.V(6).Infof("add svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceAdd(service)
	} else {
		klog.V(6).Infof("add svc %s in main proxy", svcName)
		p.mainProxy.OnServiceAdd(service)
	}
}

func (p *HybridProxier) OnServiceUpdate(oldService, service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	// NB: usingUserspace can only change in the endpoints handler,
	// so that should deal with calling OnServiceDelete on switches
	if hsvc.usingUserspace {
		klog.V(6).Infof("update svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceUpdate(oldService, service)
	} else {
		klog.V(6).Infof("update svc %s in main proxy", svcName)
		p.mainProxy.OnServiceUpdate(oldService, service)
	}
}

func (p *HybridProxier) OnServiceDelete(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = false

	if hsvc.usingUserspace {
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
	klog.V(6).Infof("services synced")
}

// shouldEndpointsUseUserspace checks to see if the given endpoints have the correct
// annotations and size to use the unidling proxy.
func (p *HybridProxier) shouldEndpointsUseUserspace(endpoints *corev1.Endpoints) bool {
	hasEndpoints := false
	for _, subset := range endpoints.Subsets {
		if len(subset.Addresses) > 0 {
			hasEndpoints = true
			break
		}
	}

	if !hasEndpoints {
		if _, ok := endpoints.Annotations[unidlingapi.IdledAtAnnotation]; ok {
			return true
		}
	}

	return false
}

// switchService moves a service between the unidling and main proxies.
func (p *HybridProxier) switchService(svcName types.NamespacedName, hsvc *hybridProxierService) {
	// We shouldn't call switchService more than once (per switch), but there
	// are some logic bugs where this happens
	// So, cache the real state and don't allow this to be called twice.
	// This assumes the caller already holds serviceLock
	if hsvc.usingUserspace == hsvc.switchedToUserspace {
		klog.V(6).Infof("ignoring duplicate switchService(%s)", svcName)
		return
	}

	svc, err := p.serviceLister.Services(svcName.Namespace).Get(svcName.Name)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Error while getting service %s from cache: %v", svcName, err))
		return
	}

	if hsvc.usingUserspace {
		klog.Infof("switching svc %s to unidling proxy", svcName)
		p.unidlingProxy.OnServiceAdd(svc)
		p.mainProxy.OnServiceDelete(svc)
	} else {
		klog.Infof("switching svc %s to main proxy", svcName)
		p.mainProxy.OnServiceAdd(svc)
		p.unidlingProxy.OnServiceDelete(svc)
	}

	hsvc.switchedToUserspace = hsvc.usingUserspace
}

func (p *HybridProxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints = true
	wasUsingUserspace := hsvc.usingUserspace
	hsvc.usingUserspace = p.shouldEndpointsUseUserspace(endpoints)

	klog.V(6).Infof("add ep %s", svcName)
	p.unidlingProxy.OnEndpointsAdd(endpoints)
	p.mainProxy.OnEndpointsAdd(endpoints)

	// a service could appear before endpoints, so we have to treat this as a potential
	// state modification for services, and not just an addition (since we could flip proxies).
	if hsvc.knownService && wasUsingUserspace != hsvc.usingUserspace {
		p.switchService(svcName, hsvc)
	}
}

func (p *HybridProxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	wasUsingUserspace := hsvc.usingUserspace
	hsvc.usingUserspace = p.shouldEndpointsUseUserspace(endpoints)

	klog.V(6).Infof("update ep %s", svcName)
	p.unidlingProxy.OnEndpointsUpdate(oldEndpoints, endpoints)
	p.mainProxy.OnEndpointsUpdate(oldEndpoints, endpoints)

	if wasUsingUserspace != hsvc.usingUserspace {
		p.switchService(svcName, hsvc)
	}
}

func (p *HybridProxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints = false

	klog.V(6).Infof("del ep %s", svcName)
	p.unidlingProxy.OnEndpointsDelete(endpoints)
	p.mainProxy.OnEndpointsDelete(endpoints)
}

func (p *HybridProxier) OnEndpointsSynced() {
	p.unidlingProxy.OnEndpointsSynced()
	p.mainProxy.OnEndpointsSynced()
	klog.V(6).Infof("endpoints synced")
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
