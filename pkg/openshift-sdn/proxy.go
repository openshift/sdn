package openshift_sdn

import (
	"fmt"
	"net"
	"net/http"
	"time"

	sdnproxy "github.com/openshift/sdn/pkg/network/proxy"
	"github.com/openshift/sdn/pkg/network/proxyimpl/unidler"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/apiserver/pkg/server/routes"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes/scheme"
	kv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"
	kubeproxyoptions "k8s.io/kubernetes/cmd/kube-proxy/app"
	"k8s.io/kubernetes/pkg/features"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	pconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/iptables"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	"k8s.io/kubernetes/pkg/proxy/userspace"
	proxyutiliptables "k8s.io/kubernetes/pkg/proxy/util/iptables"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilsysctl "k8s.io/kubernetes/pkg/util/sysctl"
	utilexec "k8s.io/utils/exec"
)

// readProxyConfig reads the proxy config from a file
func readProxyConfig(filename string) (*kubeproxyconfig.KubeProxyConfiguration, error) {
	o := kubeproxyoptions.NewOptions()
	o.ConfigFile = filename
	if err := o.Complete(); err != nil {
		return nil, err
	}
	return o.GetConfig(), nil
}

// initProxy sets up the proxy process.
func (sdn *OpenShiftSDN) initProxy() error {
	var err error
	sdn.OsdnProxy, err = sdnproxy.New(
		sdn.informers.KubeClient,
		sdn.informers.KubeInformers,
		sdn.informers.NetworkClient,
		sdn.informers.NetworkInformers,
		sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration)
	return err
}

// runProxy starts the configured proxy process and closes the provided channel
// when the proxy has initialized
func (sdn *OpenShiftSDN) runProxy(waitChan chan<- bool) {
	if string(sdn.ProxyConfig.Mode) == "disabled" {
		klog.Warningf("Built-in kube-proxy is disabled")
		sdn.startMetricsServer()
		close(waitChan)
		return
	}

	bindAddr := net.ParseIP(sdn.ProxyConfig.BindAddress)
	nodeAddr := bindAddr

	if nodeAddr.IsUnspecified() {
		nodeAddr = net.ParseIP(sdn.nodeIP)
		if nodeAddr == nil {
			klog.Fatalf("Unable to parse node IP %q", sdn.nodeIP)
		}
	}

	protocol := utiliptables.ProtocolIPv4
	if nodeAddr.To4() == nil {
		protocol = utiliptables.ProtocolIPv6
	}

	portRange := utilnet.ParsePortRangeOrDie(sdn.ProxyConfig.PortRange)

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&kv1core.EventSinkImpl{Interface: sdn.informers.KubeClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "kube-proxy", Host: sdn.nodeName})

	execer := utilexec.New()
	iptInterface := utiliptables.New(execer, protocol)

	var healthzServer healthcheck.ProxierHealthUpdater
	if len(sdn.ProxyConfig.HealthzBindAddress) > 0 {
		nodeRef := &v1.ObjectReference{
			Kind:      "Node",
			Name:      sdn.nodeName,
			UID:       types.UID(sdn.nodeName),
			Namespace: "",
		}
		healthzServer = healthcheck.NewProxierHealthServer(sdn.ProxyConfig.HealthzBindAddress, 2*sdn.ProxyConfig.IPTables.SyncPeriod.Duration, recorder, nodeRef)
	}

	enableUnidling := false
	usingEndpointSlices := false
	var err error

	var proxier, unidlingProxy sdnproxy.HybridizableProxy
	switch string(sdn.ProxyConfig.Mode) {
	case "unidling+iptables":
		enableUnidling = true
		fallthrough
	case "iptables":
		klog.V(0).Infof("Using %s Proxier.", sdn.ProxyConfig.Mode)
		usingEndpointSlices = utilfeature.DefaultFeatureGate.Enabled(features.EndpointSliceProxying)

		if sdn.ProxyConfig.IPTables.MasqueradeBit == nil {
			// IPTablesMasqueradeBit must be specified or defaulted.
			klog.Fatalf("Unable to read IPTablesMasqueradeBit from config")
		}

		var localDetector proxyutiliptables.LocalTrafficDetector
		if sdn.ProxyConfig.ClusterCIDR == "" {
			klog.Warningf("Kubeproxy does not support multiple cluster CIDRs, configuring no-op local traffic detector")
			localDetector = proxyutiliptables.NewNoOpLocalDetector()
		} else {
			localDetector, err = proxyutiliptables.NewDetectLocalByCIDR(sdn.ProxyConfig.ClusterCIDR, iptInterface)
			if err != nil {
				klog.Fatalf("Unable to configure local traffic detector: %v", err)
			}
		}

		proxier, err = iptables.NewProxier(
			iptInterface,
			utilsysctl.New(),
			execer,
			sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
			sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.ProxyConfig.IPTables.MasqueradeAll,
			int(*sdn.ProxyConfig.IPTables.MasqueradeBit),
			localDetector,
			sdn.nodeName,
			nodeAddr,
			recorder,
			healthzServer,
			sdn.ProxyConfig.NodePortAddresses,
		)
		metrics.RegisterMetrics()

		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
		// No turning back. Remove artifacts that might still exist from the userspace Proxier.
		klog.V(0).Info("Tearing down userspace rules.")
		userspace.CleanupLeftovers(iptInterface)
	case "userspace":
		klog.V(0).Info("Using userspace Proxier.")

		execer := utilexec.New()
		proxier, err = userspace.NewProxier(
			userspace.NewLoadBalancerRR(),
			bindAddr,
			iptInterface,
			execer,
			*portRange,
			sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
			sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.ProxyConfig.UDPIdleTimeout.Duration,
			sdn.ProxyConfig.NodePortAddresses,
		)
		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
		// Remove artifacts from the pure-iptables Proxier.
		klog.V(0).Info("Tearing down pure-iptables proxy rules.")
		iptables.CleanupLeftovers(iptInterface)
	default:
		klog.Fatalf("Unknown proxy mode %q", sdn.ProxyConfig.Mode)
	}

	if enableUnidling {
		signaler := unidler.NewEventSignaler(recorder)
		unidlingProxy, err = unidler.NewUnidlerProxier(
			userspace.NewLoadBalancerRR(),
			bindAddr,
			iptInterface,
			execer,
			*portRange,
			sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
			sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.ProxyConfig.UDPIdleTimeout.Duration,
			sdn.ProxyConfig.NodePortAddresses,
			signaler)
		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
	}

	sdn.OsdnProxy.SetBaseProxies(proxier, unidlingProxy)
	if err := sdn.OsdnProxy.Start(waitChan); err != nil {
		klog.Fatalf("error: node proxy plugin startup failed: %v", err)
	}

	serviceConfig := pconfig.NewServiceConfig(
		sdn.informers.KubeInformers.Core().V1().Services(),
		sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
	)
	serviceConfig.RegisterEventHandler(sdn.OsdnProxy)
	go serviceConfig.Run(utilwait.NeverStop)

	if usingEndpointSlices {
		endpointSliceConfig := pconfig.NewEndpointSliceConfig(
			sdn.informers.KubeInformers.Discovery().V1beta1().EndpointSlices(),
			sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
		)
		endpointSliceConfig.RegisterEventHandler(sdn.OsdnProxy)
		go endpointSliceConfig.Run(utilwait.NeverStop)
	} else {
		endpointsConfig := pconfig.NewEndpointsConfig(
			sdn.informers.KubeInformers.Core().V1().Endpoints(),
			sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
		)
		endpointsConfig.RegisterEventHandler(sdn.OsdnProxy)
		go endpointsConfig.Run(utilwait.NeverStop)
	}

	// Start up healthz server
	if len(sdn.ProxyConfig.HealthzBindAddress) > 0 {
		serveHealthz(healthzServer)
	}

	// Start up a metrics server if requested
	sdn.startMetricsServer()

	// periodically sync k8s iptables rules
	go utilwait.Forever(sdn.OsdnProxy.SyncLoop, 0)
	klog.Infof("Started Kubernetes Proxy on %s", sdn.ProxyConfig.BindAddress)
}

func (sdn *OpenShiftSDN) startMetricsServer() {
	if sdn.ProxyConfig.MetricsBindAddress == "" {
		return
	}

	mux := mux.NewPathRecorderMux("kube-proxy")
	mux.HandleFunc("/proxyMode", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", sdn.ProxyConfig.Mode)
	})
	mux.Handle("/metrics", legacyregistry.Handler())
	if sdn.ProxyConfig.EnableProfiling {
		routes.Profiling{}.Install(mux)
	}
	go utilwait.Until(func() {
		err := http.ListenAndServe(sdn.ProxyConfig.MetricsBindAddress, mux)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("starting metrics server failed: %v", err))
		}
	}, 5*time.Second, utilwait.NeverStop)
}

func serveHealthz(hz healthcheck.ProxierHealthUpdater) {
	go utilwait.Until(func() {
		err := hz.Run()
		if err != nil {
			// For historical reasons we do not abort on errors here.  We may
			// change that in the future.
			klog.Errorf("healthz server failed: %v", err)
		} else {
			klog.Errorf("healthz server returned without error")
		}
	}, 5*time.Second, utilwait.NeverStop)
}
