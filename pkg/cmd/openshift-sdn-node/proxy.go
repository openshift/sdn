package openshift_sdn_node

import (
	"fmt"
	"net"
	"net/http"
	"time"

	sdnproxy "github.com/openshift/sdn/pkg/network/proxy"
	"github.com/openshift/sdn/pkg/network/proxy/unidler"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/apiserver/pkg/server/routes"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
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
func (sdn *openShiftSDN) initProxy() error {
	var err error
	sdn.osdnProxy, err = sdnproxy.New(
		sdn.informers.kubeClient,
		sdn.informers.kubeInformers,
		sdn.informers.osdnClient,
		sdn.informers.osdnInformers,
		sdn.proxyConfig.IPTables.MinSyncPeriod.Duration)
	return err
}

// runProxy starts the configured proxy process and closes the provided channel
// when the proxy has initialized
func (sdn *openShiftSDN) runProxy(waitChan chan<- bool) {
	if string(sdn.proxyConfig.Mode) == "disabled" {
		klog.Warningf("Built-in kube-proxy is disabled")
		sdn.startMetricsServer()
		close(waitChan)
		return
	}

	bindAddr := net.ParseIP(sdn.proxyConfig.BindAddress)
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

	portRange := utilnet.ParsePortRangeOrDie(sdn.proxyConfig.PortRange)

	eventBroadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: sdn.informers.kubeClient.EventsV1()})
	stopCh := make(chan struct{})
	eventBroadcaster.StartRecordingToSink(stopCh)
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, "kube-proxy")

	execer := utilexec.New()
	iptInterface := utiliptables.New(execer, protocol)

	var healthzServer healthcheck.ProxierHealthUpdater
	if len(sdn.proxyConfig.HealthzBindAddress) > 0 {
		nodeRef := &corev1.ObjectReference{
			Kind:      "Node",
			Name:      sdn.nodeName,
			UID:       types.UID(sdn.nodeName),
			Namespace: "",
		}
		healthzServer = healthcheck.NewProxierHealthServer(sdn.proxyConfig.HealthzBindAddress, 2*sdn.proxyConfig.IPTables.SyncPeriod.Duration, recorder, nodeRef)
	}

	enableUnidling := false
	usingEndpointSlices := false
	var err error

	var proxier, unidlingProxy sdnproxy.HybridizableProxy
	switch string(sdn.proxyConfig.Mode) {
	case "unidling+iptables":
		enableUnidling = true
		fallthrough
	case "iptables":
		klog.V(0).Infof("Using %s Proxier.", sdn.proxyConfig.Mode)
		usingEndpointSlices = utilfeature.DefaultFeatureGate.Enabled(features.EndpointSliceProxying)

		if sdn.proxyConfig.IPTables.MasqueradeBit == nil {
			// IPTablesMasqueradeBit must be specified or defaulted.
			klog.Fatalf("Unable to read IPTablesMasqueradeBit from config")
		}

		var localDetector proxyutiliptables.LocalTrafficDetector
		if sdn.proxyConfig.ClusterCIDR == "" {
			klog.Warningf("Kubeproxy does not support multiple cluster CIDRs, configuring no-op local traffic detector")
			localDetector = proxyutiliptables.NewNoOpLocalDetector()
		} else {
			localDetector, err = proxyutiliptables.NewDetectLocalByCIDR(sdn.proxyConfig.ClusterCIDR, iptInterface)
			if err != nil {
				klog.Fatalf("Unable to configure local traffic detector: %v", err)
			}
		}

		proxier, err = iptables.NewProxier(
			iptInterface,
			utilsysctl.New(),
			execer,
			sdn.proxyConfig.IPTables.SyncPeriod.Duration,
			sdn.proxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.proxyConfig.IPTables.MasqueradeAll,
			int(*sdn.proxyConfig.IPTables.MasqueradeBit),
			localDetector,
			sdn.nodeName,
			nodeAddr,
			recorder,
			healthzServer,
			sdn.proxyConfig.NodePortAddresses,
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
			sdn.proxyConfig.IPTables.SyncPeriod.Duration,
			sdn.proxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.proxyConfig.UDPIdleTimeout.Duration,
			sdn.proxyConfig.NodePortAddresses,
		)
		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
		// Remove artifacts from the pure-iptables Proxier.
		klog.V(0).Info("Tearing down pure-iptables proxy rules.")
		iptables.CleanupLeftovers(iptInterface)
	default:
		klog.Fatalf("Unknown proxy mode %q", sdn.proxyConfig.Mode)
	}

	if enableUnidling {
		signaler := unidler.NewEventSignaler(recorder)
		unidlingProxy, err = unidler.NewUnidlerProxier(
			userspace.NewLoadBalancerRR(),
			bindAddr,
			iptInterface,
			execer,
			*portRange,
			sdn.proxyConfig.IPTables.SyncPeriod.Duration,
			sdn.proxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.proxyConfig.UDPIdleTimeout.Duration,
			sdn.proxyConfig.NodePortAddresses,
			signaler)
		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
	}

	sdn.osdnProxy.SetBaseProxies(proxier, unidlingProxy)
	if err := sdn.osdnProxy.Start(waitChan); err != nil {
		klog.Fatalf("error: node proxy plugin startup failed: %v", err)
	}

	serviceConfig := pconfig.NewServiceConfig(
		sdn.informers.kubeInformers.Core().V1().Services(),
		sdn.proxyConfig.IPTables.SyncPeriod.Duration,
	)
	serviceConfig.RegisterEventHandler(sdn.osdnProxy)
	go serviceConfig.Run(utilwait.NeverStop)

	if usingEndpointSlices {
		endpointSliceConfig := pconfig.NewEndpointSliceConfig(
			sdn.informers.kubeInformers.Discovery().V1().EndpointSlices(),
			sdn.proxyConfig.IPTables.SyncPeriod.Duration,
		)
		endpointSliceConfig.RegisterEventHandler(sdn.osdnProxy)
		go endpointSliceConfig.Run(utilwait.NeverStop)
	} else {
		endpointsConfig := pconfig.NewEndpointsConfig(
			sdn.informers.kubeInformers.Core().V1().Endpoints(),
			sdn.proxyConfig.IPTables.SyncPeriod.Duration,
		)
		endpointsConfig.RegisterEventHandler(sdn.osdnProxy)
		go endpointsConfig.Run(utilwait.NeverStop)
	}

	// Start up healthz server
	if len(sdn.proxyConfig.HealthzBindAddress) > 0 {
		serveHealthz(healthzServer)
	}

	// Start up a metrics server if requested
	sdn.startMetricsServer()

	// periodically sync k8s iptables rules
	go utilwait.Forever(sdn.osdnProxy.SyncLoop, 0)
	klog.Infof("Started Kubernetes Proxy on %s", sdn.proxyConfig.BindAddress)
}

func (sdn *openShiftSDN) startMetricsServer() {
	if sdn.proxyConfig.MetricsBindAddress == "" {
		return
	}

	mux := mux.NewPathRecorderMux("kube-proxy")
	mux.HandleFunc("/proxyMode", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", sdn.proxyConfig.Mode)
	})
	mux.Handle("/metrics", legacyregistry.Handler())
	if sdn.proxyConfig.EnableProfiling {
		routes.Profiling{}.Install(mux)
	}
	go utilwait.Until(func() {
		err := http.ListenAndServe(sdn.proxyConfig.MetricsBindAddress, mux)
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
