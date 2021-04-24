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
	proxy "k8s.io/kubernetes/pkg/proxy"
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
		sdn.informers.NetworkClient,
		sdn.informers.KubeClient,
		sdn.informers.NetworkInformers)
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

	if utilfeature.DefaultFeatureGate.Enabled(features.EndpointSliceProxying) {
		klog.Warningf("kube-proxy has unsupported EndpointSliceProxying gates enabled")
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

	var proxier proxy.Provider
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
	var err error

	switch string(sdn.ProxyConfig.Mode) {
	case "unidling+iptables":
		enableUnidling = true
		fallthrough
	case "iptables":
		klog.V(0).Infof("Using %s Proxier.", sdn.ProxyConfig.Mode)
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

	// Create configs (i.e. Watches for Services and Endpoints)
	// Note: RegisterHandler() calls need to happen before creation of Sources because sources
	// only notify on changes, and the initial update (on process start) may be lost if no handlers
	// are registered yet.
	serviceConfig := pconfig.NewServiceConfig(
		sdn.informers.KubeInformers.Core().V1().Services(),
		sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
	)

	if enableUnidling {
		signaler := unidler.NewEventSignaler(recorder)
		unidlingUserspaceProxy, err := unidler.NewUnidlerProxier(userspace.NewLoadBalancerRR(), bindAddr, iptInterface, execer, *portRange, sdn.ProxyConfig.IPTables.SyncPeriod.Duration, sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration, sdn.ProxyConfig.UDPIdleTimeout.Duration, sdn.ProxyConfig.NodePortAddresses, signaler)
		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
		hp, ok := proxier.(sdnproxy.RunnableProxy)
		if !ok {
			// unreachable
			klog.Fatalf("unidling proxy must be used in iptables mode")
		}
		proxier, err = sdnproxy.NewHybridProxier(
			hp,
			unidlingUserspaceProxy,
			sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.informers.KubeInformers.Core().V1().Services().Lister(),
		)
		if err != nil {
			klog.Fatalf("error: Could not initialize Kubernetes Proxy. You must run this process as root (and if containerized, in the host network namespace as privileged) to use the service proxy: %v", err)
		}
	}

	endpointsConfig := pconfig.NewEndpointsConfig(
		sdn.informers.KubeInformers.Core().V1().Endpoints(),
		sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
	)
	// customized handling registration that inserts a filter if needed
	if err := sdn.OsdnProxy.Start(proxier, waitChan); err != nil {
		klog.Fatalf("error: node proxy plugin startup failed: %v", err)
	}
	proxier = sdn.OsdnProxy

	serviceConfig.RegisterEventHandler(proxier)
	go serviceConfig.Run(utilwait.NeverStop)

	endpointsConfig.RegisterEventHandler(proxier)
	go endpointsConfig.Run(utilwait.NeverStop)

	// Start up healthz server
	if len(sdn.ProxyConfig.HealthzBindAddress) > 0 {
		serveHealthz(healthzServer)
	}

	// Start up a metrics server if requested
	sdn.startMetricsServer()

	// periodically sync k8s iptables rules
	go utilwait.Forever(proxier.SyncLoop, 0)
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
