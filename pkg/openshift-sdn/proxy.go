package openshift_sdn

import (
	"fmt"
	"net"
	"net/http"
	"time"

	v1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	kv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	kubeproxyoptions "k8s.io/kubernetes/cmd/kube-proxy/app"
	proxy "k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	pconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/iptables"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	"k8s.io/kubernetes/pkg/proxy/userspace"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilnode "k8s.io/kubernetes/pkg/util/node"
	utilsysctl "k8s.io/kubernetes/pkg/util/sysctl"
	utilexec "k8s.io/utils/exec"

	sdnproxy "github.com/openshift/sdn/pkg/network/proxy"
	"github.com/openshift/sdn/pkg/network/proxyimpl/hybrid"
	"github.com/openshift/sdn/pkg/network/proxyimpl/unidler"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog"
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
	protocol := utiliptables.ProtocolIpv4
	bindAddr := net.ParseIP(sdn.ProxyConfig.BindAddress)
	if bindAddr.To4() == nil {
		protocol = utiliptables.ProtocolIpv6
	}

	portRange := utilnet.ParsePortRangeOrDie(sdn.ProxyConfig.PortRange)

	hostname, err := utilnode.GetHostname(sdn.ProxyConfig.HostnameOverride)
	if err != nil {
		klog.Fatalf("Unable to get hostname: %v", err)
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&kv1core.EventSinkImpl{Interface: sdn.informers.KubeClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "kube-proxy", Host: hostname})

	execer := utilexec.New()
	iptInterface := utiliptables.New(execer, protocol)

	var proxier proxy.ProxyProvider
	var healthzServer *healthcheck.HealthzServer
	if len(sdn.ProxyConfig.HealthzBindAddress) > 0 {
		nodeRef := &v1.ObjectReference{
			Kind:      "Node",
			Name:      hostname,
			UID:       types.UID(hostname),
			Namespace: "",
		}
		healthzServer = healthcheck.NewDefaultHealthzServer(sdn.ProxyConfig.HealthzBindAddress, 2*sdn.ProxyConfig.IPTables.SyncPeriod.Duration, recorder, nodeRef)
	}

	enableUnidling := false

	switch string(sdn.ProxyConfig.Mode) {
	case "unidling+iptables":
		enableUnidling = true
		fallthrough
	case "iptables":
		klog.V(0).Infof("Using %s Proxier.", sdn.ProxyConfig.Mode)
		if bindAddr.Equal(net.IPv4zero) {
			var err error
			bindAddr, err = getNodeIP(sdn.informers.KubeClient.CoreV1(), hostname)
			if err != nil {
				klog.Fatalf("Unable to get a bind address: %v", err)
			}
		}
		if sdn.ProxyConfig.IPTables.MasqueradeBit == nil {
			// IPTablesMasqueradeBit must be specified or defaulted.
			klog.Fatalf("Unable to read IPTablesMasqueradeBit from config")
		}
		proxier, err = iptables.NewProxier(
			iptInterface,
			utilsysctl.New(),
			execer,
			sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
			sdn.ProxyConfig.IPTables.MinSyncPeriod.Duration,
			sdn.ProxyConfig.IPTables.MasqueradeAll,
			int(*sdn.ProxyConfig.IPTables.MasqueradeBit),
			sdn.ProxyConfig.ClusterCIDR,
			hostname,
			bindAddr,
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
		hp, ok := proxier.(hybrid.RunnableProxy)
		if !ok {
			// unreachable
			klog.Fatalf("unidling proxy must be used in iptables mode")
		}
		proxier, err = hybrid.NewHybridProxier(
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
		healthzServer.Run()
	}

	// Start up a metrics server if requested
	if len(sdn.ProxyConfig.MetricsBindAddress) > 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/proxyMode", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s", sdn.ProxyConfig.Mode)
		})
		mux.Handle("/metrics", prometheus.Handler())
		go utilwait.Until(func() {
			err := http.ListenAndServe(sdn.ProxyConfig.MetricsBindAddress, mux)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("starting metrics server failed: %v", err))
			}
		}, 5*time.Second, utilwait.NeverStop)
	}

	// periodically sync k8s iptables rules
	go utilwait.Forever(proxier.SyncLoop, 0)
	klog.Infof("Started Kubernetes Proxy on %s", sdn.ProxyConfig.BindAddress)
}

// getNodeIP is copied from the upstream proxy config to retrieve the IP of a node.
func getNodeIP(client kv1core.CoreV1Interface, hostname string) (net.IP, error) {
	var node *v1.Node
	var nodeErr error

	// We may beat the thread that causes the node object to be created,
	// so if we can't get it, then we need to wait.
	// This will wait 0, 2, 4, 8, ... 64 seconds, for a total of ~2 mins
	nodeWaitBackoff := utilwait.Backoff{
		Duration: 2 * time.Second,
		Factor:   2,
		Steps:    7,
	}
	utilwait.ExponentialBackoff(nodeWaitBackoff, func() (bool, error) {
		node, nodeErr = client.Nodes().Get(hostname, metav1.GetOptions{})
		if nodeErr == nil {
			return true, nil
		} else if kapierrors.IsNotFound(nodeErr) {
			klog.Warningf("waiting for node %q to be registered with master...", hostname)
			return false, nil
		} else {
			return false, nodeErr
		}
	})
	if nodeErr != nil {
		return nil, fmt.Errorf("failed to retrieve node info (after waiting): %v", nodeErr)
	}

	nodeIP, err := utilnode.GetNodeHostIP(node)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve node IP: %v", err)
	}

	return nodeIP, nil
}
