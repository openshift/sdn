package openshift_sdn_node

import (
	"fmt"
	"k8s.io/apimachinery/pkg/fields"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/features"
	"net"
	"net/http"
	"time"

	// In this file we use the import names that the upstream kube-proxy code uses.
	// eg, "v1", "wait" rather than "corev1", "utilwait".

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/apiserver/pkg/server/routes"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"k8s.io/component-base/configz"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/metrics/legacyregistry"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/apis"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/iptables"
	proxymetrics "k8s.io/kubernetes/pkg/proxy/metrics"
	"k8s.io/kubernetes/pkg/proxy/userspace"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"

	sdnproxy "github.com/openshift/sdn/pkg/network/proxy"
)

const (
	proxyModeUserspace = "userspace"
	proxyModeIPTables  = "iptables"
	proxyModeUnidling  = "unidling+iptables"
	proxyModeIPVS      = "ipvs"
	proxyModeDisabled  = "disabled"
)

// This is a stripped-down copy of ProxyServer from
// k8s.io/kubernetes/cmd/kube-proxy/app/server.go, and should be kept in sync with that.
type ProxyServer struct {
	Client             clientset.Interface
	IptInterface       utiliptables.Interface
	execer             exec.Interface
	Broadcaster        events.EventBroadcaster
	Proxier            proxy.Provider
	ProxyMode          string
	NodeRef            *v1.ObjectReference
	MetricsBindAddress string
	EnableProfiling    bool
	UseEndpointSlices  bool
	ConfigSyncPeriod   time.Duration
	HealthzServer      healthcheck.ProxierHealthUpdater

	// Not in the upstream version
	baseProxy      sdnproxy.HybridizableProxy
	enableUnidling bool
}

// newProxyServer creates the service proxy. This is a modified version of
// newProxyServer() from k8s.io/kubernetes/cmd/kube-proxy/app/server_others.go, and should
// be kept in sync with that.
func newProxyServer(config *kubeproxyconfig.KubeProxyConfiguration, client clientset.Interface, hostname, sdnNodeIP string) (*ProxyServer, error) {
	var err error

	var iptInterface utiliptables.Interface
	execer := exec.New()

	// SDNMISSING: upstream implements --show-hidden-metrics-for-version here

	nodeIP := detectNodeIP(config, sdnNodeIP)
	klog.Infof("Detected node IP %s", nodeIP.String())

	// Create event recorder
	eventBroadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: client.EventsV1()})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, "kube-proxy")

	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      hostname,
		UID:       types.UID(hostname),
		Namespace: "",
	}

	var healthzServer healthcheck.ProxierHealthUpdater
	if len(config.HealthzBindAddress) > 0 {
		healthzServer = healthcheck.NewProxierHealthServer(config.HealthzBindAddress, 2*config.IPTables.SyncPeriod.Duration, recorder, nodeRef)
	}

	var proxier sdnproxy.HybridizableProxy
	var enableUnidling bool

	proxyMode := config.Mode
	if proxyMode == proxyModeUnidling {
		enableUnidling = true
		proxyMode = proxyModeIPTables
	}

	// SDNMISSING: upstream supports dual-stack
	primaryProtocol := utiliptables.ProtocolIPv4
	iptInterface = utiliptables.New(execer, primaryProtocol)

	klog.V(0).Infof("kube-proxy running in single-stack %s mode", iptInterface.Protocol())

	if proxyMode == proxyModeIPTables {
		klog.V(0).Info("Using iptables Proxier.")
		if config.IPTables.MasqueradeBit == nil {
			// MasqueradeBit must be specified or defaulted.
			return nil, fmt.Errorf("unable to read IPTables MasqueradeBit from config")
		}

		localDetector := getLocalDetector()

		proxier, err = iptables.NewProxier(
			iptInterface,
			utilsysctl.New(),
			execer,
			config.IPTables.SyncPeriod.Duration,
			config.IPTables.MinSyncPeriod.Duration,
			config.IPTables.MasqueradeAll,
			int(*config.IPTables.MasqueradeBit),
			localDetector,
			hostname,
			nodeIP,
			recorder,
			healthzServer,
			config.NodePortAddresses,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create proxier: %v", err)
		}
		proxymetrics.RegisterMetrics()
	} else if proxyMode == proxyModeIPVS {
		// SDNMISSING: NOT REACHED: We don't support IPVS mode. (CNO doesn't
		// allow you to set "mode: ipvs".)
	} else {
		klog.V(0).Info("Using userspace Proxier.")

		proxier, err = userspace.NewProxier(
			userspace.NewLoadBalancerRR(),
			net.ParseIP(config.BindAddress),
			iptInterface,
			execer,
			*utilnet.ParsePortRangeOrDie(config.PortRange),
			config.IPTables.SyncPeriod.Duration,
			config.IPTables.MinSyncPeriod.Duration,
			config.UDPIdleTimeout.Duration,
			config.NodePortAddresses,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create proxier: %v", err)
		}
	}

	useEndpointSlices := true
	if proxyMode == proxyModeUserspace {
		// userspace mode doesn't support endpointslice.
		useEndpointSlices = false
	}

	return &ProxyServer{
		Client:             client,
		IptInterface:       iptInterface,
		execer:             execer,
		Broadcaster:        eventBroadcaster,
		ProxyMode:          string(proxyMode),
		NodeRef:            nodeRef,
		MetricsBindAddress: config.MetricsBindAddress,
		EnableProfiling:    config.EnableProfiling,
		ConfigSyncPeriod:   config.ConfigSyncPeriod.Duration,
		HealthzServer:      healthzServer,
		UseEndpointSlices:  useEndpointSlices,

		baseProxy:      proxier,
		enableUnidling: enableUnidling,
	}, nil
}

// serveHealthz runs the healthz server. This is an exact copy of serveHealthz() from
// k8s.io/kubernetes/cmd/kube-proxy/app/server.go
func serveHealthz(hz healthcheck.ProxierHealthUpdater, errCh chan error) {
	if hz == nil {
		return
	}

	fn := func() {
		err := hz.Run()
		if err != nil {
			klog.Errorf("healthz server failed: %v", err)
			if errCh != nil {
				errCh <- fmt.Errorf("healthz server failed: %v", err)
				// if in hardfail mode, never retry again
				blockCh := make(chan error)
				<-blockCh
			}
		} else {
			klog.Errorf("healthz server returned without error")
		}
	}
	go wait.Until(fn, 5*time.Second, wait.NeverStop)
}

// serveMetrics runs the metrics server. This is an exact copy of serveMetrics() from
// k8s.io/kubernetes/cmd/kube-proxy/app/server.go
func serveMetrics(bindAddress, proxyMode string, enableProfiling bool, errCh chan error) {
	if len(bindAddress) == 0 {
		return
	}

	proxyMux := mux.NewPathRecorderMux("kube-proxy")
	healthz.InstallHandler(proxyMux)
	proxyMux.HandleFunc("/proxyMode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintf(w, "%s", proxyMode)
	})

	//lint:ignore SA1019 See the Metrics Stability Migration KEP
	proxyMux.Handle("/metrics", legacyregistry.Handler())

	if enableProfiling {
		routes.Profiling{}.Install(proxyMux)
		routes.DebugFlags{}.Install(proxyMux, "v", routes.StringFlagPutHandler(logs.GlogSetter))
	}

	configz.InstallHandler(proxyMux)

	fn := func() {
		err := http.ListenAndServe(bindAddress, proxyMux)
		if err != nil {
			err = fmt.Errorf("starting metrics server failed: %v", err)
			utilruntime.HandleError(err)
			if errCh != nil {
				errCh <- err
				// if in hardfail mode, never retry again
				blockCh := make(chan error)
				<-blockCh
			}
		}
	}
	go wait.Until(fn, 5*time.Second, wait.NeverStop)
}

// startProxyServer starts the service proxy. This is a modified version of
// ProxyServer.Run() from k8s.io/kubernetes/cmd/kube-proxy/app/server.go, and should be
// kept in sync with that.
func startProxyServer(s *ProxyServer) error {
	// SDNMISSING: upstream handles the --oom-score-adj flag here

	if s.Broadcaster != nil {
		stopCh := make(chan struct{})
		s.Broadcaster.StartRecordingToSink(stopCh)
	}

	var errCh chan error
	// SDNMISSING: upstream handles the --bind-address-hard-fail flag here

	// Start up a healthz server if requested
	serveHealthz(s.HealthzServer, errCh)

	// Start up a metrics server if requested
	serveMetrics(s.MetricsBindAddress, s.ProxyMode, s.EnableProfiling, errCh)

	// SDNMISSING: upstream handles the --conntrack-max-per-core, --conntrack-min,
	// --conntrack-tcp-timeout-close-wait, and --conntrack-tcp-timeout-close-wait
	// flags here.

	noProxyName, err := labels.NewRequirement(apis.LabelServiceProxyName, selection.DoesNotExist, nil)
	if err != nil {
		return err
	}

	noHeadlessEndpoints, err := labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		return err
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

	// Make informers that filter out objects that want a non-default service proxy.
	informerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.ConfigSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = labelSelector.String()
		}))

	// Create configs (i.e. Watches for Services and Endpoints or EndpointSlices)
	// Note: RegisterHandler() calls need to happen before creation of Sources because sources
	// only notify on changes, and the initial update (on process start) may be lost if no handlers
	// are registered yet.
	serviceConfig := config.NewServiceConfig(informerFactory.Core().V1().Services(), s.ConfigSyncPeriod)
	serviceConfig.RegisterEventHandler(s.Proxier)
	go serviceConfig.Run(wait.NeverStop)

	if endpointsHandler, ok := s.Proxier.(config.EndpointsHandler); ok && !s.UseEndpointSlices {
		endpointsConfig := config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), s.ConfigSyncPeriod)
		endpointsConfig.RegisterEventHandler(endpointsHandler)
		go endpointsConfig.Run(wait.NeverStop)
	} else {
		endpointSliceConfig := config.NewEndpointSliceConfig(informerFactory.Discovery().V1().EndpointSlices(), s.ConfigSyncPeriod)
		endpointSliceConfig.RegisterEventHandler(s.Proxier)
		go endpointSliceConfig.Run(wait.NeverStop)
	}

	// This has to start after the calls to NewServiceConfig and NewEndpointsConfig because those
	// functions must configure their shared informer event handlers first.
	informerFactory.Start(wait.NeverStop)

	if utilfeature.DefaultFeatureGate.Enabled(features.TopologyAwareHints) {
		// Make an informer that selects for our nodename.
		currentNodeInformerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.ConfigSyncPeriod,
			informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.FieldSelector = fields.OneTermEqualSelector("metadata.name", s.NodeRef.Name).String()
			}))
		nodeConfig := config.NewNodeConfig(currentNodeInformerFactory.Core().V1().Nodes(), s.ConfigSyncPeriod)
		nodeConfig.RegisterEventHandler(s.Proxier)
		go nodeConfig.Run(wait.NeverStop)

		// This has to start after the calls to NewNodeConfig because that must
		// configure the shared informer event handler first.
		currentNodeInformerFactory.Start(wait.NeverStop)
	}

	go s.Proxier.SyncLoop()

	return nil
}
