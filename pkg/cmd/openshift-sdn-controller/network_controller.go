package openshift_sdn_controller

import (
	"context"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	configv1 "github.com/openshift/api/config/v1"
	leaderelectionconverter "github.com/openshift/library-go/pkg/config/leaderelection"
	"github.com/openshift/library-go/pkg/serviceability"
	sdnmaster "github.com/openshift/sdn/pkg/network/master"
	"github.com/openshift/sdn/pkg/network/master/metrics"

	// for metrics
	_ "k8s.io/component-base/metrics/prometheus/restclient"
	_ "k8s.io/component-base/metrics/prometheus/version"
)

func RunOpenShiftNetworkController(platformType string) error {
	serviceability.InitLogrusFromKlog()

	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return err
	}

	originControllerManager := func(ctx context.Context) {
		controllerContext, err := newControllerContext(platformType, clientConfig)
		if err != nil {
			klog.Fatal(err)
		}
		if err := sdnmaster.Start(
			controllerContext.kubernetesClient,
			controllerContext.kubernetesInformers,
			controllerContext.osdnClient,
			controllerContext.osdnInformers,
			controllerContext.cloudNetworkClient,
			controllerContext.cloudNetworkInformer,
		); err != nil {
			klog.Fatalf("Error starting OpenShift Network Controller: %v", err)
		}
		klog.Infof("Started OpenShift Network Controller")
		controllerContext.StartInformers()
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	eventRecorder := eventBroadcaster.NewRecorder(legacyscheme.Scheme, corev1.EventSource{Component: "openshift-network-controller"})
	id, err := os.Hostname()
	if err != nil {
		return err
	}

	leaderConfig := leaderelectionconverter.LeaderElectionDefaulting(configv1.LeaderElection{}, "openshift-sdn", "openshift-network-controller")
	rl, err := resourcelock.New(
		"configmaps",
		leaderConfig.Namespace,
		leaderConfig.Name,
		kubeClient.CoreV1(),
		kubeClient.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity:      id,
			EventRecorder: eventRecorder,
		})
	if err != nil {
		return err
	}
	metricsServer := metrics.StartServer()
	go leaderelection.RunOrDie(context.Background(),
		leaderelection.LeaderElectionConfig{
			Lock:          rl,
			LeaseDuration: leaderConfig.LeaseDuration.Duration,
			RenewDeadline: leaderConfig.RenewDeadline.Duration,
			RetryPeriod:   leaderConfig.RetryPeriod.Duration,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(ctx context.Context) {
					metrics.Register()
					originControllerManager(ctx)
				},
				OnStoppedLeading: func() {
					metrics.StopServer(metricsServer)
					klog.Errorf("leader election lost")
					os.Exit(1)
				},
			},
		})

	return nil
}
