package openshift_sdn_node

import (
	"io/ioutil"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	sdnnode "github.com/openshift/sdn/pkg/network/node"
)

const openshiftCNIFile string = "/etc/cni/net.d/80-openshift-network.conf"

// initSDN sets up the sdn process.
func (sdn *openShiftSDN) initSDN() error {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: sdn.informers.kubeClient.CoreV1().Events("")})
	sdn.sdnRecorder = eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "openshift-sdn", Host: sdn.nodeName})

	var err error
	sdn.osdnNode, err = sdnnode.New(&sdnnode.OsdnNodeConfig{
		NodeName:      sdn.nodeName,
		NodeIP:        sdn.nodeIP,
		PlatformType:  sdn.platformType,
		OSDNClient:    sdn.informers.osdnClient,
		KClient:       sdn.informers.kubeClient,
		KubeInformers: sdn.informers.kubeInformers,
		OSDNInformers: sdn.informers.osdnInformers,
		IPTables:      sdn.ipt,
		MasqueradeBit: sdn.proxyConfig.IPTables.MasqueradeBit,
		Recorder:      sdn.sdnRecorder,
		OverrideMTU:   sdn.overrideMTU,
		RoutableMTU:   sdn.routableMTU,
	})
	return err
}

// runSDN starts the sdn node process. Returns.
func (sdn *openShiftSDN) runSDN() error {
	return sdn.osdnNode.Start()
}

func (sdn *openShiftSDN) writeConfigFile() error {
	// Make an event that openshift-sdn started
	sdn.sdnRecorder.Eventf(&corev1.ObjectReference{Kind: "Node", Name: sdn.nodeName}, corev1.EventTypeNormal, "Starting", "openshift-sdn done initializing node networking.")

	// Write our CNI config file out to disk to signal to kubelet that
	// our network plugin is ready
	return ioutil.WriteFile(openshiftCNIFile, []byte(`
{
  "cniVersion": "0.3.1",
  "name": "openshift-sdn",
  "type": "openshift-sdn"
}
`), 0600)
}
