package openshift_sdn_node

import (
	"fmt"
	"io/ioutil"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	eventsv1 "k8s.io/client-go/tools/events"

	sdnnode "github.com/openshift/sdn/pkg/network/node"
)

const openshiftCNIFile string = "/etc/cni/net.d/80-openshift-network.conf"

// initSDN sets up the sdn process.
func (sdn *openShiftSDN) initSDN(stopCh <-chan struct{}) error {
	eventBroadcaster := eventsv1.NewBroadcaster(&eventsv1.EventSinkImpl{Interface: sdn.informers.kubeClient.EventsV1()})
	eventBroadcaster.StartRecordingToSink(stopCh)
	sdn.sdnRecorder = eventBroadcaster.NewRecorder(scheme.Scheme, "openshift-sdn")

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
		ProxyMode:     sdn.proxyConfig.Mode,
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
	nodeRef := &corev1.ObjectReference{Kind: "Node", Name: sdn.nodeName}
	note := fmt.Sprintf("openshift-sdn completed initializing networking for node %s", sdn.nodeName)
	sdn.sdnRecorder.Eventf(nodeRef, nil, corev1.EventTypeNormal, "", "NodeNetworkReady", note)

	// Write our CNI config file out to disk to signal to kubelet that
	// our network plugin is ready
	return ioutil.WriteFile(openshiftCNIFile, []byte(`
{
  "cniVersion": "0.3.1",
  "name": "openshift-sdn",
  "type": "openshift-sdn"
}
`), 0644)
}
