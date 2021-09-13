package iptables

// Some extra hacking for openshift-specific stuff

import (
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/util/async"
)

func (p *Proxier) UsesEndpoints() bool {
	return !utilfeature.DefaultFeatureGate.Enabled(features.EndpointSliceProxying)
}

func (p *Proxier) UsesEndpointSlices() bool {
	return utilfeature.DefaultFeatureGate.Enabled(features.EndpointSliceProxying)
}

func (p *Proxier) SyncProxyRules() {
	p.syncProxyRules()
}

func (p *Proxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
	p.syncRunner = b
}

func (p *Proxier) ReloadIPTables() {
	// Ignore this; the iptables proxier has its own iptables.Monitor
}
