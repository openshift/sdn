package userspace

// Some extra hacking for openshift-specific stuff

import "k8s.io/kubernetes/pkg/util/async"

func (p *Proxier) UsesEndpoints() bool {
	return true
}

func (p *Proxier) UsesEndpointSlices() bool {
	return false
}

func (p *Proxier) SyncProxyRules() {
	p.syncProxyRules()
}

func (p *Proxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
	p.syncRunner = b
}
