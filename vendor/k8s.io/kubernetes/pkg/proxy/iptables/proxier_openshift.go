package iptables

// Some extra hacking for openshift-specific stuff

import "k8s.io/kubernetes/pkg/util/async"

func (p *Proxier) SyncProxyRules() {
	p.forceSyncProxyRules()
}

func (p *Proxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
	p.syncRunner = b
}
