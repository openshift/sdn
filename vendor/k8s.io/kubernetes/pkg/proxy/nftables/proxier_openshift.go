package nftables

// Some extra hacking for openshift-specific stuff

import (
	"k8s.io/kubernetes/pkg/util/async"
)

func (p *Proxier) SyncProxyRules() {
	p.syncProxyRules()
}

func (p *Proxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
	p.syncRunner = b
}

func (p *Proxier) ReloadIPTables() {
	// Ignore this; the iptables proxier has its own iptables.Monitor
}
