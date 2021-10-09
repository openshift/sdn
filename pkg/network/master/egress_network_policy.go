package master

import (
	"k8s.io/apimachinery/pkg/watch"

	osdnv1 "github.com/openshift/api/network/v1"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/network/master/metrics"
)

type egressNetworkPolicyManager struct {
	policyCount int
	ruleCount   int
}

func newEgressNetworkPolicyManager() *egressNetworkPolicyManager {
	return &egressNetworkPolicyManager{}
}

func (enp *egressNetworkPolicyManager) start(informer osdninformers.EgressNetworkPolicyInformer) {
	informer.Informer().AddEventHandler(
		common.InformerFuncs(&osdnv1.EgressNetworkPolicy{}, enp.handleAddUpdate, enp.handleDelete))
}

func (enp *egressNetworkPolicyManager) handleAddUpdate(current, old interface{}, event watch.EventType) {
	var change int
	currentEgressNetworkPolicy, _ := current.(*osdnv1.EgressNetworkPolicy)

	if event == watch.Modified {
		oldEgressNetworkPolicy := old.(*osdnv1.EgressNetworkPolicy)
		change = len(currentEgressNetworkPolicy.Spec.Egress) - len(oldEgressNetworkPolicy.Spec.Egress)
	} else {
		change = len(currentEgressNetworkPolicy.Spec.Egress)
		enp.policyCount++
	}
	enp.ruleCount += change
	enp.recordMetrics()
}

func (enp *egressNetworkPolicyManager) handleDelete(obj interface{}) {
	egressNetworkPolicy, _ := obj.(*osdnv1.EgressNetworkPolicy)
	enp.ruleCount -= len(egressNetworkPolicy.Spec.Egress)
	enp.policyCount--
	enp.recordMetrics()
}

// recordMetrics records prometheus metrics
func (enp *egressNetworkPolicyManager) recordMetrics() {
	metrics.RecordEgressFirewallRuleCount(float64(enp.ruleCount))
	metrics.RecordEgressFirewallCount(float64(enp.policyCount))
}
