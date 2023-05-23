package node

import (
	"context"
	"fmt"

	"k8s.io/klog/v2"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"

	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
)

func (plugin *OsdnNode) SetupEgressNetworkPolicy() error {
	policies, err := common.ListAllEgressNetworkPolicies(context.TODO(), plugin.osdnClient)
	if err != nil {
		return fmt.Errorf("could not get EgressNetworkPolicies: %s", err)
	}

	plugin.egressPoliciesLock.Lock()
	defer plugin.egressPoliciesLock.Unlock()

	for _, policy := range policies {
		vnid, err := plugin.policy.GetVNID(policy.Namespace)
		if err != nil {
			klog.Warningf("Could not find netid for namespace %q: %v", policy.Namespace, err)
			continue
		}
		plugin.egressPolicies[vnid] = append(plugin.egressPolicies[vnid], *policy)

		plugin.egressDNS.Add(*policy)
	}

	for vnid := range plugin.egressPolicies {
		plugin.updateEgressNetworkPolicyRules(vnid)
	}

	go utilwait.Forever(plugin.syncEgressDNSPolicyRules, 0)
	plugin.watchEgressNetworkPolicies()
	return nil
}

func (plugin *OsdnNode) watchEgressNetworkPolicies() {
	funcs := common.InformerFuncs(&osdnv1.EgressNetworkPolicy{}, plugin.handleAddOrUpdateEgressNetworkPolicy, plugin.handleDeleteEgressNetworkPolicy)
	plugin.osdnInformers.Network().V1().EgressNetworkPolicies().Informer().AddEventHandler(funcs)
}

func (plugin *OsdnNode) handleAddOrUpdateEgressNetworkPolicy(obj, _ interface{}, eventType watch.EventType) {
	policy := obj.(*osdnv1.EgressNetworkPolicy)
	klog.V(5).Infof("Watch %s event for EgressNetworkPolicy %s/%s", eventType, policy.Namespace, policy.Name)

	plugin.handleEgressNetworkPolicy(policy, eventType)
}

func (plugin *OsdnNode) handleDeleteEgressNetworkPolicy(obj interface{}) {
	policy := obj.(*osdnv1.EgressNetworkPolicy)
	klog.V(5).Infof("Watch %s event for EgressNetworkPolicy %s/%s", watch.Deleted, policy.Namespace, policy.Name)

	plugin.handleEgressNetworkPolicy(policy, watch.Deleted)
}

func (plugin *OsdnNode) handleEgressNetworkPolicy(policy *osdnv1.EgressNetworkPolicy, eventType watch.EventType) {
	vnid, err := plugin.policy.GetVNID(policy.Namespace)
	if err != nil {
		klog.Errorf("Could not find netid for namespace %q: %v", policy.Namespace, err)
		return
	}

	plugin.egressPoliciesLock.Lock()
	defer plugin.egressPoliciesLock.Unlock()

	policies := plugin.egressPolicies[vnid]
	for i, oldPolicy := range policies {
		if oldPolicy.UID == policy.UID {
			policies = append(policies[:i], policies[i+1:]...)
			plugin.egressDNS.Delete(oldPolicy)
			break
		}
	}

	if eventType != watch.Deleted && len(policy.Spec.Egress) > 0 {
		policies = append(policies, *policy)
		plugin.egressDNS.Add(*policy)
	}
	plugin.egressPolicies[vnid] = policies

	plugin.updateEgressNetworkPolicyRules(vnid)
}

func (plugin *OsdnNode) UpdateEgressNetworkPolicyVNID(namespace string, oldVnid, newVnid uint32) {
	var policy *osdnv1.EgressNetworkPolicy

	plugin.egressPoliciesLock.Lock()
	defer plugin.egressPoliciesLock.Unlock()

	policies := plugin.egressPolicies[oldVnid]
	for i, oldPolicy := range policies {
		if oldPolicy.Namespace == namespace {
			policy = &oldPolicy
			plugin.egressPolicies[oldVnid] = append(policies[:i], policies[i+1:]...)
			plugin.updateEgressNetworkPolicyRules(oldVnid)
			break
		}
	}

	if policy != nil {
		plugin.egressPolicies[newVnid] = append(plugin.egressPolicies[newVnid], *policy)
		plugin.updateEgressNetworkPolicyRules(newVnid)
	}
}

func (plugin *OsdnNode) syncEgressDNSPolicyRules() {
	go utilwait.Forever(plugin.egressDNS.Sync, 0)

	for {
		policyUpdates := <-plugin.egressDNS.Updates
		for _, policyUpdate := range policyUpdates {
			klog.V(5).Infof("Egress dns sync: updating policy: %v", policyUpdate.UID)
			vnid, err := plugin.policy.GetVNID(policyUpdate.Namespace)
			if err != nil {
				klog.Warningf("Could not find netid for namespace %q: %v", policyUpdate.Namespace, err)
				continue
			}

			func() {
				plugin.egressPoliciesLock.Lock()
				defer plugin.egressPoliciesLock.Unlock()

				plugin.updateEgressNetworkPolicyRules(vnid)
			}()
		}
	}
}
