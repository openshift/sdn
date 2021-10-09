package master

import (
	"testing"

	"k8s.io/apimachinery/pkg/watch"

	osdnv1 "github.com/openshift/api/network/v1"
)

func Test_handleAddUpdate(t *testing.T) {
	tests := []struct {
		testCaseName          string
		initialRulesCount     int
		expectedRulesCount    int
		initialPoliciesCount  int
		expectedPoliciesCount int
		current               *osdnv1.EgressNetworkPolicy
		old                   *osdnv1.EgressNetworkPolicy
		event                 watch.EventType
	}{
		{
			testCaseName:          "should set egress rule count for add handle with non-zero rules",
			expectedRulesCount:    3,
			expectedPoliciesCount: 1,
			current:               generateNPWithRules(3),
			old:                   nil,
			event:                 watch.Added,
		},
		{
			testCaseName:          "should not alter egress rule count for add handle with zero rules",
			expectedRulesCount:    0,
			expectedPoliciesCount: 1,
			current:               generateNPWithRules(0),
			old:                   nil,
			event:                 watch.Added,
		},
		{
			testCaseName:          "should increase egress rule count for update handle with increased rules count",
			expectedRulesCount:    1,
			expectedPoliciesCount: 0,
			current:               generateNPWithRules(3),
			old:                   generateNPWithRules(2),
			event:                 watch.Modified,
		},
		{
			testCaseName:          "should not alter egress rule count for update handle with unchanged rules count",
			expectedRulesCount:    0,
			initialPoliciesCount:  5,
			expectedPoliciesCount: 5,
			current:               generateNPWithRules(0),
			old:                   generateNPWithRules(0),
			event:                 watch.Modified,
		},
		{
			testCaseName:          "should decrease egress rule count for update handle with decreased rules count",
			initialRulesCount:     4,
			expectedRulesCount:    3,
			initialPoliciesCount:  1,
			expectedPoliciesCount: 1,
			current:               generateNPWithRules(3),
			old:                   generateNPWithRules(4),
			event:                 watch.Modified,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testCaseName, func(t *testing.T) {
			pm := newEgressNetworkPolicyManager()
			pm.ruleCount = tc.initialRulesCount
			pm.policyCount = tc.initialPoliciesCount
			pm.handleAddUpdate(tc.current, tc.old, tc.event)
			if pm.ruleCount != tc.expectedRulesCount {
				t.Errorf("handleAddUpdate(): got %d egress network policy rules, expected %d egress network policy rules",
					pm.ruleCount, tc.expectedRulesCount)
			}
			if pm.policyCount != tc.expectedPoliciesCount {
				t.Errorf("handleAddUpdate(): got %d egress network policies, expected %d egress network policies",
					pm.policyCount, tc.expectedPoliciesCount)
			}
		})
	}
}

func Test_handleDelete(t *testing.T) {
	tests := []struct {
		testCaseName         string
		initialRulesCount    int
		expectedRulesCount   int
		initialPoliciesCount int
		obj                  *osdnv1.EgressNetworkPolicy
	}{
		{
			testCaseName:         "should not alter egress rule count for delete handle with zero rules",
			expectedRulesCount:   0,
			initialPoliciesCount: 1,
			obj:                  generateNPWithRules(0),
		},
		{
			testCaseName:         "should set egress rule count for delete handle non-zero rules",
			expectedRulesCount:   1,
			initialPoliciesCount: 5,
			initialRulesCount:    5,
			obj:                  generateNPWithRules(4),
		},
	}

	for _, tc := range tests {
		t.Run(tc.testCaseName, func(t *testing.T) {
			pm := newEgressNetworkPolicyManager()
			pm.ruleCount = tc.initialRulesCount
			pm.policyCount = tc.initialPoliciesCount
			pm.handleDelete(tc.obj)
			if pm.ruleCount != tc.expectedRulesCount {
				t.Errorf("handleDelete(): got %d, expected %d", pm.ruleCount, tc.expectedRulesCount)
			}
			if pm.policyCount != (tc.initialPoliciesCount - 1) {
				t.Errorf("handleDelete(): got %d egress network policies, expected %d egress network policy",
					pm.policyCount, tc.initialPoliciesCount-1)
			}
		})
	}
}

func generateNPWithRules(amount int) *osdnv1.EgressNetworkPolicy {
	prs := make([]osdnv1.EgressNetworkPolicyRule, amount)
	for i := 0; i < amount; i++ {
		prs[i] = osdnv1.EgressNetworkPolicyRule{}
	}
	return &osdnv1.EgressNetworkPolicy{
		Spec: osdnv1.EgressNetworkPolicySpec{
			Egress: prs,
		},
	}
}
