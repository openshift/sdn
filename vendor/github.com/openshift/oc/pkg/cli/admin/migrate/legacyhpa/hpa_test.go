package legacyhpa

import (
	"testing"

	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDefaultMigrations(t *testing.T) {
	testCases := []struct {
		name   string
		input  metav1.TypeMeta
		output metav1.TypeMeta
	}{
		{
			name:   "legacy-dc",
			input:  metav1.TypeMeta{Kind: "DeploymentConfig", APIVersion: "v1"},
			output: metav1.TypeMeta{Kind: "DeploymentConfig", APIVersion: "apps.openshift.io/v1"},
		},
		{
			name:   "console-dc",
			input:  metav1.TypeMeta{Kind: "DeploymentConfig", APIVersion: "extensions/v1beta1"},
			output: metav1.TypeMeta{Kind: "DeploymentConfig", APIVersion: "apps.openshift.io/v1"},
		},
		{
			name:   "console-rc",
			input:  metav1.TypeMeta{Kind: "ReplicationController", APIVersion: "extensions/v1beta1"},
			output: metav1.TypeMeta{Kind: "ReplicationController", APIVersion: "v1"},
		},
		{
			name:   "console-deploy",
			input:  metav1.TypeMeta{Kind: "Deployment", APIVersion: "extensions/v1beta1"},
			output: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		},
		{
			name:   "console-rs",
			input:  metav1.TypeMeta{Kind: "ReplicaSet", APIVersion: "extensions/v1beta1"},
			output: metav1.TypeMeta{Kind: "ReplicaSet", APIVersion: "apps/v1"},
		},
		{
			name:   "ok-dc",
			input:  metav1.TypeMeta{Kind: "DeploymentConfig", APIVersion: "apps.openshift.io/v1"},
			output: metav1.TypeMeta{Kind: "DeploymentConfig", APIVersion: "apps.openshift.io/v1"},
		},
		{
			name:   "other",
			input:  metav1.TypeMeta{Kind: "Cheddar", APIVersion: "cheese/v1alpha1"},
			output: metav1.TypeMeta{Kind: "Cheddar", APIVersion: "cheese/v1alpha1"},
		},
	}

	opts := MigrateLegacyHPAOptions{
		finalVersionKinds: defaultMigrations,
	}

	for _, tc := range testCases {
		tc := tc // copy the iteration variable to a non-iteration memory location
		t.Run(tc.name, func(t *testing.T) {
			oldHPA := &autoscalingv1.HorizontalPodAutoscaler{
				Spec: autoscalingv1.HorizontalPodAutoscalerSpec{
					ScaleTargetRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: tc.input.APIVersion,
						Kind:       tc.input.Kind,
						Name:       tc.name,
					},
				},
			}

			reporter, err := opts.checkAndTransform(oldHPA)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			expectedChanged := tc.input != tc.output
			if reporter.Changed() != expectedChanged {
				indicator := ""
				if expectedChanged {
					indicator = " not"
				}
				t.Errorf("expected the HPA%s to have been changed, but it had%s", indicator, indicator)
			}
			newVersionKind := metav1.TypeMeta{
				APIVersion: oldHPA.Spec.ScaleTargetRef.APIVersion,
				Kind:       oldHPA.Spec.ScaleTargetRef.Kind,
			}
			if newVersionKind != tc.output {
				t.Errorf("expected the HPA to be updated to %v, yet it ended up as %v", tc.output, newVersionKind)
			}
		})

	}
}
