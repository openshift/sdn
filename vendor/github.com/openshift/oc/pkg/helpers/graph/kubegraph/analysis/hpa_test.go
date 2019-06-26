package analysis

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta/testrestmapper"
	"k8s.io/apimachinery/pkg/runtime"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/openshift/api"
	appsgraph "github.com/openshift/oc/pkg/helpers/graph/appsgraph"
	osgraph "github.com/openshift/oc/pkg/helpers/graph/genericgraph"
	osgraphtest "github.com/openshift/oc/pkg/helpers/graph/genericgraph/test"
	"github.com/openshift/oc/pkg/helpers/graph/kubegraph"
)

func TestHPAMissingCPUTargetError(t *testing.T) {
	g, _, err := osgraphtest.BuildGraph("./../../../graph/genericgraph/test/hpa-missing-cpu-target.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	markers := FindHPASpecsMissingCPUTargets(g, osgraph.DefaultNamer)
	if len(markers) != 1 {
		t.Fatalf("expected to find one HPA spec missing a CPU target, got %d", len(markers))
	}

	if actual, expected := markers[0].Severity, osgraph.ErrorSeverity; actual != expected {
		t.Errorf("expected HPA missing CPU target to be %v, got %v", expected, actual)
	}

	if actual, expected := markers[0].Key, HPAMissingCPUTargetError; actual != expected {
		t.Errorf("expected marker type %v, got %v", expected, actual)
	}

	patchString := `-p '{"spec":{"targetCPUUtilizationPercentage": 80}}'`
	if !strings.HasSuffix(string(markers[0].Suggestion), patchString) {
		t.Errorf("expected suggestion to end with patch JSON path, got %q", markers[0].Suggestion)
	}
}

func TestHPAMissingScaleRefError(t *testing.T) {
	g, _, err := osgraphtest.BuildGraph("./../../../graph/genericgraph/test/hpa-missing-scale-ref.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	markers := FindHPASpecsMissingScaleRefs(g, osgraph.DefaultNamer)
	if len(markers) != 1 {
		t.Fatalf("expected to find one HPA spec missing a scale ref, got %d", len(markers))
	}

	if actual, expected := markers[0].Severity, osgraph.ErrorSeverity; actual != expected {
		t.Errorf("expected HPA missing scale ref to be %v, got %v", expected, actual)
	}

	if actual, expected := markers[0].Key, HPAMissingScaleRefError; actual != expected {
		t.Errorf("expected marker type %v, got %v", expected, actual)
	}
}

func TestOverlappingHPAsWarning(t *testing.T) {
	g, _, err := osgraphtest.BuildGraph("./../../../graph/genericgraph/test/overlapping-hpas.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scheme := runtime.NewScheme()
	kubernetesscheme.AddToScheme(scheme)
	api.Install(scheme)
	kubegraph.AddHPAScaleRefEdges(g, testrestmapper.TestOnlyStaticRESTMapper(scheme))
	appsgraph.AddAllDeploymentConfigsDeploymentEdges(g)

	markers := FindOverlappingHPAs(g, osgraph.DefaultNamer)
	if len(markers) != 8 {
		t.Fatalf("expected to find eight overlapping HPA markers, got %d", len(markers))
	}

	for _, marker := range markers {
		if actual, expected := marker.Severity, osgraph.WarningSeverity; actual != expected {
			t.Errorf("expected overlapping HPAs to be %v, got %v", expected, actual)
		}

		if actual, expected := marker.Key, HPAOverlappingScaleRefWarning; actual != expected {
			t.Errorf("expected marker type %v, got %v", expected, actual)
		}
	}
}

func TestOverlappingLegacyHPAsWarning(t *testing.T) {
	g, _, err := osgraphtest.BuildGraph("./../../../graph/genericgraph/test/overlapping-hpas-legacy.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scheme := runtime.NewScheme()
	kubernetesscheme.AddToScheme(scheme)
	api.Install(scheme)
	kubegraph.AddHPAScaleRefEdges(g, testrestmapper.TestOnlyStaticRESTMapper(scheme))
	appsgraph.AddAllDeploymentConfigsDeploymentEdges(g)

	markers := FindOverlappingHPAs(g, osgraph.DefaultNamer)
	if len(markers) != 8 {
		t.Fatalf("expected to find eight overlapping HPA markers, got %d", len(markers))
	}

	for _, marker := range markers {
		if actual, expected := marker.Severity, osgraph.WarningSeverity; actual != expected {
			t.Errorf("expected overlapping HPAs to be %v, got %v", expected, actual)
		}

		if actual, expected := marker.Key, HPAOverlappingScaleRefWarning; actual != expected {
			t.Errorf("expected marker type %v, got %v", expected, actual)
		}
	}
}
