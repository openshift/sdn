package policy

import (
	"testing"

	"k8s.io/apimachinery/pkg/labels"

	buildv1 "github.com/openshift/api/build/v1"
)

func TestSerialLatestOnlyIsRunnableNewBuilds(t *testing.T) {
	allNewBuilds := []buildv1.Build{
		addBuild("build-1", "sample-bc", buildv1.BuildPhaseNew, buildv1.BuildRunPolicySerialLatestOnly),
		addBuild("build-2", "sample-bc", buildv1.BuildPhaseNew, buildv1.BuildRunPolicySerialLatestOnly),
		addBuild("build-3", "sample-bc", buildv1.BuildPhaseNew, buildv1.BuildRunPolicySerialLatestOnly),
	}
	client := newTestClient(allNewBuilds...)
	lister := &fakeBuildLister{client}
	policy := SerialLatestOnlyPolicy{BuildLister: lister, BuildUpdater: client}
	runnableBuilds := []string{
		"build-1",
	}
	shouldRun := func(name string) bool {
		for _, b := range runnableBuilds {
			if b == name {
				return true
			}
		}
		return false
	}
	shouldNotRun := func(name string) bool {
		return !shouldRun(name)
	}
	for _, build := range allNewBuilds {
		runnable, err := policy.IsRunnable(&build)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if runnable && shouldNotRun(build.Name) {
			t.Errorf("%s should not be runnable", build.Name)
		}
		if !runnable && shouldRun(build.Name) {
			t.Errorf("%s should be runnable, it is not", build.Name)
		}
	}
	builds, err := lister.List(labels.Everything())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !builds[1].Status.Cancelled {
		t.Errorf("expected build-2 to be cancelled")
	}
}

func TestSerialLatestOnlyIsRunnableMixedRunning(t *testing.T) {
	allNewBuilds := []buildv1.Build{
		addBuild("build-1", "sample-bc", buildv1.BuildPhaseComplete, buildv1.BuildRunPolicySerialLatestOnly),
		addBuild("build-2", "sample-bc", buildv1.BuildPhaseCancelled, buildv1.BuildRunPolicySerialLatestOnly),
		addBuild("build-3", "sample-bc", buildv1.BuildPhaseRunning, buildv1.BuildRunPolicySerialLatestOnly),
		addBuild("build-4", "sample-bc", buildv1.BuildPhaseNew, buildv1.BuildRunPolicySerialLatestOnly),
	}
	client := newTestClient(allNewBuilds...)
	lister := &fakeBuildLister{client}
	policy := SerialLatestOnlyPolicy{BuildLister: lister}
	for _, build := range allNewBuilds {
		runnable, err := policy.IsRunnable(&build)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if runnable {
			t.Errorf("%s should not be runnable", build.Name)
		}
	}
	builds, err := lister.List(labels.Everything())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if builds[0].Status.Cancelled {
		t.Errorf("expected build-1 is complete and should not be cancelled")
	}
	if builds[2].Status.Cancelled {
		t.Errorf("expected build-3 is running and should not be cancelled")
	}
	if builds[3].Status.Cancelled {
		t.Errorf("expected build-4 will run next and should not be cancelled")
	}
}

func TestSerialLatestOnlyIsRunnableBuildsWithErrors(t *testing.T) {
	builds := []buildv1.Build{
		addBuild("build-1", "sample-bc", buildv1.BuildPhaseNew, buildv1.BuildRunPolicySerialLatestOnly),
		addBuild("build-2", "sample-bc", buildv1.BuildPhaseNew, buildv1.BuildRunPolicySerialLatestOnly),
	}

	// The build-1 will lack required labels
	builds[0].ObjectMeta.Labels = map[string]string{}

	// The build-2 will lack the build number annotation
	builds[1].ObjectMeta.Annotations = map[string]string{}

	client := newTestClient(builds...)
	policy := SerialLatestOnlyPolicy{BuildLister: &fakeBuildLister{client}}

	ok, err := policy.IsRunnable(&builds[0])
	if !ok || err != nil {
		t.Errorf("expected build to be runnable, got %v, error: %v", ok, err)
	}

	// No type-check as this error is returned as kerrors.aggregate
	if _, err := policy.IsRunnable(&builds[1]); err == nil {
		t.Errorf("expected error for build-2")
	}
}
