package policy

import (
	"time"

	"k8s.io/klog"

	"k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	buildv1 "github.com/openshift/api/build/v1"
	buildclientv1 "github.com/openshift/client-go/build/clientset/versioned/typed/build/v1"
	buildlister "github.com/openshift/client-go/build/listers/build/v1"
	sharedbuildutil "github.com/openshift/library-go/pkg/build/buildutil"
	buildutil "github.com/openshift/openshift-controller-manager/pkg/build/buildutil"
)

// SerialLatestOnlyPolicy implements the RunPolicy interface. This variant of
// the serial build policy makes sure that builds are executed in same order as
// they were created, but when a new build is created, the previous, queued
// build is cancelled, always making the latest created build run as next. This
// will produce consistent results, but might not suit the CI/CD flow where user
// expect that every commit is built.
type SerialLatestOnlyPolicy struct {
	BuildUpdater buildclientv1.BuildsGetter
	BuildLister  buildlister.BuildLister
}

// IsRunnable implements the RunPolicy interface.
// Calling this function on a build mean that any previous build that is in
// 'new' phase will be automatically cancelled. This will also cancel any
// "serial" build (when you changed the build config run policy on-the-fly).
func (s *SerialLatestOnlyPolicy) IsRunnable(build *buildv1.Build) (bool, error) {
	bcName := sharedbuildutil.ConfigNameForBuild(build)
	if len(bcName) == 0 {
		return true, nil
	}
	if err := kerrors.NewAggregate(s.cancelPreviousBuilds(build)); err != nil {
		return false, err
	}
	nextBuilds, runningBuilds, err := GetNextConfigBuild(s.BuildLister, build.Namespace, bcName)
	if err != nil || runningBuilds {
		return false, err
	}
	return len(nextBuilds) == 1 && nextBuilds[0].Name == build.Name, err
}

// Handles returns true for the build run serial latest only policy
func (s *SerialLatestOnlyPolicy) Handles(policy buildv1.BuildRunPolicy) bool {
	return policy == buildv1.BuildRunPolicySerialLatestOnly
}

// cancelPreviousBuilds cancels all queued builds that have the build sequence number
// lower than the given build. It retries the cancellation in case of conflict.
func (s *SerialLatestOnlyPolicy) cancelPreviousBuilds(build *buildv1.Build) []error {
	bcName := sharedbuildutil.ConfigNameForBuild(build)
	if len(bcName) == 0 {
		return []error{}
	}
	currentBuildNumber, err := buildNumber(build)
	if err != nil {
		return []error{NewNoBuildNumberAnnotationError(build)}
	}
	builds, err := buildutil.BuildConfigBuildsFromLister(s.BuildLister, build.Namespace, bcName, func(b *buildv1.Build) bool {
		// Do not cancel the complete builds, builds that were already cancelled, or
		// running builds.
		if buildutil.IsBuildComplete(b) || b.Status.Phase == buildv1.BuildPhaseRunning {
			return false
		}

		// Prevent race-condition when there is a newer build than this and we don't
		// want to cancel it. The HandleBuild() function that runs for that build
		// will cancel this build.
		buildNumber, _ := buildNumber(b)
		return buildNumber < currentBuildNumber
	})
	if err != nil {
		return []error{err}
	}
	var result = []error{}
	for _, b := range builds {
		err := wait.Poll(500*time.Millisecond, 5*time.Second, func() (bool, error) {
			b = b.DeepCopy()
			b.Status.Cancelled = true
			_, err := s.BuildUpdater.Builds(b.Namespace).Update(b)
			if err != nil && errors.IsConflict(err) {
				klog.V(5).Infof("Error cancelling build %s/%s: %v (will retry)", b.Namespace, b.Name, err)
				return false, nil
			}
			return true, err
		})
		if err != nil {
			result = append(result, err)
		}
	}
	return result
}
