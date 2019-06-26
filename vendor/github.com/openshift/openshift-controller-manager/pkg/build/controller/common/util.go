package common

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	buildv1 "github.com/openshift/api/build/v1"
	buildclientv1 "github.com/openshift/client-go/build/clientset/versioned/typed/build/v1"
	buildlisterv1 "github.com/openshift/client-go/build/listers/build/v1"
	sharedbuildutil "github.com/openshift/library-go/pkg/build/buildutil"
	"github.com/openshift/library-go/pkg/build/envresolve"
	"github.com/openshift/openshift-controller-manager/pkg/build/buildutil"
	"github.com/openshift/openshift-controller-manager/pkg/build/controller/common/internal/expansion"
)

type ByCreationTimestamp []*buildv1.Build

func (b ByCreationTimestamp) Len() int {
	return len(b)
}

func (b ByCreationTimestamp) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b ByCreationTimestamp) Less(i, j int) bool {
	return !b[j].CreationTimestamp.Time.After(b[i].CreationTimestamp.Time)
}

// HandleBuildPruning handles the deletion of old successful and failed builds
// based on settings in the BuildConfig.
func HandleBuildPruning(buildConfigName string, namespace string, buildLister buildlisterv1.BuildLister, buildConfigGetter buildlisterv1.BuildConfigLister, buildDeleter buildclientv1.BuildsGetter) error {
	klog.V(4).Infof("Handling build pruning for %s/%s", namespace, buildConfigName)

	buildConfig, err := buildConfigGetter.BuildConfigs(namespace).Get(buildConfigName)
	if err != nil {
		return err
	}

	var buildsToDelete []*buildv1.Build
	var errList []error

	if buildConfig.Spec.SuccessfulBuildsHistoryLimit != nil {
		successfulBuilds, err := buildutil.BuildConfigBuildsFromLister(buildLister, namespace, buildConfigName, func(build *buildv1.Build) bool { return build.Status.Phase == buildv1.BuildPhaseComplete })
		if err != nil {
			return err
		}
		sort.Sort(ByCreationTimestamp(successfulBuilds))

		successfulBuildsHistoryLimit := int(*buildConfig.Spec.SuccessfulBuildsHistoryLimit)
		klog.V(5).Infof("Current successful builds: %v, SuccessfulBuildsHistoryLimit: %v", len(successfulBuilds), successfulBuildsHistoryLimit)
		if len(successfulBuilds) > successfulBuildsHistoryLimit {
			klog.V(5).Infof("Preparing to prune %v of %v successful builds", len(successfulBuilds)-successfulBuildsHistoryLimit, len(successfulBuilds))
			buildsToDelete = append(buildsToDelete, successfulBuilds[successfulBuildsHistoryLimit:]...)
		}
	}

	if buildConfig.Spec.FailedBuildsHistoryLimit != nil {
		failedBuilds, err := buildutil.BuildConfigBuildsFromLister(buildLister, namespace, buildConfigName, func(build *buildv1.Build) bool {
			return build.Status.Phase == buildv1.BuildPhaseFailed || build.Status.Phase == buildv1.BuildPhaseCancelled || build.Status.Phase == buildv1.BuildPhaseError
		})
		if err != nil {
			return err
		}
		sort.Sort(ByCreationTimestamp(failedBuilds))

		failedBuildsHistoryLimit := int(*buildConfig.Spec.FailedBuildsHistoryLimit)
		klog.V(5).Infof("Current failed builds: %v, FailedBuildsHistoryLimit: %v", len(failedBuilds), failedBuildsHistoryLimit)
		if len(failedBuilds) > failedBuildsHistoryLimit {
			klog.V(5).Infof("Preparing to prune %v of %v failed builds", len(failedBuilds)-failedBuildsHistoryLimit, len(failedBuilds))
			buildsToDelete = append(buildsToDelete, failedBuilds[failedBuildsHistoryLimit:]...)
		}
	}

	for i, b := range buildsToDelete {
		klog.V(4).Infof("Pruning build: %s/%s", b.Namespace, b.Name)
		if err := buildDeleter.Builds(b.Namespace).Delete(buildsToDelete[i].Name, &metav1.DeleteOptions{}); err != nil {
			errList = append(errList, err)
		}
	}
	if errList != nil {
		return kerrors.NewAggregate(errList)
	}

	return nil
}

func SetBuildPodNameAnnotation(build *buildv1.Build, podName string) {
	if build.Annotations == nil {
		build.Annotations = map[string]string{}
	}
	build.Annotations[buildv1.BuildPodNameAnnotation] = podName
}

func HasBuildPodNameAnnotation(build *buildv1.Build) bool {
	if build.Annotations == nil {
		return false
	}
	_, hasAnnotation := build.Annotations[buildv1.BuildPodNameAnnotation]
	return hasAnnotation
}

// ErrEnvVarResolver is an error type for build environment resolution errors
type ErrEnvVarResolver struct {
	message kerrors.Aggregate
}

// Error returns a string representation of the error
func (e ErrEnvVarResolver) Error() string {
	return fmt.Sprintf("%v", e.message)
}

// ResolveValueFrom resolves valueFrom references in build environment variables
// including references to existing environment variables, jsonpath references to
// the build object, secrets, and configmaps.
// The build.Strategy.BuildStrategy.Env is replaced with the resolved references.
func ResolveValueFrom(pod *corev1.Pod, client kubernetes.Interface) error {
	var outputEnv []corev1.EnvVar
	var allErrs []error

	build, err := GetBuildFromPod(pod)
	if err != nil {
		return nil
	}

	mapEnvs := map[string]string{}
	mapping := expansion.MappingFuncFor(mapEnvs)
	inputEnv := sharedbuildutil.GetBuildEnv(build)
	store := envresolve.NewResourceStore()

	for _, e := range inputEnv {
		var value string
		var err error

		if e.Value != "" {
			value = expansion.Expand(e.Value, mapping)
		} else if e.ValueFrom != nil {
			value, err = envresolve.GetEnvVarRefValue(client, build.Namespace, store, e.ValueFrom, build, nil)
			if err != nil {
				allErrs = append(allErrs, err)
				continue
			}
		}

		outputEnv = append(outputEnv, corev1.EnvVar{Name: e.Name, Value: value})
		mapEnvs[e.Name] = value
	}

	if len(allErrs) > 0 {
		return ErrEnvVarResolver{utilerrors.NewAggregate(allErrs)}
	}

	sharedbuildutil.SetBuildEnv(build, outputEnv)
	return SetBuildInPod(pod, build)
}
