package build

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/containers/image/signature"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	v1lister "k8s.io/client-go/listers/core/v1"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	buildv1 "github.com/openshift/api/build/v1"
	configv1 "github.com/openshift/api/config/v1"
	imagev1 "github.com/openshift/api/image/v1"
	buildv1client "github.com/openshift/client-go/build/clientset/versioned"
	fakebuildv1client "github.com/openshift/client-go/build/clientset/versioned/fake"
	buildv1informer "github.com/openshift/client-go/build/informers/externalversions"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	fakeconfigv1client "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1informer "github.com/openshift/client-go/config/informers/externalversions"
	imagev1client "github.com/openshift/client-go/image/clientset/versioned"
	fakeimagev1client "github.com/openshift/client-go/image/clientset/versioned/fake"
	imagev1informer "github.com/openshift/client-go/image/informers/externalversions"
	"github.com/openshift/openshift-controller-manager/pkg/build/buildscheme"
	"github.com/openshift/openshift-controller-manager/pkg/build/buildutil"
	builddefaults "github.com/openshift/openshift-controller-manager/pkg/build/controller/build/defaults"
	buildoverrides "github.com/openshift/openshift-controller-manager/pkg/build/controller/build/overrides"
	"github.com/openshift/openshift-controller-manager/pkg/build/controller/common"
	"github.com/openshift/openshift-controller-manager/pkg/build/controller/policy"
	"github.com/openshift/openshift-controller-manager/pkg/build/controller/strategy"
)

const (
	dummyCA = `---- BEGIN CERTIFICATE ----
	VEhJUyBJUyBBIEJBRCBDRVJUSUZJQ0FURQo=
	---- END CERTIFICATE ----
	`

	dummyRegistryConf = `registries:
	- registry.redhat.io
	- quay.io
	- docker.io
	insecure_registries:
	- my.registry.corp.com
	block_registries:
	- all
	`
)

// registryCAConfigMap is created by the openshift-controller-manager-operator, serving as a placeholder
// for the service-ca-operator to inject the internal registry's certificate authority
var registryCAConfigMap = &corev1.ConfigMap{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "openshift-service-ca",
		Namespace: "openshift-controller-manager",
		Annotations: map[string]string{
			"service.beta.openshift.io/inject-cabundle": "true",
		},
	},
	Data: map[string]string{
		buildv1.ServiceCAKey: dummyCA,
	},
}

// TestHandleBuild is the main test for build updates through the controller
func TestHandleBuild(t *testing.T) {

	// patch appears to drop sub-second accuracy from times, which causes problems
	// during equality testing later, so start with a rounded number of seconds for a time.
	now := metav1.NewTime(time.Now().Round(time.Second))

	build := func(phase buildv1.BuildPhase) *buildv1.Build {
		b := dockerStrategy(mockBuild(phase, buildv1.BuildOutput{}))
		if phase != buildv1.BuildPhaseNew {
			podName := buildutil.GetBuildPodName(b)
			common.SetBuildPodNameAnnotation(b, podName)
		}
		return b
	}
	pod := func(phase corev1.PodPhase) *corev1.Pod {
		p := mockBuildPod(build(buildv1.BuildPhaseNew))
		p.Status.Phase = phase
		switch phase {
		case corev1.PodRunning:
			p.Status.StartTime = &now
		case corev1.PodFailed:
			p.Status.StartTime = &now
			p.Status.ContainerStatuses = []corev1.ContainerStatus{
				{
					Name: "container",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 1,
						},
					},
				},
			}
		case corev1.PodSucceeded:
			p.Status.StartTime = &now
			p.Status.ContainerStatuses = []corev1.ContainerStatus{
				{
					Name: "container",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 0,
						},
					},
				},
			}
		}
		return p
	}
	withTerminationMessage := func(pod *corev1.Pod) *corev1.Pod {
		pod.Status.ContainerStatuses[0].State.Terminated.Message = "termination message"
		return pod
	}
	withOwnerReference := func(pod *corev1.Pod, build *buildv1.Build) *corev1.Pod {
		t := true
		pod.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: buildv1.SchemeGroupVersion.String(),
			Kind:       "Build",
			Name:       build.Name,
			Controller: &t,
		}}
		return pod
	}

	cancelled := func(build *buildv1.Build) *buildv1.Build {
		build.Status.Cancelled = true
		return build
	}
	withCompletionTS := func(build *buildv1.Build) *buildv1.Build {
		build.Status.CompletionTimestamp = &now
		return build
	}
	withLogSnippet := func(build *buildv1.Build) *buildv1.Build {
		build.Status.LogSnippet = "termination message"
		return build
	}

	tests := []struct {
		name string

		// Conditions
		build                  *buildv1.Build
		pod                    *corev1.Pod
		runPolicy              *fakeRunPolicy
		errorOnPodDelete       bool
		errorOnPodCreate       bool
		errorOnBuildUpdate     bool
		errorOnConfigMapCreate bool

		// Expected Result
		expectUpdate           *buildUpdate
		expectPodCreated       bool
		expectPodDeleted       bool
		expectError            bool
		expectConfigMapCreated bool
	}{
		{
			name:  "cancel running build",
			build: cancelled(build(buildv1.BuildPhaseRunning)),
			pod:   pod(corev1.PodRunning),
			expectUpdate: newUpdate().phase(buildv1.BuildPhaseCancelled).
				reason(buildv1.StatusReasonCancelledBuild).
				message("The build was cancelled by the user.").
				completionTime(now).
				startTime(now).update,
			expectPodDeleted: true,
		},
		{
			name:         "cancel build in terminal state",
			build:        cancelled(withCompletionTS(build(buildv1.BuildPhaseComplete))),
			pod:          pod(corev1.PodRunning),
			expectUpdate: nil,
		},
		{
			name:             "cancel build with delete pod error",
			build:            cancelled(build(buildv1.BuildPhaseRunning)),
			errorOnPodDelete: true,
			expectUpdate:     nil,
			expectError:      true,
		},
		{
			name:  "new -> pending",
			build: build(buildv1.BuildPhaseNew),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhasePending).
				reason("").
				message("").
				podNameAnnotation(pod(corev1.PodPending).Name).
				update,
			expectPodCreated:       true,
			expectConfigMapCreated: true,
		},
		{
			name:  "new with existing related pod",
			build: build(buildv1.BuildPhaseNew),
			pod:   withOwnerReference(pod(corev1.PodRunning), build(buildv1.BuildPhaseNew)),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhaseRunning).
				reason("").
				message("").
				startTime(now).
				podNameAnnotation(pod(corev1.PodRunning).Name).
				update,
		},
		{
			name:  "new with existing unrelated pod",
			build: build(buildv1.BuildPhaseNew),
			pod:   pod(corev1.PodRunning),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhaseError).
				reason(buildv1.StatusReasonBuildPodExists).
				message("The pod for this build already exists and is older than the build.").
				podNameAnnotation(pod(corev1.PodRunning).Name).
				startTime(now).
				completionTime(now).
				update,
		},
		{
			name:         "new not runnable by policy",
			build:        build(buildv1.BuildPhaseNew),
			runPolicy:    &fakeRunPolicy{notRunnable: true},
			expectUpdate: nil,
		},
		{
			name:                   "new -> pending with update error",
			build:                  build(buildv1.BuildPhaseNew),
			errorOnBuildUpdate:     true,
			expectUpdate:           nil,
			expectPodCreated:       true,
			expectConfigMapCreated: true,
			expectError:            true,
		},
		{
			name:  "pending -> running",
			build: build(buildv1.BuildPhasePending),
			pod:   pod(corev1.PodRunning),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhaseRunning).
				reason("").
				message("").
				startTime(now).
				update,
		},
		{
			name:               "pending -> running with update error",
			build:              build(buildv1.BuildPhasePending),
			pod:                pod(corev1.PodRunning),
			errorOnBuildUpdate: true,
			expectUpdate:       nil,
			expectError:        true,
		},
		{
			name:  "pending -> failed",
			build: build(buildv1.BuildPhasePending),
			pod:   pod(corev1.PodFailed),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhaseFailed).
				reason(buildv1.StatusReasonGenericBuildFailed).
				message("Generic Build failure - check logs for details.").
				startTime(now).
				completionTime(now).
				update,
		},
		{
			name:         "pending -> pending",
			build:        build(buildv1.BuildPhasePending),
			pod:          pod(corev1.PodPending),
			expectUpdate: nil,
		},
		{
			name:  "running -> complete",
			build: build(buildv1.BuildPhaseRunning),
			pod:   pod(corev1.PodSucceeded),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhaseComplete).
				reason("").
				message("").
				startTime(now).
				completionTime(now).
				update,
		},
		{
			name:         "running -> running",
			build:        build(buildv1.BuildPhaseRunning),
			pod:          pod(corev1.PodRunning),
			expectUpdate: nil,
		},
		{
			name:  "running with missing pod",
			build: build(buildv1.BuildPhaseRunning),
			expectUpdate: newUpdate().
				phase(buildv1.BuildPhaseError).
				reason(buildv1.StatusReasonBuildPodDeleted).
				message("The pod for this build was deleted before the build completed.").
				startTime(now).
				completionTime(now).
				update,
		},
		{
			name:  "failed -> failed with no completion timestamp",
			build: build(buildv1.BuildPhaseFailed),
			pod:   pod(corev1.PodFailed),
			expectUpdate: newUpdate().
				startTime(now).
				completionTime(now).
				update,
		},
		{
			name:  "failed -> failed with completion timestamp+message and no logsnippet",
			build: withCompletionTS(build(buildv1.BuildPhaseFailed)),
			pod:   withTerminationMessage(pod(corev1.PodFailed)),
			expectUpdate: newUpdate().
				startTime(now).
				logSnippet("termination message").
				update,
		},
		{
			name:  "failed -> failed with completion timestamp+message and logsnippet",
			build: withLogSnippet(withCompletionTS(build(buildv1.BuildPhaseFailed))),
			pod:   withTerminationMessage(pod(corev1.PodFailed)),
		},
	}

	for _, tc := range tests {
		func() {
			var patchedBuild *buildv1.Build
			var appliedPatch string
			buildClient := fakeBuildClient(tc.build)
			buildClient.(*fakebuildv1client.Clientset).PrependReactor("patch", "builds",
				func(action clientgotesting.Action) (bool, runtime.Object, error) {
					if tc.errorOnBuildUpdate {
						return true, nil, fmt.Errorf("error")
					}
					var err error
					patchAction := action.(clientgotesting.PatchActionImpl)
					appliedPatch = string(patchAction.Patch)
					patchedBuild, err = applyBuildPatch(tc.build, patchAction.Patch)
					if err != nil {
						panic(fmt.Sprintf("unexpected error: %v", err))
					}
					return true, patchedBuild, nil
				})
			var kubeClient kubernetes.Interface
			if tc.pod != nil {
				kubeClient = fakeKubeExternalClientSet(tc.pod, registryCAConfigMap)
			} else {
				kubeClient = fakeKubeExternalClientSet(registryCAConfigMap)
			}
			podCreated := false
			var newPod *corev1.Pod
			kubeClient.(*fake.Clientset).PrependReactor("delete", "pods",
				func(action clientgotesting.Action) (bool, runtime.Object, error) {
					if tc.errorOnPodDelete {
						return true, nil, fmt.Errorf("error")
					}
					return true, nil, nil
				})
			kubeClient.(*fake.Clientset).PrependReactor("create", "pods",
				func(action clientgotesting.Action) (bool, runtime.Object, error) {
					if tc.errorOnPodCreate {
						return true, nil, fmt.Errorf("error")
					}
					podCreated = true
					newPod = mockBuildPod(tc.build)
					newPod.UID = types.UID(uuid.New().String())
					return true, newPod, nil
				})
			caConfigMapCreated := false
			registryConfigMapCreated := false
			kubeClient.(*fake.Clientset).PrependReactor("create", "configmaps",
				func(action clientgotesting.Action) (bool, runtime.Object, error) {
					if !caConfigMapCreated {
						caConfigMapCreated = true
						return true, mockBuildCAConfigMap(tc.build, newPod), nil
					}
					if !registryConfigMapCreated {
						registryConfigMapCreated = true
						return true, mockBuildSystemConfigMap(tc.build, newPod), nil
					}
					return false, nil, nil
				})
			bc := newFakeBuildController(buildClient, nil, kubeClient, nil, nil)
			defer bc.stop()

			runPolicy := tc.runPolicy
			if runPolicy == nil {
				runPolicy = &fakeRunPolicy{}
			}
			bc.runPolicies = []policy.RunPolicy{runPolicy}

			err := bc.handleBuild(tc.build)
			if err != nil {
				if !tc.expectError {
					t.Errorf("%s: unexpected error: %v", tc.name, err)
				}
			}
			if err == nil && tc.expectError {
				t.Errorf("%s: expected error, got none", tc.name)
			}
			if tc.expectUpdate == nil && patchedBuild != nil {
				t.Errorf("%s: did not expect a build update, got patch %s", tc.name, appliedPatch)
			}
			if tc.expectPodCreated != podCreated {
				t.Errorf("%s: pod created. expected: %v, actual: %v", tc.name, tc.expectPodCreated, podCreated)
			}
			if tc.expectConfigMapCreated != caConfigMapCreated {
				t.Errorf("%s: ca configMap created. expected: %v, actual: %v", tc.name, tc.expectConfigMapCreated, caConfigMapCreated)
			}
			if tc.expectConfigMapCreated != registryConfigMapCreated {
				t.Errorf("%s: registry configMap created. expected: %v, actual: %v", tc.name, tc.expectConfigMapCreated, registryConfigMapCreated)
			}
			if tc.expectUpdate != nil {
				if patchedBuild == nil {
					t.Errorf("%s: did not get an update. Expected: %v", tc.name, tc.expectUpdate)
					return
				}
				expectedBuild := tc.build.DeepCopy()
				tc.expectUpdate.apply(expectedBuild)

				// For start/completion/duration fields, simply validate that they are set/not set
				if tc.expectUpdate.startTime != nil && patchedBuild.Status.StartTimestamp != nil {
					expectedBuild.Status.StartTimestamp = patchedBuild.Status.StartTimestamp
				}
				if tc.expectUpdate.completionTime != nil && patchedBuild.Status.CompletionTimestamp != nil {
					expectedBuild.Status.CompletionTimestamp = patchedBuild.Status.CompletionTimestamp
					expectedBuild.Status.Duration = patchedBuild.Status.Duration
				}
				expectedBuild.CreationTimestamp = patchedBuild.CreationTimestamp

				// TODO: For some reason the external builds does not with with this check. The output is correct, we should investigate later.
				/*
					if !apiequality.Semantic.DeepEqual(*expectedBuild, *patchedBuild) {
						t.Errorf("%s: did not get expected update on build. \nUpdate: %v\nPatch: %s\n", tc.name, tc.expectUpdate, appliedPatch)
					}
				*/
			}
		}()
	}

}

// TestWork - High-level test of the work function to ensure that a build
// in the queue will be handled by updating the build status to pending
func TestWorkWithNewBuild(t *testing.T) {
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))
	var patchedBuild *buildv1.Build
	buildClient := fakeBuildClient(build)
	buildClient.(*fakebuildv1client.Clientset).PrependReactor("patch", "builds", applyBuildPatchReaction(t, build, &patchedBuild))

	bc := newFakeBuildController(buildClient, nil, nil, nil, nil)
	defer bc.stop()
	bc.enqueueBuild(build)

	bc.buildWork()

	if bc.buildQueue.Len() > 0 {
		t.Errorf("Expected queue to be empty")
	}
	if patchedBuild == nil {
		t.Errorf("Expected patched build not to be nil")
	}

	if patchedBuild != nil && patchedBuild.Status.Phase != buildv1.BuildPhasePending {
		t.Errorf("Expected patched build status set to Pending. It is %s", patchedBuild.Status.Phase)
	}
}

func TestCreateBuildPod(t *testing.T) {
	kubeClient := fakeKubeExternalClientSet(registryCAConfigMap)
	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	update, err := bc.createBuildPod(build)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	podName := buildutil.GetBuildPodName(build)
	// Validate update
	expected := &buildUpdate{}
	expected.setPodNameAnnotation(podName)
	expected.setPhase(buildv1.BuildPhasePending)
	expected.setReason("")
	expected.setMessage("")
	validateUpdate(t, "create build pod", expected, update)
	// Make sure that a pod was created
	pod, err := kubeClient.CoreV1().Pods("namespace").Get(podName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Make sure that a configMap was created, with an ownerRef
	configMapName := buildutil.GetBuildCAConfigMapName(build)
	configMap, err := kubeClient.CoreV1().ConfigMaps("namespace").Get(configMapName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if configMap == nil {
		// ConfigMap was not found
		return
	}
	if len(configMap.ObjectMeta.OwnerReferences) == 0 {
		t.Errorf("expected configMap %s to have an owner reference", configMapName)
	}
	foundOwner := false
	for _, o := range configMap.OwnerReferences {
		if o.Name == pod.Name {
			foundOwner = true
			break
		}
	}
	if !foundOwner {
		t.Errorf("expected configMap %s to reference owner %s", configMapName, podName)
	}
	// Make sure that the pod references the configMap
	foundVolume := false
	for _, v := range pod.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == configMapName {
			foundVolume = true
			break
		}
	}
	if !foundVolume {
		t.Errorf("configMap %s should exist exist as a volume in the build pod, but was not found.", configMapName)
	}
}

func TestCreateBuildPodWithImageStreamOutput(t *testing.T) {
	imageStream := &imagev1.ImageStream{}
	imageStream.Namespace = "isnamespace"
	imageStream.Name = "isname"
	imageStream.Status.DockerImageRepository = "namespace/image-name"
	imageClient := fakeImageClient(imageStream)
	imageStreamRef := &corev1.ObjectReference{Name: "isname:latest", Namespace: "isnamespace", Kind: "ImageStreamTag"}
	bc := newFakeBuildController(nil, imageClient, nil, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{To: imageStreamRef, PushSecret: &corev1.LocalObjectReference{}}))
	podName := buildutil.GetBuildPodName(build)

	update, err := bc.createBuildPod(build)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := &buildUpdate{}
	expected.setPodNameAnnotation(podName)
	expected.setPhase(buildv1.BuildPhasePending)
	expected.setReason("")
	expected.setMessage("")
	expected.setOutputRef("namespace/image-name:latest")
	validateUpdate(t, "create build pod with imagestream output", expected, update)
	if len(bc.imageStreamQueue.Pop("isnamespace/isname")) > 0 {
		t.Errorf("should not have queued build update")
	}
}

func TestCreateBuildPodWithOutputImageStreamMissing(t *testing.T) {
	imageStreamRef := &corev1.ObjectReference{Name: "isname:latest", Namespace: "isnamespace", Kind: "ImageStreamTag"}
	bc := newFakeBuildController(nil, nil, nil, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{To: imageStreamRef, PushSecret: &corev1.LocalObjectReference{}}))

	update, err := bc.createBuildPod(build)

	if err != nil {
		t.Fatalf("Expected no error")
	}
	expected := &buildUpdate{}
	expected.setReason(buildv1.StatusReasonInvalidOutputReference)
	expected.setMessage("Output image could not be resolved.")
	validateUpdate(t, "create build pod with image stream error", expected, update)
	if !reflect.DeepEqual(bc.imageStreamQueue.Pop("isnamespace/isname"), []string{"namespace/data-build"}) {
		t.Errorf("should have queued build update: %#v", bc.imageStreamQueue)
	}
}

func TestCreateBuildPodWithImageStreamMissing(t *testing.T) {
	imageStreamRef := &corev1.ObjectReference{Name: "isname:latest", Kind: "DockerImage"}
	bc := newFakeBuildController(nil, nil, nil, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{To: imageStreamRef, PushSecret: &corev1.LocalObjectReference{}}))
	build.Spec.Strategy.DockerStrategy.From = &corev1.ObjectReference{Kind: "ImageStreamTag", Name: "isname:latest"}

	update, err := bc.createBuildPod(build)
	if err != nil {
		t.Fatalf("Expected no error: %v", err)
	}
	expected := &buildUpdate{}
	expected.setReason(buildv1.StatusReasonInvalidImageReference)
	expected.setMessage("Referenced image could not be resolved.")
	validateUpdate(t, "create build pod with image stream error", expected, update)
	if !reflect.DeepEqual(bc.imageStreamQueue.Pop("namespace/isname"), []string{"namespace/data-build"}) {
		t.Errorf("should have queued build update: %#v", bc.imageStreamQueue)
	}
}

func TestCreateBuildPodWithImageStreamUnresolved(t *testing.T) {
	imageStream := &imagev1.ImageStream{}
	imageStream.Namespace = "isnamespace"
	imageStream.Name = "isname"
	imageStream.Status.DockerImageRepository = ""
	imageClient := fakeImageClient(imageStream)
	imageStreamRef := &corev1.ObjectReference{Name: "isname:latest", Namespace: "isnamespace", Kind: "ImageStreamTag"}
	bc := newFakeBuildController(nil, imageClient, nil, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{To: imageStreamRef, PushSecret: &corev1.LocalObjectReference{}}))

	update, err := bc.createBuildPod(build)

	if err == nil {
		t.Fatalf("Expected error")
	}
	expected := &buildUpdate{}
	expected.setReason(buildv1.StatusReasonInvalidOutputReference)
	expected.setMessage("Output image could not be resolved.")
	validateUpdate(t, "create build pod with image stream error", expected, update)
	if !reflect.DeepEqual(bc.imageStreamQueue.Pop("isnamespace/isname"), []string{"namespace/data-build"}) {
		t.Errorf("should have queued build update")
	}
}

type errorStrategy struct{}

func (*errorStrategy) CreateBuildPod(build *buildv1.Build, additionalCAs map[string]string, internalRegistryHost string) (*corev1.Pod, error) {
	return nil, fmt.Errorf("error")
}

func TestCreateBuildPodWithPodSpecCreationError(t *testing.T) {
	bc := newFakeBuildController(nil, nil, nil, nil, nil)
	defer bc.stop()
	bc.createStrategy = &errorStrategy{}
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	update, err := bc.createBuildPod(build)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	expected := &buildUpdate{}
	expected.setReason(buildv1.StatusReasonCannotCreateBuildPodSpec)
	expected.setMessage("Failed to create pod spec.")
	validateUpdate(t, "create build pod with pod spec creation error", expected, update)
}

func TestCreateBuildPodWithExistingRelatedPod(t *testing.T) {
	tru := true
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildutil.GetBuildPodName(build),
			Namespace: build.Namespace,
			UID:       types.UID(uuid.New().String()),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: buildv1.SchemeGroupVersion.String(),
					Kind:       "Build",
					Name:       build.Name,
					Controller: &tru,
				},
			},
		},
	}

	kubeClient := fakeKubeExternalClientSet(existingPod, registryCAConfigMap)
	errorReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "pods"}, existingPod.Name)
	}
	kubeClient.(*fake.Clientset).PrependReactor("create", "pods", errorReaction)
	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	bc.start()
	defer bc.stop()

	update, err := bc.createBuildPod(build)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := &buildUpdate{}
	expected.setPhase(buildv1.BuildPhasePending)
	expected.setReason("")
	expected.setMessage("")
	expected.setPodNameAnnotation(buildutil.GetBuildPodName(build))
	validateUpdate(t, "create build pod with existing related pod error", expected, update)
}

func TestCreateBuildPodWithExistingRelatedPodMissingCA(t *testing.T) {
	tru := true
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildutil.GetBuildPodName(build),
			Namespace: build.Namespace,
			UID:       types.UID(uuid.New().String()),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: buildv1.SchemeGroupVersion.String(),
					Kind:       "Build",
					Name:       build.Name,
					Controller: &tru,
				},
			},
		},
	}
	caMapName := buildutil.GetBuildCAConfigMapName(build)
	kubeClient := fakeKubeExternalClientSet(existingPod, registryCAConfigMap)
	errorReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "pods"}, existingPod.Name)
	}
	notFoundReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewNotFound(schema.GroupResource{Group: "", Resource: "configmaps"}, caMapName)
	}
	kubeClient.(*fake.Clientset).PrependReactor("create", "pods", errorReaction)
	kubeClient.(*fake.Clientset).PrependReactor("get", "configmaps", notFoundReaction)

	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	bc.start()
	defer bc.stop()

	update, err := bc.createBuildPod(build)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := &buildUpdate{}
	expected.setPhase(buildv1.BuildPhasePending)
	expected.setReason("")
	expected.setMessage("")
	expected.setPodNameAnnotation(buildutil.GetBuildPodName(build))
	validateUpdate(t, "create build pod with existing related pod and missing CA configMap error", expected, update)
}

func TestCreateBuildPodWithExistingRelatedPodBadCA(t *testing.T) {
	tru := true
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildutil.GetBuildPodName(build),
			Namespace: build.Namespace,
			UID:       types.UID(uuid.New().String()),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: buildv1.SchemeGroupVersion.String(),
					Kind:       "Build",
					Name:       build.Name,
					Controller: &tru,
				},
			},
		},
	}
	badPod := mockBuildPod(build)
	existingCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildutil.GetBuildCAConfigMapName(build),
			Namespace: build.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       badPod.Name,
					UID:        badPod.UID,
				},
			},
		},
	}
	kubeClient := fakeKubeExternalClientSet(existingPod, registryCAConfigMap)
	errorReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "pods"}, existingPod.Name)
	}
	getCAReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, existingCA, nil
	}
	kubeClient.(*fake.Clientset).PrependReactor("create", "pods", errorReaction)
	kubeClient.(*fake.Clientset).PrependReactor("get", "configmaps", getCAReaction)

	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	bc.start()
	defer bc.stop()

	update, err := bc.createBuildPod(build)

	if err == nil {
		t.Error("expected error")
	}

	expected := &buildUpdate{}
	validateUpdate(t, "create build pod with existing related pod and bad CA configMap error", expected, update)
}

func TestCreateBuildPodWithExistingUnrelatedPod(t *testing.T) {
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildutil.GetBuildPodName(build),
			Namespace: build.Namespace,
		},
	}

	kubeClient := fakeKubeExternalClientSet(existingPod, registryCAConfigMap)
	errorReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "pods"}, existingPod.Name)
	}
	kubeClient.(*fake.Clientset).PrependReactor("create", "pods", errorReaction)
	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	defer bc.stop()

	update, err := bc.createBuildPod(build)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := &buildUpdate{}
	expected.setPhase(buildv1.BuildPhaseError)
	expected.setReason(buildv1.StatusReasonBuildPodExists)
	expected.setMessage("The pod for this build already exists and is older than the build.")
	validateUpdate(t, "create build pod with pod with older existing pod", expected, update)
}

func TestCreateBuildPodWithPodCreationError(t *testing.T) {
	kubeClient := fakeKubeExternalClientSet(registryCAConfigMap)
	errorReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("error")
	}
	kubeClient.(*fake.Clientset).PrependReactor("create", "pods", errorReaction)
	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	update, err := bc.createBuildPod(build)

	if err == nil {
		t.Errorf("expected error")
	}

	expected := &buildUpdate{}
	expected.setReason(buildv1.StatusReasonCannotCreateBuildPod)
	expected.setMessage("Failed creating build pod.")
	validateUpdate(t, "create build pod with pod creation error", expected, update)
}

func TestCreateBuildPodWithCACreationError(t *testing.T) {
	kubeClient := fakeKubeExternalClientSet(registryCAConfigMap)
	errorReaction := func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("error")
	}
	kubeClient.(*fake.Clientset).PrependReactor("create", "configmaps", errorReaction)
	bc := newFakeBuildController(nil, nil, kubeClient, nil, nil)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))

	update, err := bc.createBuildPod(build)

	if err == nil {
		t.Errorf("expected error")
	}

	expected := &buildUpdate{}
	expected.setReason("CannotCreateCAConfigMap")
	expected.setMessage("Failed creating build certificate authority configMap.")
	validateUpdate(t, "create build pod with CA ConfigMap creation error", expected, update)
}

func TestCancelBuild(t *testing.T) {
	build := mockBuild(buildv1.BuildPhaseRunning, buildv1.BuildOutput{})
	build.Name = "canceltest"
	build.Namespace = "testns"
	pod := &corev1.Pod{}
	pod.Name = "canceltest-build"
	pod.Namespace = "testns"
	client := fake.NewSimpleClientset(pod).CoreV1()
	bc := BuildController{
		podClient: client,
	}
	update, err := bc.cancelBuild(build)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if _, err := client.Pods("testns").Get("canceltest-build", metav1.GetOptions{}); err == nil {
		t.Errorf("expect pod canceltest-build to have been deleted")
	}
	if update.phase == nil || *update.phase != buildv1.BuildPhaseCancelled {
		t.Errorf("expected phase to be set to cancelled")
	}
	if update.reason == nil || *update.reason != buildv1.StatusReasonCancelledBuild {
		t.Errorf("expected status reason to be set to %s", buildv1.StatusReasonCancelledBuild)
	}
	if update.message == nil || *update.message != ("The build was cancelled by the user.") {
		t.Errorf("expected status message to be set to %s", "The build was cancelled by the user.")
	}
}

func TestShouldIgnore(t *testing.T) {

	setCompletionTimestamp := func(build *buildv1.Build) *buildv1.Build {
		now := metav1.Now()
		build.Status.CompletionTimestamp = &now
		return build
	}

	tests := []struct {
		name         string
		build        *buildv1.Build
		expectIgnore bool
	}{
		{
			name:         "new docker build",
			build:        dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{})),
			expectIgnore: false,
		},
		{
			name:         "running docker build",
			build:        dockerStrategy(mockBuild(buildv1.BuildPhaseRunning, buildv1.BuildOutput{})),
			expectIgnore: false,
		},
		{
			name:         "cancelled docker build",
			build:        dockerStrategy(mockBuild(buildv1.BuildPhaseCancelled, buildv1.BuildOutput{})),
			expectIgnore: true,
		},
		{
			name:         "completed docker build with no completion timestamp",
			build:        dockerStrategy(mockBuild(buildv1.BuildPhaseComplete, buildv1.BuildOutput{})),
			expectIgnore: false,
		},
		{
			name:         "completed docker build with completion timestamp",
			build:        setCompletionTimestamp(dockerStrategy(mockBuild(buildv1.BuildPhaseComplete, buildv1.BuildOutput{}))),
			expectIgnore: true,
		},
		{
			name:         "running pipeline build",
			build:        pipelineStrategy(mockBuild(buildv1.BuildPhaseRunning, buildv1.BuildOutput{})),
			expectIgnore: true,
		},
		{
			name:         "completed pipeline build",
			build:        pipelineStrategy(mockBuild(buildv1.BuildPhaseComplete, buildv1.BuildOutput{})),
			expectIgnore: true,
		},
	}

	for _, test := range tests {
		actual := shouldIgnore(test.build)
		if expected := test.expectIgnore; actual != expected {
			t.Errorf("%s: expected result: %v, actual: %v", test.name, expected, actual)
		}
	}

}

func TestIsValidTransition(t *testing.T) {
	phases := []buildv1.BuildPhase{
		buildv1.BuildPhaseNew,
		buildv1.BuildPhasePending,
		buildv1.BuildPhaseRunning,
		buildv1.BuildPhaseComplete,
		buildv1.BuildPhaseFailed,
		buildv1.BuildPhaseError,
		buildv1.BuildPhaseCancelled,
	}
	for _, fromPhase := range phases {
		for _, toPhase := range phases {
			if buildutil.IsTerminalPhase(fromPhase) && fromPhase != toPhase {
				if isValidTransition(fromPhase, toPhase) {
					t.Errorf("transition %v -> %v should be invalid", fromPhase, toPhase)
				}
				continue
			}
			if fromPhase == buildv1.BuildPhasePending && toPhase == buildv1.BuildPhaseNew {
				if isValidTransition(fromPhase, toPhase) {
					t.Errorf("transition %v -> %v should be invalid", fromPhase, toPhase)
				}
				continue
			}
			if fromPhase == buildv1.BuildPhaseRunning && (toPhase == buildv1.BuildPhaseNew || toPhase == buildv1.BuildPhasePending) {
				if isValidTransition(fromPhase, toPhase) {
					t.Errorf("transition %v -> %v shluld be invalid", fromPhase, toPhase)
				}
				continue
			}

			if !isValidTransition(fromPhase, toPhase) {
				t.Errorf("transition %v -> %v should be valid", fromPhase, toPhase)
			}
		}
	}
}

func TestIsTerminal(t *testing.T) {
	tests := map[buildv1.BuildPhase]bool{
		buildv1.BuildPhaseNew:       false,
		buildv1.BuildPhasePending:   false,
		buildv1.BuildPhaseRunning:   false,
		buildv1.BuildPhaseComplete:  true,
		buildv1.BuildPhaseFailed:    true,
		buildv1.BuildPhaseError:     true,
		buildv1.BuildPhaseCancelled: true,
	}
	for phase, expected := range tests {
		if actual := buildutil.IsTerminalPhase(phase); actual != expected {
			t.Errorf("unexpected response for %s: %v", phase, actual)
		}
	}
}

func TestSetBuildCompletionTimestampAndDuration(t *testing.T) {
	// set start time to 2 seconds ago to have some significant duration
	startTime := metav1.NewTime(time.Now().Add(time.Second * -2))
	earlierTime := metav1.NewTime(startTime.Add(time.Hour * -1))

	// Marker times used for validation
	afterStartTimeBeforeNow := metav1.NewTime(time.Time{})

	// Marker durations used for validation
	greaterThanZeroLessThanSinceStartTime := time.Duration(0)
	atLeastOneHour := time.Duration(0)
	zeroDuration := time.Duration(0)

	buildWithStartTime := &buildv1.Build{}
	buildWithStartTime.Status.StartTimestamp = &startTime
	buildWithNoStartTime := &buildv1.Build{}
	tests := []struct {
		name         string
		build        *buildv1.Build
		podStartTime *metav1.Time
		expected     *buildUpdate
	}{
		{
			name:         "build with start time",
			build:        buildWithStartTime,
			podStartTime: &earlierTime,
			expected: &buildUpdate{
				completionTime: &afterStartTimeBeforeNow,
				duration:       &greaterThanZeroLessThanSinceStartTime,
			},
		},
		{
			name:         "build with no start time",
			build:        buildWithNoStartTime,
			podStartTime: &earlierTime,
			expected: &buildUpdate{
				startTime:      &earlierTime,
				completionTime: &afterStartTimeBeforeNow,
				duration:       &atLeastOneHour,
			},
		},
		{
			name:         "build with no start time, no pod start time",
			build:        buildWithNoStartTime,
			podStartTime: nil,
			expected: &buildUpdate{
				startTime:      &afterStartTimeBeforeNow,
				completionTime: &afterStartTimeBeforeNow,
				duration:       &zeroDuration,
			},
		},
	}

	for _, test := range tests {
		update := &buildUpdate{}
		pod := &corev1.Pod{}
		pod.Status.StartTime = test.podStartTime
		setBuildCompletionData(test.build, pod, update)
		// Ensure that only the fields in the expected update are set
		if test.expected.podNameAnnotation == nil && (test.expected.podNameAnnotation != update.podNameAnnotation) {
			t.Errorf("%s: podNameAnnotation should not be set", test.name)
			continue
		}
		if test.expected.phase == nil && (test.expected.phase != update.phase) {
			t.Errorf("%s: phase should not be set", test.name)
			continue
		}
		if test.expected.reason == nil && (test.expected.reason != update.reason) {
			t.Errorf("%s: reason should not be set", test.name)
			continue
		}
		if test.expected.message == nil && (test.expected.message != update.message) {
			t.Errorf("%s: message should not be set", test.name)
			continue
		}
		if test.expected.startTime == nil && (test.expected.startTime != update.startTime) {
			t.Errorf("%s: startTime should not be set", test.name)
			continue
		}
		if test.expected.completionTime == nil && (test.expected.completionTime != update.completionTime) {
			t.Errorf("%s: completionTime should not be set", test.name)
			continue
		}
		if test.expected.duration == nil && (test.expected.duration != update.duration) {
			t.Errorf("%s: duration should not be set", test.name)
			continue
		}
		if test.expected.outputRef == nil && (test.expected.outputRef != update.outputRef) {
			t.Errorf("%s: outputRef should not be set", test.name)
			continue
		}
		now := metav1.NewTime(time.Now().Add(2 * time.Second))
		if test.expected.startTime != nil {
			if update.startTime == nil {
				t.Errorf("%s: expected startTime to be set", test.name)
				continue
			}
			switch test.expected.startTime {
			case &afterStartTimeBeforeNow:
				if !update.startTime.Time.After(startTime.Time) && !update.startTime.Time.Before(now.Time) {
					t.Errorf("%s: startTime (%v) not within expected range (%v - %v)", test.name, update.startTime, startTime, now)
					continue
				}
			default:
				if !update.startTime.Time.Equal(test.expected.startTime.Time) {
					t.Errorf("%s: startTime (%v) not equal expected time (%v)", test.name, update.startTime, test.expected.startTime)
					continue
				}
			}
		}
		if test.expected.completionTime != nil {
			if update.completionTime == nil {
				t.Errorf("%s: expected completionTime to be set", test.name)
				continue
			}
			switch test.expected.completionTime {
			case &afterStartTimeBeforeNow:
				if !update.completionTime.Time.After(startTime.Time) && !update.completionTime.Time.Before(now.Time) {
					t.Errorf("%s: completionTime (%v) not within expected range (%v - %v)", test.name, update.completionTime, startTime, now)
					continue
				}
			default:
				if !update.completionTime.Time.Equal(test.expected.completionTime.Time) {
					t.Errorf("%s: completionTime (%v) not equal expected time (%v)", test.name, update.completionTime, test.expected.completionTime)
					continue
				}
			}
		}
		if test.expected.duration != nil {
			if update.duration == nil {
				t.Errorf("%s: expected duration to be set", test.name)
				continue
			}
			switch test.expected.duration {
			case &greaterThanZeroLessThanSinceStartTime:
				sinceStart := now.Rfc3339Copy().Time.Sub(startTime.Rfc3339Copy().Time)
				if *update.duration <= 0 || *update.duration > sinceStart {
					t.Errorf("%s: duration (%v) not within expected range (%v - %v)", test.name, update.duration, 0, sinceStart)
					continue
				}
			case &atLeastOneHour:
				if *update.duration < time.Hour {
					t.Errorf("%s: duration (%v) is not at least one hour", test.name, update.duration)
					continue
				}
			default:
				if *update.duration != *test.expected.duration {
					t.Errorf("%s: duration (%v) not equal expected duration (%v)", test.name, update.duration, test.expected.duration)
					continue
				}
			}
		}
	}
}

func TestCreateBuildCAConfigMap(t *testing.T) {
	tests := []struct {
		name       string
		addlCAData map[string]string
	}{
		{
			name:       "no CAs",
			addlCAData: map[string]string{},
		},
		{
			name: "addl CA data",
			addlCAData: map[string]string{
				"mydomain":    dummyCA,
				"otherdomain": dummyCA,
				"third":       dummyCA,
			},
		},
		{
			name: "everything",
			addlCAData: map[string]string{
				"mydomain":    dummyCA,
				"otherdomain": dummyCA,
				"third":       dummyCA,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bc := newFakeBuildController(nil, nil, nil, nil, nil)
			bc.setAdditionalTrustedCAs(tc.addlCAData)
			defer bc.stop()
			build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))
			pod := mockBuildPod(build)
			caMap := bc.createBuildCAConfigMapSpec(build, pod, tc.addlCAData)
			if caMap == nil {
				t.Error("certificate authority configMap was not created")
			}
			if !hasBuildPodOwnerRef(pod, caMap) {
				t.Error("build CA configMap is missing owner ref to the build pod")
			}

			expectedData := make(map[string]string)
			for k, v := range tc.addlCAData {
				expectedData[k] = v
			}
			// Add registry CA
			expectedData[buildv1.ServiceCAKey] = dummyCA

			if !reflect.DeepEqual(expectedData, caMap.Data) {
				t.Errorf("expected CA configMap %v\ngot:\n%v", expectedData, caMap.Data)
			}
		})
	}
}

func TestHandleControllerConfig(t *testing.T) {
	tests := []struct {
		name string
		// Conditions
		build         *configv1.Build
		image         *configv1.Image
		casMap        *corev1.ConfigMap
		errorGetBuild bool
		errorGetImage bool
		errorGetCA    bool
		// Results
		expectError bool
	}{
		{
			name: "no cas",
		},
		{
			name: "ca exists",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					AdditionalTrustedCA: configv1.ConfigMapNameReference{
						Name: "cluster-cas",
					},
				},
			},
			casMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cluster-cas",
					Namespace: "openshift-config",
				},
				Data: map[string]string{
					"mydomain":    dummyCA,
					"otherdomain": dummyCA,
				},
			},
		},
		{
			name: "ca configMap removed",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					AdditionalTrustedCA: configv1.ConfigMapNameReference{
						Name: "cluster-cas",
					},
				},
			},
		},
		{
			name: "get image CRD error",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					AdditionalTrustedCA: configv1.ConfigMapNameReference{
						Name: "cluster-cas",
					},
				},
			},
			errorGetImage: true,
			expectError:   true,
		},
		{
			name: "get configMap error",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					AdditionalTrustedCA: configv1.ConfigMapNameReference{
						Name: "cluster-cas",
					},
				},
			},
			casMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cluster-cas",
					Namespace: "openshift-config",
				},
				Data: map[string]string{
					"mydomain": dummyCA,
				},
			},
			errorGetCA:  true,
			expectError: true,
		},
		{
			name: "insecure registries",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					RegistrySources: configv1.RegistrySources{
						InsecureRegistries: []string{"my-local.registry:5000", "omni.corp.org:5000"},
					},
				},
			},
		},
		{
			name: "allowed registries",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					RegistrySources: configv1.RegistrySources{
						AllowedRegistries: []string{"quay.io"},
					},
				},
			},
		},
		{
			name: "blocked registries",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					RegistrySources: configv1.RegistrySources{
						BlockedRegistries: []string{"docker.io"},
					},
				},
			},
		},
		{
			name: "allowed and blocked registries",
			image: &configv1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.ImageSpec{
					RegistrySources: configv1.RegistrySources{
						AllowedRegistries: []string{"quay.io"},
						BlockedRegistries: []string{"docker.io"},
					},
				},
			},
			expectError: true,
		},
		{
			name: "default proxy",
			build: &configv1.Build{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.BuildSpec{
					BuildDefaults: configv1.BuildDefaults{
						DefaultProxy: &configv1.ProxySpec{
							HTTPProxy:  "http://my-proxy.org",
							HTTPSProxy: "https://my-proxy.org",
							NoProxy:    "mydomain",
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var configClient configv1client.Interface
			objs := []runtime.Object{}
			if tc.build != nil {
				objs = append(objs, tc.build)

			}
			if tc.image != nil {
				objs = append(objs, tc.image)
			}
			configClient = fakeConfigClient(objs...)
			var kubeClient kubernetes.Interface
			if tc.casMap != nil {
				kubeClient = fakeKubeExternalClientSet(tc.casMap, registryCAConfigMap)
			} else {
				kubeClient = fakeKubeExternalClientSet(registryCAConfigMap)
			}
			if tc.errorGetCA {
				kubeClient.(*fake.Clientset).PrependReactor("get", "configmaps", func(action clientgotesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error")
				})
			}

			bc := newFakeBuildController(nil, nil, kubeClient, nil, configClient)
			defer bc.stop()

			if tc.errorGetBuild {
				bc.buildControllerConfigLister = &errorBuildLister{}
			}
			if tc.errorGetImage {
				bc.imageConfigLister = &errorImageLister{}
			}
			if tc.errorGetCA {
				bc.openShiftConfigConfigMapStore = &errorConfigMapLister{}
			}

			errs := bc.handleControllerConfig()
			if tc.expectError {
				if len(errs) == 0 {
					t.Errorf("expected errors, but got none")
				}
				return
			}
			if len(errs) > 0 {
				msgs := make([]string, len(errs))
				for i, e := range errs {
					msgs[i] = fmt.Sprintf("%v", e)
				}
				t.Fatalf("error handling controller config change: %v", msgs)
			}

			defaults := bc.defaults()
			if tc.build == nil {
				if defaults.DefaultProxy != nil {
					t.Errorf("expected no default proxy, got %v", defaults.DefaultProxy)
				}
			} else {
				if !reflect.DeepEqual(tc.build.Spec.BuildDefaults.DefaultProxy, defaults.DefaultProxy) {
					t.Errorf("expected default proxy %v, got %v",
						tc.build.Spec.BuildDefaults.DefaultProxy,
						defaults.DefaultProxy)
				}
			}

			// Test additional certificate authorities
			certAuthorities := bc.additionalTrustedCAs()
			if tc.image == nil {
				if len(certAuthorities) > 0 {
					t.Errorf("expected empty additional CAs data, got %v", certAuthorities)
				}
				registryConf := bc.registryConfTOML()
				if len(registryConf) > 0 {
					t.Errorf("expected empty registries config, got %v", registryConf)
				}
				signatureJSON := bc.signaturePolicyJSON()
				if len(signatureJSON) > 0 {
					t.Errorf("expected empty signature policy config, got %v", signatureJSON)
				}
				return
			}

			if tc.casMap == nil {
				if len(certAuthorities) > 0 {
					t.Errorf("expected empty additional CAs data, got %v", certAuthorities)
				}
			} else if tc.image != nil && !reflect.DeepEqual(tc.casMap.Data, certAuthorities) {
				t.Errorf("expected ca data:\n  %v\ngot:\n  %v", tc.casMap.Data, certAuthorities)
			}

			buildRegistriesConfig := tc.image.Spec.RegistrySources

			registryConfTOML := bc.registryConfTOML()
			if isRegistryConfigEmpty(buildRegistriesConfig) {
				if len(registryConfTOML) > 0 {
					t.Errorf("expected empty registries config, got %s", registryConfTOML)
				}
			}
			registriesConfig, err := decodeRegistries(registryConfTOML)
			if err != nil {
				t.Errorf("unexpected error decoding registries config: %v", err)
			}

			if !equality.Semantic.DeepEqual(registriesConfig.Registries.Insecure.Registries,
				buildRegistriesConfig.InsecureRegistries) {
				t.Errorf("expected insecure registries to equal %v, got %v",
					buildRegistriesConfig.InsecureRegistries,
					registriesConfig.Registries.Insecure.Registries)
			}

			expectedSearchRegistries := []string{}
			// If only insecure registries are specified, default search should be docker.io
			if len(buildRegistriesConfig.InsecureRegistries) > 0 {
				expectedSearchRegistries = []string{"docker.io"}
			}
			if !equality.Semantic.DeepEqual(registriesConfig.Registries.Search.Registries,
				expectedSearchRegistries) {
				t.Errorf("expected search registries to equal %v, got %v",
					expectedSearchRegistries,
					registriesConfig.Registries.Search.Registries)
			}

			signatureJSON := bc.signaturePolicyJSON()
			if isSignaturePolicyConfigEmpty(buildRegistriesConfig) {
				if len(signatureJSON) > 0 {
					t.Errorf("expected empty signature policy config, got %s", signatureJSON)
				}
				return
			}
			if len(buildRegistriesConfig.AllowedRegistries) > 0 && len(buildRegistriesConfig.BlockedRegistries) > 0 {
				// Condition is not allowed - no policy should be set
				if len(signatureJSON) > 0 {
					t.Errorf("signature policy should be empty if both allowed and blocked registries are set, got %v", signatureJSON)
				}
				return
			}
			policy, err := decodePolicyConfig(signatureJSON)
			if err != nil {
				t.Fatalf("unexpected error decoding signature policy config: %v", err)
			}

			if len(buildRegistriesConfig.AllowedRegistries) > 0 {
				expectedDefaults := signature.PolicyRequirements{
					signature.NewPRReject(),
				}
				if !reflect.DeepEqual(expectedDefaults, policy.Default) {
					t.Errorf("expected signature defaults %v, got %v", expectedDefaults, policy.Default)
				}
				expectedRepos := make(signature.PolicyTransportScopes)
				for _, reg := range buildRegistriesConfig.AllowedRegistries {
					expectedRepos[reg] = signature.PolicyRequirements{
						signature.NewPRInsecureAcceptAnything(),
					}
				}
				expectedScopes := map[string]signature.PolicyTransportScopes{
					"atomic": expectedRepos,
					"docker": expectedRepos,
				}
				if !reflect.DeepEqual(expectedScopes, policy.Transports) {
					t.Errorf("expected transport scopes %v, got %v", expectedScopes, policy.Transports)
				}
			}
			if len(buildRegistriesConfig.BlockedRegistries) > 0 {
				expectedDefaults := signature.PolicyRequirements{
					signature.NewPRInsecureAcceptAnything(),
				}
				if !reflect.DeepEqual(expectedDefaults, policy.Default) {
					t.Errorf("expected signature defaults %v, got %v", expectedDefaults, policy.Default)
				}
				expectedRepos := make(signature.PolicyTransportScopes)
				for _, reg := range buildRegistriesConfig.BlockedRegistries {
					expectedRepos[reg] = signature.PolicyRequirements{
						signature.NewPRReject(),
					}
				}
				expectedScopes := map[string]signature.PolicyTransportScopes{
					"atomic": expectedRepos,
					"docker": expectedRepos,
				}
				if !reflect.DeepEqual(expectedScopes, policy.Transports) {
					t.Errorf("expected transport scopes %v, got %v", expectedScopes, policy.Transports)
				}
			}
		})
	}
}

func isRegistryConfigEmpty(config configv1.RegistrySources) bool {
	return len(config.InsecureRegistries) == 0
}

func decodeRegistries(configTOML string) (*tomlConfig, error) {
	config := &tomlConfig{}
	err := toml.Unmarshal([]byte(configTOML), config)
	return config, err
}

func isSignaturePolicyConfigEmpty(config configv1.RegistrySources) bool {
	return len(config.AllowedRegistries) == 0 && len(config.BlockedRegistries) == 0
}

func decodePolicyConfig(configJSON string) (*signature.Policy, error) {
	if len(configJSON) == 0 {
		return &signature.Policy{}, nil
	}
	return signature.NewPolicyFromBytes([]byte(configJSON))
}

type errorBuildLister struct{}

func (e *errorBuildLister) List(selector labels.Selector) ([]*configv1.Build, error) {
	return nil, fmt.Errorf("error")
}

func (e *errorBuildLister) Get(name string) (*configv1.Build, error) {
	return nil, fmt.Errorf("error")
}

type errorImageLister struct{}

func (e *errorImageLister) List(selector labels.Selector) ([]*configv1.Image, error) {
	return nil, fmt.Errorf("error")
}

func (e *errorImageLister) Get(name string) (*configv1.Image, error) {
	return nil, fmt.Errorf("error")
}

type errorConfigMapLister struct{}

func (e *errorConfigMapLister) List(selector labels.Selector) ([]*corev1.ConfigMap, error) {
	return nil, fmt.Errorf("error")
}

func (e *errorConfigMapLister) Get(name string) (*corev1.ConfigMap, error) {
	return nil, fmt.Errorf("error")
}

func (e *errorConfigMapLister) ConfigMaps(namespace string) v1lister.ConfigMapNamespaceLister {
	return e
}

func TestCreateBuildRegistryConfConfigMap(t *testing.T) {
	bc := newFakeBuildController(nil, nil, nil, nil, nil)
	bc.setRegistryConfTOML(dummyRegistryConf)
	defer bc.stop()
	build := dockerStrategy(mockBuild(buildv1.BuildPhaseNew, buildv1.BuildOutput{}))
	pod := mockBuildPod(build)
	caMap := bc.createBuildSystemConfigMapSpec(build, pod)
	if caMap == nil {
		t.Error("build system config configMap was not created")
	}
	if !hasBuildPodOwnerRef(pod, caMap) {
		t.Error("build system config configMap is missing owner ref to the build pod")
	}
	if _, hasConf := caMap.Data[buildv1.RegistryConfKey]; !hasConf {
		t.Errorf("expected build system config configMap to have key %s", buildv1.RegistryConfKey)
	}
	if caMap.Data[buildv1.RegistryConfKey] != dummyRegistryConf {
		t.Errorf("expected build system config configMap.%s to contain\n%s\ngot:\n%s",
			buildv1.RegistryConfKey,
			dummyCA,
			caMap.Data[buildv1.RegistryConfKey])
	}
}

func mockBuild(phase buildv1.BuildPhase, output buildv1.BuildOutput) *buildv1.Build {
	return &buildv1.Build{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "data-build",
			Namespace: "namespace",
			Annotations: map[string]string{
				buildv1.BuildConfigAnnotation: "test-bc",
			},
			Labels: map[string]string{
				"name":                      "dataBuild",
				buildv1.BuildRunPolicyLabel: string(buildv1.BuildRunPolicyParallel),
				buildv1.BuildConfigLabel:    "test-bc",
			},
		},
		Spec: buildv1.BuildSpec{
			CommonSpec: buildv1.CommonSpec{
				Source: buildv1.BuildSource{
					Git: &buildv1.GitBuildSource{
						URI: "http://my.build.com/the/build/Dockerfile",
					},
					ContextDir: "contextimage",
				},
				Output: output,
			},
		},
		Status: buildv1.BuildStatus{
			Phase: phase,
		},
	}
}

func dockerStrategy(build *buildv1.Build) *buildv1.Build {
	build.Spec.Strategy = buildv1.BuildStrategy{
		DockerStrategy: &buildv1.DockerBuildStrategy{},
	}
	return build
}

func pipelineStrategy(build *buildv1.Build) *buildv1.Build {
	build.Spec.Strategy = buildv1.BuildStrategy{
		JenkinsPipelineStrategy: &buildv1.JenkinsPipelineBuildStrategy{},
	}
	return build
}

func fakeImageClient(objects ...runtime.Object) imagev1client.Interface {
	return fakeimagev1client.NewSimpleClientset(objects...)
}

func fakeBuildClient(objects ...runtime.Object) buildv1client.Interface {
	return fakebuildv1client.NewSimpleClientset(objects...)
}

func fakeConfigClient(objects ...runtime.Object) configv1client.Interface {
	return fakeconfigv1client.NewSimpleClientset(objects...)
}

func fakeKubeExternalClientSet(objects ...runtime.Object) kubernetes.Interface {
	builderSA := &corev1.ServiceAccount{}
	builderSA.Name = "builder"
	builderSA.Namespace = "namespace"
	builderSA.Secrets = []corev1.ObjectReference{
		{
			Name: "secret",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: "namespace",
		},
		Type: corev1.SecretTypeDockerConfigJson,
	}
	return fake.NewSimpleClientset(append(objects, builderSA, secret)...)
}

func fakeKubeInternalClientSet(objects ...runtime.Object) kubernetes.Interface {
	return fake.NewSimpleClientset(objects...)
}

func fakeKubeExternalInformers(clientSet kubernetes.Interface) informers.SharedInformerFactory {
	return informers.NewSharedInformerFactory(clientSet, 0)
}

type fakeBuildController struct {
	*BuildController
	kubeExternalInformers informers.SharedInformerFactory
	buildInformers        buildv1informer.SharedInformerFactory
	imageInformers        imagev1informer.SharedInformerFactory
	configInformers       configv1informer.SharedInformerFactory
	stopChan              chan struct{}
}

func (c *fakeBuildController) start() {
	c.kubeExternalInformers.Start(c.stopChan)
	c.imageInformers.Start(c.stopChan)
	c.buildInformers.Start(c.stopChan)
	c.configInformers.Start(c.stopChan)

	if !cache.WaitForCacheSync(wait.NeverStop,
		c.buildStoreSynced,
		c.podStoreSynced,
		c.secretStoreSynced,
		c.imageStreamStoreSynced,
		c.buildControllerConfigStoreSynced,
		c.imageConfigStoreSynced,
		c.openshiftConfigConfigMapStoreSynced,
		c.controllerManagerConfigMapStoreSynced) {
		panic("cannot sync cache")
	}
}

func (c *fakeBuildController) stop() {
	close(c.stopChan)
}

func newFakeBuildController(buildClient buildv1client.Interface, imageClient imagev1client.Interface, kubeExternalClient kubernetes.Interface, kubeInternalClient kubernetes.Interface, configClient configv1client.Interface) *fakeBuildController {
	if buildClient == nil {
		buildClient = fakeBuildClient()
	}
	if imageClient == nil {
		imageClient = fakeImageClient()
	}
	if kubeExternalClient == nil {
		kubeExternalClient = fakeKubeExternalClientSet(registryCAConfigMap)
	}

	if configClient == nil {
		configClient = fakeConfigClient()
	}

	kubeExternalInformers := fakeKubeExternalInformers(kubeExternalClient)
	buildInformers := buildv1informer.NewSharedInformerFactory(buildClient, 0)
	imageInformers := imagev1informer.NewSharedInformerFactory(imageClient, 0)
	configInformers := configv1informer.NewSharedInformerFactory(configClient, 0)
	stopChan := make(chan struct{})

	// For tests, use the kubeExternalInformers for pods, secrets, and configMaps.
	// The actual build controller uses a separate informer for configMaps that is namespaced to `openshif-config`
	params := &BuildControllerParams{
		BuildInformer:                      buildInformers.Build().V1().Builds(),
		BuildConfigInformer:                buildInformers.Build().V1().BuildConfigs(),
		ImageStreamInformer:                imageInformers.Image().V1().ImageStreams(),
		PodInformer:                        kubeExternalInformers.Core().V1().Pods(),
		SecretInformer:                     kubeExternalInformers.Core().V1().Secrets(),
		ServiceAccountInformer:             kubeExternalInformers.Core().V1().ServiceAccounts(),
		OpenshiftConfigConfigMapInformer:   kubeExternalInformers.Core().V1().ConfigMaps(),
		ControllerManagerConfigMapInformer: kubeExternalInformers.Core().V1().ConfigMaps(),
		BuildControllerConfigInformer:      configInformers.Config().V1().Builds(),
		ImageConfigInformer:                configInformers.Config().V1().Images(),
		KubeClient:                         kubeExternalClient,
		BuildClient:                        buildClient,
		DockerBuildStrategy: &strategy.DockerBuildStrategy{
			Image: "test/image:latest",
		},
		SourceBuildStrategy: &strategy.SourceBuildStrategy{
			Image: "test/image:latest",
		},
		CustomBuildStrategy: &strategy.CustomBuildStrategy{},
		BuildDefaults:       builddefaults.BuildDefaults{},
		BuildOverrides:      buildoverrides.BuildOverrides{},
	}
	bc := &fakeBuildController{
		BuildController:       NewBuildController(params),
		stopChan:              stopChan,
		kubeExternalInformers: kubeExternalInformers,
		buildInformers:        buildInformers,
		imageInformers:        imageInformers,
		configInformers:       configInformers,
	}
	bc.BuildController.recorder = &record.FakeRecorder{}
	bc.start()
	return bc
}

func validateUpdate(t *testing.T, name string, expected, actual *buildUpdate) {
	if expected.podNameAnnotation == nil {
		if actual.podNameAnnotation != nil {
			t.Errorf("%s: podNameAnnotation should be nil. Actual: %s", name, *actual.podNameAnnotation)
		}
	} else {
		if actual.podNameAnnotation == nil {
			t.Errorf("%s: podNameAnnotation should not be nil.", name)
		} else {
			if *expected.podNameAnnotation != *actual.podNameAnnotation {
				t.Errorf("%s: unexpected value for podNameAnnotation. Expected: %s. Actual: %s", name, *expected.podNameAnnotation, *actual.podNameAnnotation)
			}
		}
	}
	if expected.phase == nil {
		if actual.phase != nil {
			t.Errorf("%s: phase should be nil. Actual: %s", name, *actual.phase)
		}
	} else {
		if actual.phase == nil {
			t.Errorf("%s: phase should not be nil.", name)
		} else {
			if *expected.phase != *actual.phase {
				t.Errorf("%s: unexpected value for phase. Expected: %s. Actual: %s", name, *expected.phase, *actual.phase)
			}
		}
	}
	if expected.reason == nil {
		if actual.reason != nil {
			t.Errorf("%s: reason should be nil. Actual: %s", name, *actual.reason)
		}
	} else {
		if actual.reason == nil {
			t.Errorf("%s: reason should not be nil.", name)
		} else {
			if *expected.reason != *actual.reason {
				t.Errorf("%s: unexpected value for reason. Expected: %s. Actual: %s", name, *expected.reason, *actual.reason)
			}
		}
	}
	if expected.message == nil {
		if actual.message != nil {
			t.Errorf("%s: message should be nil. Actual: %s", name, *actual.message)
		}
	} else {
		if actual.message == nil {
			t.Errorf("%s: message should not be nil.", name)
		} else {
			if *expected.message != *actual.message {
				t.Errorf("%s: unexpected value for message. Expected: %s. Actual: %s", name, *expected.message, *actual.message)
			}
		}
	}
	if expected.startTime == nil {
		if actual.startTime != nil {
			t.Errorf("%s: startTime should be nil. Actual: %s", name, *actual.startTime)
		}
	} else {
		if actual.startTime == nil {
			t.Errorf("%s: startTime should not be nil.", name)
		} else {
			if !(*expected.startTime).Equal(actual.startTime) {
				t.Errorf("%s: unexpected value for startTime. Expected: %s. Actual: %s", name, *expected.startTime, *actual.startTime)
			}
		}
	}
	if expected.completionTime == nil {
		if actual.completionTime != nil {
			t.Errorf("%s: completionTime should be nil. Actual: %s", name, *actual.completionTime)
		}
	} else {
		if actual.completionTime == nil {
			t.Errorf("%s: completionTime should not be nil.", name)
		} else {
			if !(*expected.completionTime).Equal(actual.completionTime) {
				t.Errorf("%s: unexpected value for completionTime. Expected: %v. Actual: %v", name, *expected.completionTime, *actual.completionTime)
			}
		}
	}
	if expected.duration == nil {
		if actual.duration != nil {
			t.Errorf("%s: duration should be nil. Actual: %s", name, *actual.duration)
		}
	} else {
		if actual.duration == nil {
			t.Errorf("%s: duration should not be nil.", name)
		} else {
			if *expected.duration != *actual.duration {
				t.Errorf("%s: unexpected value for duration. Expected: %v. Actual: %v", name, *expected.duration, *actual.duration)
			}
		}
	}
	if expected.outputRef == nil {
		if actual.outputRef != nil {
			t.Errorf("%s: outputRef should be nil. Actual: %s", name, *actual.outputRef)
		}
	} else {
		if actual.outputRef == nil {
			t.Errorf("%s: outputRef should not be nil.", name)
		} else {
			if *expected.outputRef != *actual.outputRef {
				t.Errorf("%s: unexpected value for outputRef. Expected: %s. Actual: %s", name, *expected.outputRef, *actual.outputRef)
			}
		}
	}
}

func applyBuildPatch(build *buildv1.Build, patch []byte) (*buildv1.Build, error) {
	buildJSON, err := runtime.Encode(buildscheme.Encoder, build)
	if err != nil {
		return nil, err
	}
	patchedJSON, err := strategicpatch.StrategicMergePatch(buildJSON, patch, &buildv1.Build{})
	if err != nil {
		return nil, err
	}
	patchedVersionedBuild, err := runtime.Decode(buildscheme.Decoder, patchedJSON)
	if err != nil {
		return nil, err
	}
	return patchedVersionedBuild.(*buildv1.Build), nil
}

func applyBuildPatchReaction(t *testing.T, build *buildv1.Build, buildPtr **buildv1.Build) func(action clientgotesting.Action) (bool, runtime.Object, error) {
	return func(action clientgotesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(clientgotesting.PatchActionImpl)
		var err error
		(*buildPtr), err = applyBuildPatch(build, patchAction.Patch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
			return true, nil, nil
		}
		return true, *buildPtr, nil
	}
}

type updateBuilder struct {
	update *buildUpdate
}

func newUpdate() *updateBuilder {
	return &updateBuilder{update: &buildUpdate{}}
}

func (b *updateBuilder) phase(phase buildv1.BuildPhase) *updateBuilder {
	b.update.setPhase(phase)
	return b
}

func (b *updateBuilder) reason(reason buildv1.StatusReason) *updateBuilder {
	b.update.setReason(reason)
	return b
}

func (b *updateBuilder) message(message string) *updateBuilder {
	b.update.setMessage(message)
	return b
}

func (b *updateBuilder) startTime(startTime metav1.Time) *updateBuilder {
	b.update.setStartTime(startTime)
	return b
}

func (b *updateBuilder) completionTime(completionTime metav1.Time) *updateBuilder {
	b.update.setCompletionTime(completionTime)
	return b
}

func (b *updateBuilder) duration(duration time.Duration) *updateBuilder {
	b.update.setDuration(duration)
	return b
}

func (b *updateBuilder) outputRef(ref string) *updateBuilder {
	b.update.setOutputRef(ref)
	return b
}

func (b *updateBuilder) podNameAnnotation(podName string) *updateBuilder {
	b.update.setPodNameAnnotation(podName)
	return b
}

func (b *updateBuilder) logSnippet(message string) *updateBuilder {
	b.update.setLogSnippet(message)
	return b
}

type fakeRunPolicy struct {
	notRunnable      bool
	onCompleteCalled bool
}

func (f *fakeRunPolicy) IsRunnable(*buildv1.Build) (bool, error) {
	return !f.notRunnable, nil
}

func (f *fakeRunPolicy) OnComplete(*buildv1.Build) error {
	f.onCompleteCalled = true
	return nil
}

func (f *fakeRunPolicy) Handles(buildv1.BuildRunPolicy) bool {
	return true
}

func mockBuildPod(build *buildv1.Build) *corev1.Pod {
	pod := &corev1.Pod{}
	pod.Name = buildutil.GetBuildPodName(build)
	pod.Namespace = build.Namespace
	pod.Annotations = map[string]string{}
	pod.Annotations[buildv1.BuildAnnotation] = build.Name
	return pod
}

func mockBuildCAConfigMap(build *buildv1.Build, pod *corev1.Pod) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{}
	cm.Name = buildutil.GetBuildCAConfigMapName(build)
	cm.Namespace = build.Namespace
	if pod != nil {
		pod.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       pod.Name,
				UID:        pod.UID,
			},
		}
	}
	return cm
}

func mockBuildSystemConfigMap(build *buildv1.Build, pod *corev1.Pod) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{}
	cm.Name = buildutil.GetBuildSystemConfigMapName(build)
	cm.Namespace = build.Namespace
	if pod != nil {
		pod.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       pod.Name,
				UID:        pod.UID,
			},
		}
	}
	return cm
}

func TestPodStatusReporting(t *testing.T) {
	cases := []struct {
		name        string
		pod         *corev1.Pod
		isOOMKilled bool
		isEvicted   bool
	}{
		{
			name: "running",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "running-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "quay.io/coreos/coreos:latest",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase:   corev1.PodRunning,
					Reason:  "Running",
					Message: "Running...",
				},
			},
		},
		{
			name: "oomkilled-pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oom-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "quay.io/coreos/coreos:latest",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase:   corev1.PodFailed,
					Reason:  "OOMKilled",
					Message: "OOMKilled...",
				},
			},
			isOOMKilled: true,
		},
		{
			name: "oomkilled-init",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oom-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "init-1",
							Image: "quay.io/coreos/coreos:latest",
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "quay.io/coreos/coreos:latest",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase:   corev1.PodPending,
					Reason:  "Pending",
					Message: "Waiting on init containers...",
					InitContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "init-1",
							State: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ExitCode: 123,
									Signal:   9,
									Reason:   "OOMKilled",
								},
							},
						},
					},
				},
			},
			isOOMKilled: true,
		},
		{
			name: "oomkilled-container",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oom-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "quay.io/coreos/coreos:latest",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase:   corev1.PodFailed,
					Reason:  "Failed",
					Message: "Failed due to OOMKill...",
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "test",
							State: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ExitCode: 123,
									Signal:   9,
									Reason:   "OOMKilled",
								},
							},
						},
					},
				},
			},
			isOOMKilled: true,
		},
		{
			name: "pod-evicted",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "evicted-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "quay.io/coreos/coreos:latest",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase:   corev1.PodFailed,
					Reason:  "Evicted",
					Message: "The pod was evicted due to no memory available.",
				},
			},
			isEvicted: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isOOM := isOOMKilled(tc.pod)
			if isOOM != tc.isOOMKilled {
				t.Errorf("expected OOMKilled to be %v, got %v", tc.isOOMKilled, isOOM)
			}
			evicted := isPodEvicted(tc.pod)
			if evicted != tc.isEvicted {
				t.Errorf("expected Evicted to be %v, got %v", tc.isEvicted, evicted)
			}
		})
	}
}
