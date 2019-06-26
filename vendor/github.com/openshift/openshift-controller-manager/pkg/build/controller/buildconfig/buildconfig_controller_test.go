package controller

import (
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"

	buildv1 "github.com/openshift/api/build/v1"
	buildlister "github.com/openshift/client-go/build/listers/build/v1"

	"github.com/openshift/client-go/build/clientset/versioned/fake"
)

func TestHandleBuildConfig(t *testing.T) {
	tests := []struct {
		name              string
		bc                *buildv1.BuildConfig
		expectBuild       bool
		instantiatorError bool
		expectErr         bool
	}{
		{
			name:        "build config with no config change trigger",
			bc:          baseBuildConfig(),
			expectBuild: false,
		},
		{
			name:        "build config with non-zero last version",
			bc:          buildConfigWithNonZeroLastVersion(),
			expectBuild: false,
		},
		{
			name:        "build config with config change trigger",
			bc:          buildConfigWithConfigChangeTrigger(),
			expectBuild: true,
		},
		{
			name:              "instantiator error",
			bc:                buildConfigWithConfigChangeTrigger(),
			instantiatorError: true,
			expectErr:         true,
		},
	}

	for _, tc := range tests {
		buildClient := fake.NewSimpleClientset(tc.bc)
		instantiateRequestName := ""

		if tc.instantiatorError {
			buildClient.PrependReactor("create", "buildconfigs", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
				a, ok := action.(ktesting.CreateAction)
				if !ok {
					panic("unexpected action")
				}
				request := a.GetObject().(*buildv1.BuildRequest)
				instantiateRequestName = request.Name
				if tc.expectErr {
					return true, nil, fmt.Errorf("error")
				}
				return true, &buildv1.Build{}, nil
			})
		} else {
			buildClient.PrependReactor("create", "buildconfigs", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
				a, ok := action.(ktesting.CreateAction)
				if !ok {
					panic("unexpected action")
				}
				if a.GetSubresource() != "instantiate" {
					return false, nil, nil
				}
				request := a.GetObject().(*buildv1.BuildRequest)
				instantiateRequestName = request.Name
				return true, &buildv1.Build{}, nil
			})
		}
		controller := &BuildConfigController{
			buildLister:       &okBuildLister{},
			buildConfigGetter: buildClient.BuildV1(),
			buildGetter:       buildClient.BuildV1(),
			buildConfigLister: &okBuildConfigGetter{BuildConfig: tc.bc},
			recorder:          &record.FakeRecorder{},
		}
		err := controller.handleBuildConfig(tc.bc)
		if err != nil {
			if !tc.expectErr {
				t.Errorf("%s: unexpected error: %v", tc.name, err)
			}
			continue
		}
		if tc.expectErr {
			t.Errorf("%s: expected error, but got none", tc.name)
			continue
		}
		if tc.expectBuild && len(instantiateRequestName) == 0 {
			t.Errorf("%s: expected a build to be started.", tc.name)
		}
		if !tc.expectBuild && len(instantiateRequestName) > 0 {
			t.Errorf("%s: did not expect a build to be started.", tc.name)
		}
	}

}

func baseBuildConfig() *buildv1.BuildConfig {
	bc := &buildv1.BuildConfig{}
	bc.Name = "testBuildConfig"
	bc.Spec.Strategy.SourceStrategy = &buildv1.SourceBuildStrategy{}
	bc.Spec.Strategy.SourceStrategy.From.Name = "builderimage:latest"
	bc.Spec.Strategy.SourceStrategy.From.Kind = "ImageStreamTag"
	return bc
}

func buildConfigWithConfigChangeTrigger() *buildv1.BuildConfig {
	bc := baseBuildConfig()
	configChangeTrigger := buildv1.BuildTriggerPolicy{}
	configChangeTrigger.Type = buildv1.ConfigChangeBuildTriggerType
	bc.Spec.Triggers = append(bc.Spec.Triggers, configChangeTrigger)
	return bc
}

func buildConfigWithNonZeroLastVersion() *buildv1.BuildConfig {
	bc := buildConfigWithConfigChangeTrigger()
	bc.Status.LastVersion = 1
	return bc
}

type okBuildLister struct{}

func (okc *okBuildLister) List(label labels.Selector) ([]*buildv1.Build, error) {
	return nil, nil
}

func (okc *okBuildLister) Builds(ns string) buildlister.BuildNamespaceLister {
	return okc
}

func (okc *okBuildLister) Get(name string) (*buildv1.Build, error) {
	return nil, nil
}

type okBuildConfigGetter struct {
	BuildConfig *buildv1.BuildConfig
}

func (okc *okBuildConfigGetter) Get(name string) (*buildv1.BuildConfig, error) {
	if okc.BuildConfig != nil {
		return okc.BuildConfig, nil
	}
	return &buildv1.BuildConfig{}, nil
}

func (okc *okBuildConfigGetter) BuildConfigs(ns string) buildlister.BuildConfigNamespaceLister {
	return okc
}

func (okc *okBuildConfigGetter) List(label labels.Selector) ([]*buildv1.BuildConfig, error) {
	return nil, fmt.Errorf("not implemented")
}
