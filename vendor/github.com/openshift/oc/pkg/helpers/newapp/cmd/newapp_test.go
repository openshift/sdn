package cmd

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/apitesting"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/meta/testrestmapper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/cli-runtime/pkg/resource"
	fakev1 "k8s.io/client-go/kubernetes/fake"
	clientfake "k8s.io/client-go/rest/fake"
	"k8s.io/client-go/restmapper"
	clientgotesting "k8s.io/client-go/testing"

	"github.com/openshift/api"
	buildv1 "github.com/openshift/api/build/v1"
	imagev1 "github.com/openshift/api/image/v1"
	templatev1 "github.com/openshift/api/template/v1"
	fakeimagev1client "github.com/openshift/client-go/image/clientset/versioned/fake"
	routefakev1client "github.com/openshift/client-go/route/clientset/versioned/fake"
	faketemplatev1client "github.com/openshift/client-go/template/clientset/versioned/fake"
	"github.com/openshift/oc/pkg/helpers/newapp"
	"github.com/openshift/oc/pkg/helpers/newapp/app"
	"github.com/openshift/source-to-image/pkg/scm/git"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		cfg                 AppConfig
		componentValues     []string
		sourceRepoLocations []string
		env                 map[string]string
		buildEnv            map[string]string
		parms               map[string]string
	}{
		"components": {
			cfg: AppConfig{
				ComponentInputs: ComponentInputs{
					Components: []string{"one", "two", "three/four"},
				},
			},
			componentValues:     []string{"one", "two", "three/four"},
			sourceRepoLocations: []string{},
			env:                 map[string]string{},
			buildEnv:            map[string]string{},
			parms:               map[string]string{},
		},
		"envs": {
			cfg: AppConfig{
				GenerationInputs: GenerationInputs{
					Environment: []string{"one=first", "two=second", "three=third"},
				},
			},
			componentValues:     []string{},
			sourceRepoLocations: []string{},
			env:                 map[string]string{"one": "first", "two": "second", "three": "third"},
			buildEnv:            map[string]string{},
			parms:               map[string]string{},
		},
		"build-envs": {
			cfg: AppConfig{
				GenerationInputs: GenerationInputs{
					BuildEnvironment: []string{"one=first", "two=second", "three=third"},
				},
			},
			componentValues:     []string{},
			sourceRepoLocations: []string{},
			env:                 map[string]string{},
			buildEnv:            map[string]string{"one": "first", "two": "second", "three": "third"},
			parms:               map[string]string{},
		},
		"component+source": {
			cfg: AppConfig{
				ComponentInputs: ComponentInputs{
					Components: []string{"one~https://server/repo.git"},
				},
			},
			componentValues:     []string{"one"},
			sourceRepoLocations: []string{"https://server/repo.git"},
			env:                 map[string]string{},
			buildEnv:            map[string]string{},
			parms:               map[string]string{},
		},
		"components+source": {
			cfg: AppConfig{
				ComponentInputs: ComponentInputs{
					Components: []string{"mysql+ruby~git://github.com/namespace/repo.git"},
				},
			},
			componentValues:     []string{"mysql", "ruby"},
			sourceRepoLocations: []string{"git://github.com/namespace/repo.git"},
			env:                 map[string]string{},
			buildEnv:            map[string]string{},
			parms:               map[string]string{},
		},
		"components+parms": {
			cfg: AppConfig{
				ComponentInputs: ComponentInputs{
					Components: []string{"ruby-helloworld-sample"},
				},
				GenerationInputs: GenerationInputs{
					TemplateParameters: []string{"one=first", "two=second"},
				},
			},
			componentValues:     []string{"ruby-helloworld-sample"},
			sourceRepoLocations: []string{},
			env:                 map[string]string{},
			buildEnv:            map[string]string{},
			parms:               map[string]string{"one": "first", "two": "second"},
		},
	}
	for n, c := range tests {
		b := &app.ReferenceBuilder{}
		env, buildEnv, parms, err := c.cfg.validate()
		if err != nil {
			t.Errorf("%s: Unexpected error: %v", n, err)
			continue
		}

		if err := AddComponentInputsToRefBuilder(b, &c.cfg.Resolvers, &c.cfg.ComponentInputs, &c.cfg.GenerationInputs, &c.cfg.SourceRepositories, &c.cfg.ImageStreams); err != nil {
			t.Errorf("%s: Unexpected error: %v", n, err)
			continue
		}
		cr, _, errs := b.Result()
		if len(errs) > 0 {
			t.Errorf("%s: Unexpected error: %v", n, errs)
			continue
		}

		compValues := []string{}
		for _, r := range cr {
			compValues = append(compValues, r.Input().Value)
		}
		if !reflect.DeepEqual(c.componentValues, compValues) {
			t.Errorf("%s: Component values don't match. Expected: %v, Got: %v", n, c.componentValues, compValues)
		}
		if len(env) != len(c.env) {
			t.Errorf("%s: Environment variables don't match. Expected: %v, Got: %v", n, c.env, env)
		}
		for e, v := range env {
			if c.env[e] != v {
				t.Errorf("%s: Environment variables don't match. Expected: %v, Got: %v", n, c.env, env)
				break
			}
		}
		if len(buildEnv) != len(c.buildEnv) {
			t.Errorf("%s: Environment variables don't match. Expected: %v, Got: %v", n, c.buildEnv, buildEnv)
		}
		for e, v := range buildEnv {
			if c.buildEnv[e] != v {
				t.Errorf("%s: Environment variables don't match. Expected: %v, Got: %v", n, c.buildEnv, buildEnv)
				break
			}
		}
		if len(parms) != len(c.parms) {
			t.Errorf("%s: Template parameters don't match. Expected: %v, Got: %v", n, c.parms, parms)
		}
		for p, v := range parms {
			if c.parms[p] != v {
				t.Errorf("%s: Template parameters don't match. Expected: %v, Got: %v", n, c.parms, parms)
				break
			}
		}
	}
}

func TestBuildTemplates(t *testing.T) {
	tests := map[string]struct {
		templateName string
		namespace    string
		parms        map[string]string
	}{
		"simple": {
			templateName: "first-stored-template",
			namespace:    "default",
			parms:        map[string]string{},
		},
	}
	for n, c := range tests {
		appCfg := AppConfig{}
		appCfg.Out = &bytes.Buffer{}
		appCfg.EnvironmentClassificationErrors = map[string]ArgumentClassificationError{}
		appCfg.SourceClassificationErrors = map[string]ArgumentClassificationError{}
		appCfg.TemplateClassificationErrors = map[string]ArgumentClassificationError{}
		appCfg.ComponentClassificationErrors = map[string]ArgumentClassificationError{}
		appCfg.ClassificationWinners = map[string]ArgumentClassificationWinner{}

		// the previous fake was broken and didn't 404 properly.  this test is relying on that
		imageFake := fakeimagev1client.NewSimpleClientset()
		templateFake := faketemplatev1client.NewSimpleClientset()
		routeFake := routefakev1client.NewSimpleClientset()

		customScheme, _ := apitesting.SchemeForOrDie(api.Install)

		appCfg.Builder = resource.NewFakeBuilder(
			func(version schema.GroupVersion) (resource.RESTClient, error) {
				return &clientfake.RESTClient{}, nil
			},
			func() (meta.RESTMapper, error) {
				return testrestmapper.TestOnlyStaticRESTMapper(customScheme, customScheme.PrioritizedVersionsAllGroups()...), nil
			},
			func() (restmapper.CategoryExpander, error) {
				return resource.FakeCategoryExpander, nil
			})

		appCfg.SetOpenShiftClient(
			imageFake.ImageV1(), templateFake.TemplateV1(), routeFake.RouteV1(),
			c.namespace, nil)
		appCfg.KubeClient = fakev1.NewSimpleClientset()
		appCfg.TemplateSearcher = fakeTemplateSearcher()
		appCfg.AddArguments([]string{c.templateName})
		appCfg.TemplateParameters = []string{}
		for k, v := range c.parms {
			appCfg.TemplateParameters = append(appCfg.TemplateParameters, fmt.Sprintf("%v=%v", k, v))
		}

		_, _, parms, err := appCfg.validate()
		if err != nil {
			t.Errorf("%s: Unexpected error: %v", n, err)
			continue
		}

		resolved, err := Resolve(&appCfg)
		if err != nil {
			t.Errorf("%s: Unexpected error: %v", n, err)
			continue
		}
		components := resolved.Components

		err = components.Resolve()
		if err != nil {
			t.Errorf("%s: Unexpected error: %v", n, err)
			continue
		}
		_, _, err = appCfg.buildTemplates(components, app.Environment(parms), app.Environment(map[string]string{}), app.Environment(map[string]string{}), fakeTemplateProcessor{})
		if err != nil {
			t.Errorf("%s: Unexpected error: %v", n, err)
		}
		for _, component := range components {
			match := component.Input().ResolvedMatch
			if !match.IsTemplate() {
				t.Errorf("%s: Expected template match, got: %v", n, match)
			}
			if fmt.Sprintf("%s/%s", c.namespace, c.templateName) != match.Name {
				t.Errorf("%s: Expected template name %q, got: %q", n, c.templateName, match.Name)
			}
			if len(parms) != len(c.parms) {
				t.Errorf("%s: Template parameters don't match. Expected: %v, Got: %v", n, c.parms, parms)
			}
			for p, v := range parms {
				if c.parms[p] != v {
					t.Errorf("%s: Template parameters don't match. Expected: %v, Got: %v", n, c.parms, parms)
					break
				}
			}
		}
	}
}

func fakeTemplateSearcher() app.Searcher {
	client := faketemplatev1client.NewSimpleClientset()
	client.PrependReactor("list", "templates", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, templateList(), nil
	})

	return app.TemplateSearcher{
		Client:     client.TemplateV1(),
		Namespaces: []string{"default"},
	}
}

func templateList() *templatev1.TemplateList {
	return &templatev1.TemplateList{
		Items: []templatev1.Template{
			{
				Objects: []runtime.RawExtension{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "first-stored-template",
					Namespace: "default",
				},
			},
		},
	}
}

func TestEnsureHasSource(t *testing.T) {
	gitLocalDir, err := git.CreateLocalGitDirectory()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(gitLocalDir)

	tests := []struct {
		name              string
		cfg               AppConfig
		components        app.ComponentReferences
		repositories      []*app.SourceRepository
		expectedErr       string
		dontExpectToBuild bool
	}{
		{
			name: "One requiresSource, multiple repositories",
			components: app.ComponentReferences{
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: true,
				}),
			},
			repositories: mockSourceRepositories(t, gitLocalDir),
			expectedErr:  "there are multiple code locations provided - use one of the following suggestions",
		},
		{
			name: "Multiple requiresSource, multiple repositories",
			components: app.ComponentReferences{
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: true,
				}),
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: true,
				}),
			},
			repositories: mockSourceRepositories(t, gitLocalDir),
			expectedErr:  "Use '[image]~[repo]' to declare which code goes with which image",
		},
		{
			name: "One requiresSource, no repositories",
			components: app.ComponentReferences{
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: true,
				}),
			},
			repositories:      []*app.SourceRepository{},
			expectedErr:       "",
			dontExpectToBuild: true,
		},
		{
			name: "Multiple requiresSource, no repositories",
			components: app.ComponentReferences{
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: true,
				}),
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: true,
				}),
			},
			repositories:      []*app.SourceRepository{},
			expectedErr:       "",
			dontExpectToBuild: true,
		},
		{
			name: "Successful - one repository",
			components: app.ComponentReferences{
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: false,
				}),
			},
			repositories: mockSourceRepositories(t, gitLocalDir)[:1],
			expectedErr:  "",
		},
		{
			name: "Successful - no requiresSource",
			components: app.ComponentReferences{
				app.ComponentReference(&app.ComponentInput{
					ExpectToBuild: false,
				}),
			},
			repositories: mockSourceRepositories(t, gitLocalDir),
			expectedErr:  "",
		},
	}
	for _, test := range tests {
		err := EnsureHasSource(test.components, test.repositories, &test.cfg.GenerationInputs)
		if err != nil {
			if !strings.Contains(err.Error(), test.expectedErr) {
				t.Errorf("%s: Invalid error: Expected %s, got %v", test.name, test.expectedErr, err)
			}
		} else if len(test.expectedErr) != 0 {
			t.Errorf("%s: Expected %s error but got none", test.name, test.expectedErr)
		}
		if test.dontExpectToBuild {
			for _, comp := range test.components {
				if comp.NeedsSource() {
					t.Errorf("%s: expected component reference to not require source.", test.name)
				}
			}
		}
	}
}

// mockSourceRepositories is a set of mocked source repositories used for
// testing.
func mockSourceRepositories(t *testing.T, file string) []*app.SourceRepository {
	var b []*app.SourceRepository
	for _, location := range []string{
		"https://github.com/openshift/ruby-hello-world.git",
		file,
	} {
		s, err := app.NewSourceRepository(location, newapp.StrategySource)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, s)
	}
	return b
}

// Make sure that buildPipelines defaults DockerImage.Config if needed to
// avoid a nil panic.
func TestBuildPipelinesWithUnresolvedImage(t *testing.T) {
	dockerFile, err := app.NewDockerfile("FROM centos\nEXPOSE 1234\nEXPOSE 4567")
	if err != nil {
		t.Fatal(err)
	}

	sourceRepo, err := app.NewSourceRepository("https://github.com/foo/bar.git", newapp.StrategyDocker)
	if err != nil {
		t.Fatal(err)
	}
	sourceRepo.SetInfo(&app.SourceRepositoryInfo{
		Dockerfile: dockerFile,
	})

	refs := app.ComponentReferences{
		app.ComponentReference(&app.ComponentInput{
			Value:         "mysql",
			Uses:          sourceRepo,
			ExpectToBuild: true,
			ResolvedMatch: &app.ComponentMatch{
				Value: "mysql",
			},
		}),
	}

	a := AppConfig{}
	a.Out = &bytes.Buffer{}
	group, err := a.buildPipelines(refs, app.Environment{}, app.Environment{})
	if err != nil {
		t.Error(err)
	}

	expectedPorts := sets.NewString("1234", "4567")
	actualPorts := sets.NewString()
	for port := range group[0].InputImage.Info.Config.ExposedPorts {
		actualPorts.Insert(port)
	}
	if e, a := expectedPorts.List(), actualPorts.List(); !reflect.DeepEqual(e, a) {
		t.Errorf("Expected ports=%v, got %v", e, a)
	}
}

func TestBuildOutputCycleResilience(t *testing.T) {

	config := &AppConfig{}

	mockIS := &imagev1.ImageStream{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mockimagestream",
		},
		Spec: imagev1.ImageStreamSpec{
			Tags: []imagev1.TagReference{
				{
					Name: "latest",
					From: &corev1.ObjectReference{
						Kind: "DockerImage",
						Name: "mockimage:latest",
					},
				},
			},
		},
	}

	dfn := "mockdockerfilename"
	malOutputBC := &buildv1.BuildConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "buildCfgWithWeirdOutputObjectRef",
		},
		Spec: buildv1.BuildConfigSpec{
			CommonSpec: buildv1.CommonSpec{
				Source: buildv1.BuildSource{
					Dockerfile: &dfn,
				},
				Strategy: buildv1.BuildStrategy{
					DockerStrategy: &buildv1.DockerBuildStrategy{
						From: &corev1.ObjectReference{
							Kind: "ImageStreamTag",
							Name: "mockimagestream:latest",
						},
					},
				},
				Output: buildv1.BuildOutput{
					To: &corev1.ObjectReference{
						Kind: "NewTypeOfRef",
						Name: "Yet-to-be-implemented",
					},
				},
			},
		},
	}

	_, err := config.followRefToDockerImage(malOutputBC.Spec.Output.To, nil, []runtime.Object{malOutputBC, mockIS})
	expected := "Unable to follow reference type: \"NewTypeOfRef\""
	if err == nil || err.Error() != expected {
		t.Errorf("Expected error from followRefToDockerImage: got \"%v\" versus expected %q", err, expected)
	}
}

func TestBuildOutputCycleWithCircularTag(t *testing.T) {

	dfn := "mockdockerfilename"

	tests := []struct {
		bc       *buildv1.BuildConfig
		is       []runtime.Object
		expected string
	}{
		{
			bc: &buildv1.BuildConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "buildCfgWithWeirdOutputObjectRef",
				},
				Spec: buildv1.BuildConfigSpec{
					CommonSpec: buildv1.CommonSpec{
						Source: buildv1.BuildSource{
							Dockerfile: &dfn,
						},
						Strategy: buildv1.BuildStrategy{
							DockerStrategy: &buildv1.DockerBuildStrategy{
								From: &corev1.ObjectReference{
									Kind: "ImageStreamTag",
									Name: "mockimagestream:latest",
								},
							},
						},
						Output: buildv1.BuildOutput{
							To: &corev1.ObjectReference{
								Kind: "ImageStreamTag",
								Name: "mockimagestream:10.0",
							},
						},
					},
				},
			},
			is: []runtime.Object{
				&imagev1.ImageStream{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mockimagestream",
					},
					Spec: imagev1.ImageStreamSpec{
						Tags: []imagev1.TagReference{
							{
								Name: "latest",
								From: &corev1.ObjectReference{
									Kind: "ImageStreamTag",
									Name: "10.0",
								},
							},
							{
								Name: "10.0",
								From: &corev1.ObjectReference{
									Kind: "ImageStreamTag",
									Name: "latest",
								},
							},
						},
					},
				},
			},
			expected: "image stream tag reference \"mockimagestream:latest\" is a circular loop of image stream tags",
		},
		{
			bc: &buildv1.BuildConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "buildCfgWithWeirdOutputObjectRef",
				},
				Spec: buildv1.BuildConfigSpec{
					CommonSpec: buildv1.CommonSpec{
						Source: buildv1.BuildSource{
							Dockerfile: &dfn,
						},
						Strategy: buildv1.BuildStrategy{
							DockerStrategy: &buildv1.DockerBuildStrategy{
								From: &corev1.ObjectReference{
									Kind: "ImageStreamTag",
									Name: "mockimagestream:latest",
								},
							},
						},
						Output: buildv1.BuildOutput{
							To: &corev1.ObjectReference{
								Kind: "ImageStreamTag",
								Name: "fakeimagestream:latest",
							},
						},
					},
				},
			},
			is: []runtime.Object{
				&imagev1.ImageStream{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mockimagestream",
					},
					Spec: imagev1.ImageStreamSpec{
						Tags: []imagev1.TagReference{
							{
								Name: "latest",
								From: &corev1.ObjectReference{
									Kind: "ImageStreamTag",
									Name: "fakeimagestream:latest",
								},
							},
						},
					},
				},
				&imagev1.ImageStream{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fakeimagestream",
					},
					Spec: imagev1.ImageStreamSpec{
						Tags: []imagev1.TagReference{
							{
								Name: "latest",
								From: &corev1.ObjectReference{
									Kind: "ImageStreamTag",
									Name: "mockimagestream:latest",
								},
							},
						},
					},
				},
			},
			expected: "image stream tag reference \"mockimagestream:latest\" is a circular loop of image stream tags",
		},
	}

	config := &AppConfig{}
	for _, test := range tests {
		imageFake := fakeimagev1client.NewSimpleClientset()
		imageFakeConfig := fakeimagev1client.NewSimpleClientset(test.is...)

		objs := append(test.is, test.bc)
		// so we test both with the fake image client seeded with the image streams, i.e. existing image streams
		// and without, i.e. the generate flow is creating the image streams as well
		config.ImageClient = imageFake.ImageV1()
		err := config.checkCircularReferences(objs)
		if err == nil || err.Error() != test.expected {
			t.Errorf("Expected error from followRefToDockerImage: got \"%v\" versus expected %q", err, test.expected)
		}
		config.ImageClient = imageFakeConfig.ImageV1()
		err = config.checkCircularReferences(objs)
		if err == nil || err.Error() != test.expected {
			t.Errorf("Expected error from followRefToDockerImage: got \"%v\" versus expected %q", err, test.expected)
		}
	}
}
