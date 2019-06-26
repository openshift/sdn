package app

import (
	"path"

	"k8s.io/client-go/informers"
	"k8s.io/klog"
	"k8s.io/kubernetes/cmd/kube-controller-manager/app/config"
	"k8s.io/kubernetes/cmd/kube-controller-manager/app/options"
	utilflag "k8s.io/kubernetes/pkg/util/flag"
)

var InformerFactoryOverride informers.SharedInformerFactory

func ShimForOpenShift(controllerManagerOptions *options.KubeControllerManagerOptions, controllerManager *config.Config) error {
	if len(controllerManager.OpenShiftContext.OpenShiftConfig) == 0 {
		return nil
	}

	// TODO this gets removed when no longer take flags and no longer build a recycler template
	openshiftConfig, err := getOpenShiftConfig(controllerManager.OpenShiftContext.OpenShiftConfig)
	if err != nil {
		return err
	}

	// TODO this should be replaced by using a flex volume to inject service serving cert CAs into pods instead of adding it to the sa token
	if err := applyOpenShiftServiceServingCertCAFunc(path.Dir(controllerManager.OpenShiftContext.OpenShiftConfig), openshiftConfig); err != nil {
		return err
	}

	// skip GC on some openshift resources
	// TODO this should be replaced by discovery information in some way
	if err := applyOpenShiftGCConfig(controllerManager); err != nil {
		return err
	}

	// Overwrite the informers, because we have our custom generic informers for quota.
	// TODO update quota to create its own informer like garbage collection
	if informers, err := newInformerFactory(controllerManager.Kubeconfig); err != nil {
		return err
	} else {
		InformerFactoryOverride = informers
	}

	return nil
}

func ShimFlagsForOpenShift(controllerManagerOptions *options.KubeControllerManagerOptions) error {
	if len(controllerManagerOptions.OpenShiftContext.OpenShiftConfig) == 0 {
		return nil
	}

	// TODO this gets removed when no longer take flags and no longer build a recycler template
	openshiftConfig, err := getOpenShiftConfig(controllerManagerOptions.OpenShiftContext.OpenShiftConfig)
	if err != nil {
		return err
	}
	// apply the config based controller manager flags.  They will override.
	// TODO this should be replaced by the installer setting up the flags for us
	if err := applyOpenShiftConfigFlags(controllerManagerOptions, openshiftConfig); err != nil {
		return err
	}

	for name, fs := range controllerManagerOptions.Flags(KnownControllers(), ControllersDisabledByDefault.List()).FlagSets {
		klog.V(1).Infof("FLAGSET: %s", name)
		utilflag.PrintFlags(fs)
	}

	return nil
}
