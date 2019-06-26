package controller

import (
	"k8s.io/klog"

	kapiv1 "k8s.io/api/core/v1"
	sacontroller "k8s.io/kubernetes/pkg/controller/serviceaccount"

	serviceaccountcontrollers "github.com/openshift/openshift-controller-manager/pkg/serviceaccounts/controllers"
)

func RunServiceAccountController(ctx *ControllerContext) (bool, error) {
	if len(ctx.OpenshiftControllerConfig.ServiceAccount.ManagedNames) == 0 {
		klog.Infof("Skipped starting Service Account Manager, no managed names specified")
		return false, nil
	}

	options := sacontroller.DefaultServiceAccountsControllerOptions()
	options.ServiceAccounts = []kapiv1.ServiceAccount{}

	for _, saName := range ctx.OpenshiftControllerConfig.ServiceAccount.ManagedNames {
		// the upstream controller does this one, so we don't have to
		if saName == "default" {
			continue
		}
		sa := kapiv1.ServiceAccount{}
		sa.Name = saName

		options.ServiceAccounts = append(options.ServiceAccounts, sa)
	}

	controller, err := sacontroller.NewServiceAccountsController(
		ctx.KubernetesInformers.Core().V1().ServiceAccounts(),
		ctx.KubernetesInformers.Core().V1().Namespaces(),
		ctx.ClientBuilder.ClientOrDie(infraServiceAccountControllerServiceAccountName),
		options)
	if err != nil {
		return true, nil
	}
	go controller.Run(3, ctx.Stop)

	return true, nil
}

func RunServiceAccountPullSecretsController(ctx *ControllerContext) (bool, error) {
	kc := ctx.ClientBuilder.ClientOrDie(iInfraServiceAccountPullSecretsControllerServiceAccountName)

	go serviceaccountcontrollers.NewDockercfgDeletedController(
		ctx.KubernetesInformers.Core().V1().Secrets(),
		kc,
		serviceaccountcontrollers.DockercfgDeletedControllerOptions{},
	).Run(ctx.Stop)

	go serviceaccountcontrollers.NewDockercfgTokenDeletedController(
		ctx.KubernetesInformers.Core().V1().Secrets(),
		kc,
		serviceaccountcontrollers.DockercfgTokenDeletedControllerOptions{},
	).Run(ctx.Stop)

	dockerURLsInitialized := make(chan struct{})
	dockercfgController := serviceaccountcontrollers.NewDockercfgController(
		ctx.KubernetesInformers.Core().V1().ServiceAccounts(),
		ctx.KubernetesInformers.Core().V1().Secrets(),
		kc,
		serviceaccountcontrollers.DockercfgControllerOptions{DockerURLsInitialized: dockerURLsInitialized},
	)
	go dockercfgController.Run(5, ctx.Stop)

	dockerRegistryControllerOptions := serviceaccountcontrollers.DockerRegistryServiceControllerOptions{
		DockercfgController:    dockercfgController,
		DockerURLsInitialized:  dockerURLsInitialized,
		ClusterDNSSuffix:       "cluster.local",
		AdditionalRegistryURLs: ctx.OpenshiftControllerConfig.DockerPullSecret.RegistryURLs,
	}
	go serviceaccountcontrollers.NewDockerRegistryServiceController(
		ctx.KubernetesInformers.Core().V1().Secrets(),
		ctx.KubernetesInformers.Core().V1().Services(),
		kc,
		dockerRegistryControllerOptions,
	).Run(10, ctx.Stop)

	return true, nil
}
