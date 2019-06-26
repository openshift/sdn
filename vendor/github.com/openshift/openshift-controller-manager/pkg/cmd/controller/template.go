package controller

import (
	templatecontroller "github.com/openshift/openshift-controller-manager/pkg/template/controller"
	"k8s.io/client-go/dynamic"
)

func RunTemplateInstanceController(ctx *ControllerContext) (bool, error) {
	saName := infraTemplateInstanceControllerServiceAccountName

	restConfig, err := ctx.ClientBuilder.Config(saName)
	if err != nil {
		return true, err
	}
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return true, err
	}

	go templatecontroller.NewTemplateInstanceController(
		ctx.RestMapper,
		dynamicClient,
		ctx.ClientBuilder.ClientOrDie(saName).AuthorizationV1(),
		ctx.ClientBuilder.ClientOrDie(saName),
		ctx.ClientBuilder.OpenshiftBuildClientOrDie(saName),
		ctx.ClientBuilder.OpenshiftTemplateClientOrDie(saName).TemplateV1(),
		ctx.TemplateInformers.Template().V1().TemplateInstances(),
	).Run(5, ctx.Stop)

	return true, nil
}

func RunTemplateInstanceFinalizerController(ctx *ControllerContext) (bool, error) {
	saName := infraTemplateInstanceFinalizerControllerServiceAccountName

	restConfig, err := ctx.ClientBuilder.Config(saName)
	if err != nil {
		return true, err
	}
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return true, err
	}

	go templatecontroller.NewTemplateInstanceFinalizerController(
		ctx.RestMapper,
		dynamicClient,
		ctx.ClientBuilder.OpenshiftTemplateClientOrDie(saName),
		ctx.TemplateInformers.Template().V1().TemplateInstances(),
	).Run(5, ctx.Stop)

	return true, nil
}
