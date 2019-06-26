package servicebroker

import (
	"net/http"

	"k8s.io/klog"

	authorizationv1 "k8s.io/api/authorization/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	templateapi "github.com/openshift/template-service-broker/apis/template"
	"github.com/openshift/template-service-broker/pkg/openservicebroker/api"
	"github.com/openshift/template-service-broker/pkg/util"
)

// Deprovision is the reverse of Provision.  We clean up the TemplateInstance,
// Secret and BrokerTemplateInstance objects (in that order); the garbage
// collector is responsible for the removal of the objects provisioned by the
// Template(Instance) itself.
func (b *Broker) Deprovision(u user.Info, instanceID string) *api.Response {
	klog.V(4).Infof("Template service broker: Deprovision: instanceID %s", instanceID)

	brokerTemplateInstance, err := b.templateclient.BrokerTemplateInstances().Get(instanceID, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return api.NewResponse(http.StatusGone, &api.DeprovisionResponse{}, nil)
		}
		return api.InternalServerError(err)
	}

	namespace := brokerTemplateInstance.Spec.TemplateInstance.Namespace

	// end users are not expected to have access to BrokerTemplateInstance
	// objects; SAR on the TemplateInstance instead.

	if err := util.Authorize(b.kc.AuthorizationV1().SubjectAccessReviews(), u, &authorizationv1.ResourceAttributes{
		Namespace: namespace,
		Verb:      "get",
		Group:     templateapi.GroupName,
		Resource:  "templateinstances",
		Name:      brokerTemplateInstance.Spec.TemplateInstance.Name,
	}); err != nil {
		return api.Forbidden(err)
	}

	if err := util.Authorize(b.kc.AuthorizationV1().SubjectAccessReviews(), u, &authorizationv1.ResourceAttributes{
		Namespace: namespace,
		Verb:      "delete",
		Group:     templateapi.GroupName,
		Resource:  "templateinstances",
		Name:      brokerTemplateInstance.Spec.TemplateInstance.Name,
	}); err != nil {
		return api.Forbidden(err)
	}

	opts := metav1.NewPreconditionDeleteOptions(string(brokerTemplateInstance.UID))
	policy := metav1.DeletePropagationForeground
	opts.PropagationPolicy = &policy
	err = b.templateclient.BrokerTemplateInstances().Delete(instanceID, opts)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return api.NewResponse(http.StatusGone, &api.DeprovisionResponse{}, nil)
		}
		return api.InternalServerError(err)
	}

	return api.NewResponse(http.StatusAccepted, &api.DeprovisionResponse{Operation: api.OperationDeprovisioning}, nil)
}
