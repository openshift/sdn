package printers

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	kprinters "k8s.io/kubernetes/pkg/printers"
	kprintersinternal "k8s.io/kubernetes/pkg/printers/internalversion"

	"github.com/openshift/api/annotations"
	appsapi "github.com/openshift/api/apps/v1"
	authorizationapi "github.com/openshift/api/authorization/v1"
	buildapi "github.com/openshift/api/build/v1"
	imageapi "github.com/openshift/api/image/v1"
	networkapi "github.com/openshift/api/network/v1"
	oauthapi "github.com/openshift/api/oauth/v1"
	projectapi "github.com/openshift/api/project/v1"
	quotaapi "github.com/openshift/api/quota/v1"
	routeapi "github.com/openshift/api/route/v1"
	securityapi "github.com/openshift/api/security/v1"
	templateapi "github.com/openshift/api/template/v1"
	userapi "github.com/openshift/api/user/v1"
	authorizationhelpers "github.com/openshift/oc/pkg/helpers/authorization"
	buildhelpers "github.com/openshift/oc/pkg/helpers/build"
	imagehelpers "github.com/openshift/oc/pkg/helpers/image"
	quotahelpers "github.com/openshift/oc/pkg/helpers/quota"
)

var (
	buildColumns                = []string{"NAME", "TYPE", "FROM", "STATUS", "STARTED", "DURATION"}
	buildConfigColumns          = []string{"NAME", "TYPE", "FROM", "LATEST"}
	imageColumns                = []string{"NAME", "IMAGE REF"}
	imageStreamTagColumns       = []string{"NAME", "IMAGE REF", "UPDATED"}
	imageStreamTagWideColumns   = []string{"NAME", "IMAGE REF", "UPDATED", "IMAGENAME"}
	imageStreamImageColumns     = []string{"NAME", "UPDATED"}
	imageStreamImageWideColumns = []string{"NAME", "IMAGE REF", "UPDATED", "IMAGENAME"}
	imageStreamColumns          = []string{"NAME", "IMAGE REPOSITORY", "TAGS", "UPDATED"}
	projectColumns              = []string{"NAME", "DISPLAY NAME", "STATUS"}
	routeColumns                = []string{"NAME", "HOST/PORT", "PATH", "SERVICES", "PORT", "TERMINATION", "WILDCARD"}
	deploymentConfigColumns     = []string{"NAME", "REVISION", "DESIRED", "CURRENT", "TRIGGERED BY"}
	templateColumns             = []string{"NAME", "DESCRIPTION", "PARAMETERS", "OBJECTS"}
	roleBindingColumns          = []string{"NAME", "ROLE", "USERS", "GROUPS", "SERVICE ACCOUNTS", "SUBJECTS"}
	roleColumns                 = []string{"NAME"}

	oauthClientColumns              = []string{"NAME", "SECRET", "WWW-CHALLENGE", "TOKEN-MAX-AGE", "REDIRECT URIS"}
	oauthClientAuthorizationColumns = []string{"NAME", "USER NAME", "CLIENT NAME", "SCOPES"}
	oauthAccessTokenColumns         = []string{"NAME", "USER NAME", "CLIENT NAME", "CREATED", "EXPIRES", "REDIRECT URI", "SCOPES"}
	oauthAuthorizeTokenColumns      = []string{"NAME", "USER NAME", "CLIENT NAME", "CREATED", "EXPIRES", "REDIRECT URI", "SCOPES"}

	userColumns                = []string{"NAME", "UID", "FULL NAME", "IDENTITIES"}
	identityColumns            = []string{"NAME", "IDP NAME", "IDP USER NAME", "USER NAME", "USER UID"}
	userIdentityMappingColumns = []string{"NAME", "IDENTITY", "USER NAME", "USER UID"}
	groupColumns               = []string{"NAME", "USERS"}

	// IsPersonalSubjectAccessReviewColumns contains known custom role extensions
	IsPersonalSubjectAccessReviewColumns = []string{"NAME"}

	hostSubnetColumns          = []string{"NAME", "HOST", "HOST IP", "SUBNET", "EGRESS CIDRS", "EGRESS IPS"}
	netNamespaceColumns        = []string{"NAME", "NETID", "EGRESS IPS"}
	clusterNetworkColumns      = []string{"NAME", "CLUSTER NETWORKS", "SERVICE NETWORK", "PLUGIN NAME"}
	egressNetworkPolicyColumns = []string{"NAME"}

	clusterResourceQuotaColumns = []string{"NAME", "LABEL SELECTOR", "ANNOTATION SELECTOR"}

	roleBindingRestrictionColumns = []string{"NAME", "SUBJECT TYPE", "SUBJECTS"}

	templateInstanceColumns       = []string{"NAME", "TEMPLATE"}
	brokerTemplateInstanceColumns = []string{"NAME", "TEMPLATEINSTANCE"}

	policyRuleColumns = []string{"VERBS", "NON-RESOURCE URLS", "RESOURCE NAMES", "API GROUPS", "RESOURCES"}

	securityContextConstraintsColumns = []string{"NAME", "PRIV", "CAPS", "SELINUX", "RUNASUSER", "FSGROUP", "SUPGROUP", "PRIORITY", "READONLYROOTFS", "VOLUMES"}
	rangeAllocationColumns            = []string{"NAME", "RANGE", "DATA"}
)

func init() {
	// TODO this should be eliminated
	kprintersinternal.AddHandlers = func(p kprinters.PrintHandler) {
		kprintersinternal.AddKubeHandlers(p)
		AddHandlers(p)
	}
}

// AddHandlers adds print handlers for internal openshift API objects
func AddHandlers(p kprinters.PrintHandler) {
	p.Handler(buildColumns, nil, printBuild)
	p.Handler(buildColumns, nil, printBuildList)
	p.Handler(buildConfigColumns, nil, printBuildConfig)
	p.Handler(buildConfigColumns, nil, printBuildConfigList)
	p.Handler(policyRuleColumns, nil, printSubjectRulesReview)
	p.Handler(policyRuleColumns, nil, printSelfSubjectRulesReview)
	p.Handler(imageColumns, nil, printImage)
	p.Handler(imageStreamTagColumns, imageStreamTagWideColumns, printImageStreamTag)
	p.Handler(imageStreamTagColumns, imageStreamTagWideColumns, printImageStreamTagList)
	p.Handler(imageStreamImageColumns, imageStreamImageWideColumns, printImageStreamImage)
	p.Handler(imageColumns, nil, printImageList)
	p.Handler(imageStreamColumns, nil, printImageStream)
	p.Handler(imageStreamColumns, nil, printImageStreamList)
	p.Handler(projectColumns, nil, printProject)
	p.Handler(projectColumns, nil, printProjectList)
	p.Handler(routeColumns, nil, printRoute)
	p.Handler(routeColumns, nil, printRouteList)
	p.Handler(deploymentConfigColumns, nil, printDeploymentConfig)
	p.Handler(deploymentConfigColumns, nil, printDeploymentConfigList)
	p.Handler(templateColumns, nil, printTemplate)
	p.Handler(templateColumns, nil, printTemplateList)

	p.Handler(roleBindingColumns, nil, printRoleBinding)
	p.Handler(roleBindingColumns, nil, printRoleBindingList)
	p.Handler(roleColumns, nil, printRole)
	p.Handler(roleColumns, nil, printRoleList)

	p.Handler(roleColumns, nil, printClusterRole)
	p.Handler(roleColumns, nil, printClusterRoleList)
	p.Handler(roleBindingColumns, nil, printClusterRoleBinding)
	p.Handler(roleBindingColumns, nil, printClusterRoleBindingList)

	p.Handler(oauthClientColumns, nil, printOAuthClient)
	p.Handler(oauthClientColumns, nil, printOAuthClientList)
	p.Handler(oauthClientAuthorizationColumns, nil, printOAuthClientAuthorization)
	p.Handler(oauthClientAuthorizationColumns, nil, printOAuthClientAuthorizationList)
	p.Handler(oauthAccessTokenColumns, nil, printOAuthAccessToken)
	p.Handler(oauthAccessTokenColumns, nil, printOAuthAccessTokenList)
	p.Handler(oauthAuthorizeTokenColumns, nil, printOAuthAuthorizeToken)
	p.Handler(oauthAuthorizeTokenColumns, nil, printOAuthAuthorizeTokenList)

	p.Handler(userColumns, nil, printUser)
	p.Handler(userColumns, nil, printUserList)
	p.Handler(identityColumns, nil, printIdentity)
	p.Handler(identityColumns, nil, printIdentityList)
	p.Handler(userIdentityMappingColumns, nil, printUserIdentityMapping)
	p.Handler(groupColumns, nil, printGroup)
	p.Handler(groupColumns, nil, printGroupList)

	p.Handler(IsPersonalSubjectAccessReviewColumns, nil, printIsPersonalSubjectAccessReview)

	p.Handler(hostSubnetColumns, nil, printHostSubnet)
	p.Handler(hostSubnetColumns, nil, printHostSubnetList)
	p.Handler(netNamespaceColumns, nil, printNetNamespaceList)
	p.Handler(netNamespaceColumns, nil, printNetNamespace)
	p.Handler(clusterNetworkColumns, nil, printClusterNetwork)
	p.Handler(clusterNetworkColumns, nil, printClusterNetworkList)
	p.Handler(egressNetworkPolicyColumns, nil, printEgressNetworkPolicy)
	p.Handler(egressNetworkPolicyColumns, nil, printEgressNetworkPolicyList)

	p.Handler(clusterResourceQuotaColumns, nil, printClusterResourceQuota)
	p.Handler(clusterResourceQuotaColumns, nil, printClusterResourceQuotaList)
	p.Handler(clusterResourceQuotaColumns, nil, printAppliedClusterResourceQuota)
	p.Handler(clusterResourceQuotaColumns, nil, printAppliedClusterResourceQuotaList)

	p.Handler(roleBindingRestrictionColumns, nil, printRoleBindingRestriction)
	p.Handler(roleBindingRestrictionColumns, nil, printRoleBindingRestrictionList)

	p.Handler(templateInstanceColumns, nil, printTemplateInstance)
	p.Handler(templateInstanceColumns, nil, printTemplateInstanceList)
	p.Handler(brokerTemplateInstanceColumns, nil, printBrokerTemplateInstance)
	p.Handler(brokerTemplateInstanceColumns, nil, printBrokerTemplateInstanceList)

	p.Handler(securityContextConstraintsColumns, nil, printSecurityContextConstraints)
	p.Handler(securityContextConstraintsColumns, nil, printSecurityContextConstraintsList)
	p.Handler(rangeAllocationColumns, nil, printRangeAllocation)
	p.Handler(rangeAllocationColumns, nil, printRangeAllocationList)
}

const templateDescriptionLen = 80

// formatResourceName receives a resource kind, name, and boolean specifying
// whether or not to update the current name to "kind/name"
func formatResourceName(kind schema.GroupKind, name string, withKind bool) string {
	if !withKind || kind.Empty() {
		return name
	}

	return strings.ToLower(kind.String()) + "/" + name
}

func printTemplate(t *templateapi.Template, w io.Writer, opts kprinters.PrintOptions) error {
	description := ""
	if t.Annotations != nil {
		description = t.Annotations["description"]
	}
	// Only print the first line of description
	if lines := strings.SplitN(description, "\n", 2); len(lines) > 1 {
		description = lines[0] + "..."
	}
	if len(description) > templateDescriptionLen {
		description = strings.TrimSpace(description[:templateDescriptionLen-3]) + "..."
	}
	empty, generated, total := 0, 0, len(t.Parameters)
	for _, p := range t.Parameters {
		if len(p.Value) > 0 {
			continue
		}
		if len(p.Generate) > 0 {
			generated++
			continue
		}
		empty++
	}
	params := ""
	switch {
	case empty > 0:
		params = fmt.Sprintf("%d (%d blank)", total, empty)
	case generated > 0:
		params = fmt.Sprintf("%d (%d generated)", total, generated)
	default:
		params = fmt.Sprintf("%d (all set)", total)
	}

	name := formatResourceName(opts.Kind, t.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", t.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d", name, description, params, len(t.Objects)); err != nil {
		return err
	}
	if err := appendItemLabels(t.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printTemplateList(list *templateapi.TemplateList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, t := range list.Items {
		if err := printTemplate(&t, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printBuild(build *buildapi.Build, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, build.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", build.Namespace); err != nil {
			return err
		}
	}
	var created string
	if build.Status.StartTimestamp != nil {
		created = fmt.Sprintf("%s ago", formatRelativeTime(build.Status.StartTimestamp.Time))
	}
	var duration string
	if build.Status.Duration > 0 {
		duration = build.Status.Duration.String()
	}
	from := describeSourceShort(build.Spec.CommonSpec)
	status := string(build.Status.Phase)
	if len(build.Status.Reason) > 0 {
		status = fmt.Sprintf("%s (%s)", status, build.Status.Reason)
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s", name, buildhelpers.StrategyType(build.Spec.Strategy), from, status, created,
		duration); err != nil {
		return err
	}
	if err := appendItemLabels(build.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func describeSourceShort(spec buildapi.CommonSpec) string {
	var from string
	switch source := spec.Source; {
	case source.Binary != nil:
		from = "Binary"
		if rev := describeSourceGitRevision(spec); len(rev) != 0 {
			from = fmt.Sprintf("%s@%s", from, rev)
		}
	case source.Dockerfile != nil && source.Git != nil:
		from = "Dockerfile,Git"
		if rev := describeSourceGitRevision(spec); len(rev) != 0 {
			from = fmt.Sprintf("%s@%s", from, rev)
		}
	case source.Dockerfile != nil:
		from = "Dockerfile"
	case source.Git != nil:
		from = "Git"
		if rev := describeSourceGitRevision(spec); len(rev) != 0 {
			from = fmt.Sprintf("%s@%s", from, rev)
		}
	default:
		from = buildSourceType(source)
	}
	return from
}

func buildSourceType(source buildapi.BuildSource) string {
	var sourceType string
	if source.Git != nil {
		sourceType = "Git"
	}
	if source.Dockerfile != nil {
		if len(sourceType) != 0 {
			sourceType = sourceType + ","
		}
		sourceType = sourceType + "Dockerfile"
	}
	if source.Binary != nil {
		if len(sourceType) != 0 {
			sourceType = sourceType + ","
		}
		sourceType = sourceType + "Binary"
	}
	return sourceType
}

var nonCommitRev = regexp.MustCompile("[^a-fA-F0-9]")

func describeSourceGitRevision(spec buildapi.CommonSpec) string {
	var rev string
	if spec.Revision != nil && spec.Revision.Git != nil {
		rev = spec.Revision.Git.Commit
	}
	if len(rev) == 0 && spec.Source.Git != nil {
		rev = spec.Source.Git.Ref
	}
	// if this appears to be a full Git commit hash, shorten it to 7 characters for brevity
	if !nonCommitRev.MatchString(rev) && len(rev) > 20 {
		rev = rev[:7]
	}
	return rev
}

func printBuildList(buildList *buildapi.BuildList, w io.Writer, opts kprinters.PrintOptions) error {
	builds := buildList.Items
	sort.Sort(buildhelpers.BuildSliceByCreationTimestamp(builds))
	for _, build := range builds {
		if err := printBuild(&build, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printBuildConfig(bc *buildapi.BuildConfig, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, bc.Name, opts.WithKind)
	from := describeSourceShort(bc.Spec.CommonSpec)

	if bc.Spec.Strategy.CustomStrategy != nil {
		if opts.WithNamespace {
			if _, err := fmt.Fprintf(w, "%s\t", bc.Namespace); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "%s\t%v\t%s\t%d\n", name, buildhelpers.StrategyType(bc.Spec.Strategy),
			bc.Spec.Strategy.CustomStrategy.From.Name, bc.Status.LastVersion)
		return err
	}
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", bc.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%v\t%s\t%d", name, buildhelpers.StrategyType(bc.Spec.Strategy), from,
		bc.Status.LastVersion); err != nil {
		return err
	}
	if err := appendItemLabels(bc.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printSubjectRulesReview(rulesReview *authorizationapi.SubjectRulesReview, w io.Writer, opts kprinters.PrintOptions) error {
	printPolicyRule(rulesReview.Status.Rules, w)
	return nil
}

func printSelfSubjectRulesReview(selfSubjectRulesReview *authorizationapi.SelfSubjectRulesReview, w io.Writer, opts kprinters.PrintOptions) error {
	printPolicyRule(selfSubjectRulesReview.Status.Rules, w)
	return nil
}

func printPolicyRule(policyRules []authorizationapi.PolicyRule, w io.Writer) error {
	for _, rule := range policyRules {
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\n",
			rule.Verbs,
			rule.NonResourceURLsSlice,
			rule.ResourceNames,
			rule.APIGroups,
			rule.Resources,
		)
	}
	return nil
}

func printBuildConfigList(buildList *buildapi.BuildConfigList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, buildConfig := range buildList.Items {
		if err := printBuildConfig(&buildConfig, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printImage(image *imageapi.Image, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, image.Name, opts.WithKind)

	if _, err := fmt.Fprintf(w, "%s\t%s", name, image.DockerImageReference); err != nil {
		return err
	}
	if err := appendItemLabels(image.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printImageStreamTag(ist *imageapi.ImageStreamTag, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, ist.Name, opts.WithKind)
	created := fmt.Sprintf("%s ago", formatRelativeTime(ist.CreationTimestamp.Time))

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", ist.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s", name, ist.Image.DockerImageReference, created); err != nil {
		return err
	}
	if opts.Wide {
		if _, err := fmt.Fprintf(w, "\t%s", ist.Image.Name); err != nil {
			return err
		}
	}
	if err := appendItemLabels(ist.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printImageStreamTagList(list *imageapi.ImageStreamTagList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, ist := range list.Items {
		if err := printImageStreamTag(&ist, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printImageStreamImage(isi *imageapi.ImageStreamImage, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, isi.Name, opts.WithKind)
	created := fmt.Sprintf("%s ago", formatRelativeTime(isi.CreationTimestamp.Time))
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", isi.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s", name, created); err != nil {
		return err
	}
	if opts.Wide {
		if _, err := fmt.Fprintf(w, "\t%s\t%s", isi.Image.DockerImageReference, isi.Image.Name); err != nil {
			return err
		}

	}
	if err := appendItemLabels(isi.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printImageList(images *imageapi.ImageList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, image := range images.Items {
		if err := printImage(&image, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printImageStream(stream *imageapi.ImageStream, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, stream.Name, opts.WithKind)

	var latest metav1.Time
	for _, list := range stream.Status.Tags {
		if len(list.Items) > 0 {
			if list.Items[0].Created.After(latest.Time) {
				latest = list.Items[0].Created
			}
		}
	}
	latestTime := ""
	if !latest.IsZero() {
		latestTime = fmt.Sprintf("%s ago", formatRelativeTime(latest.Time))
	}

	tags := printTagsUpToWidth(stream.Status.Tags, 40)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", stream.Namespace); err != nil {
			return err
		}
	}
	repo := stream.Spec.DockerImageRepository
	if len(repo) == 0 {
		repo = stream.Status.DockerImageRepository
	}
	if len(stream.Status.PublicDockerImageRepository) > 0 {
		repo = stream.Status.PublicDockerImageRepository
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s", name, repo, tags, latestTime); err != nil {
		return err
	}
	if err := appendItemLabels(stream.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

// printTagsUpToWidth displays a human readable list of tags with as many tags as will fit in the
// width we budget. It will always display at least one tag, and will allow a slightly wider width
// if it's less than 25% of the total width to feel more even.
func printTagsUpToWidth(statusTags []imageapi.NamedTagEventList, preferredWidth int) string {
	tags := imagehelpers.SortStatusTags(statusTags)
	remaining := preferredWidth
	for i, tag := range tags {
		remaining -= len(tag) + 1
		if remaining >= 0 {
			continue
		}
		if i == 0 {
			tags = tags[:1]
			break
		}
		// if we've left more than 25% of the width unfilled, and adding the current tag would be
		// less than 125% of the preferred width, keep going in order to make the edges less ragged.
		margin := preferredWidth / 4
		if margin < (remaining+len(tag)) && margin >= (-remaining) {
			continue
		}
		tags = tags[:i]
		break
	}
	if hiddenTags := len(statusTags) - len(tags); hiddenTags > 0 {
		return fmt.Sprintf("%s + %d more...", strings.Join(tags, ","), hiddenTags)
	}
	return strings.Join(tags, ",")
}

func printImageStreamList(streams *imageapi.ImageStreamList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, stream := range streams.Items {
		if err := printImageStream(&stream, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printProject(project *projectapi.Project, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, project.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s", name, project.Annotations[annotations.OpenShiftDisplayName], project.Status.Phase)
	if err := appendItemLabels(project.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return err
}

// SortableProjects is a list of projects that can be sorted
type SortableProjects []projectapi.Project

func (list SortableProjects) Len() int {
	return len(list)
}

func (list SortableProjects) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list SortableProjects) Less(i, j int) bool {
	return list[i].ObjectMeta.Name < list[j].ObjectMeta.Name
}

func printProjectList(projects *projectapi.ProjectList, w io.Writer, opts kprinters.PrintOptions) error {
	sort.Sort(SortableProjects(projects.Items))
	for _, project := range projects.Items {
		if err := printProject(&project, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printRoute(route *routeapi.Route, w io.Writer, opts kprinters.PrintOptions) error {
	tlsTerm := ""
	insecurePolicy := ""
	if route.Spec.TLS != nil {
		tlsTerm = string(route.Spec.TLS.Termination)
		insecurePolicy = string(route.Spec.TLS.InsecureEdgeTerminationPolicy)
	}

	name := formatResourceName(opts.Kind, route.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", route.Namespace); err != nil {
			return err
		}
	}
	var (
		matchedHost bool
		reason      string
		host        = route.Spec.Host

		admitted, errors = 0, 0
	)
	for _, ingress := range route.Status.Ingress {
		switch status, condition := ingressConditionStatus(&ingress, routeapi.RouteAdmitted); status {
		case kapi.ConditionTrue:
			admitted++
			if !matchedHost {
				matchedHost = ingress.Host == route.Spec.Host
				host = ingress.Host
			}
		case kapi.ConditionFalse:
			reason = condition.Reason
			errors++
		}
	}
	switch {
	case route.Status.Ingress == nil:
		// this is the legacy case, we should continue to show the host when talking to servers
		// that have not set status ingress, since we can't distinguish this condition from there
		// being no routers.
	case admitted == 0 && errors > 0:
		host = reason
	case errors > 0:
		host = fmt.Sprintf("%s ... %d rejected", host, errors)
	case admitted == 0:
		host = "Pending"
	case admitted > 1:
		host = fmt.Sprintf("%s ... %d more", host, admitted-1)
	}
	var policy string
	switch {
	case len(tlsTerm) != 0 && len(insecurePolicy) != 0:
		policy = fmt.Sprintf("%s/%s", tlsTerm, insecurePolicy)
	case len(tlsTerm) != 0:
		policy = tlsTerm
	case len(insecurePolicy) != 0:
		policy = fmt.Sprintf("default/%s", insecurePolicy)
	default:
		policy = ""
	}

	backends := append([]routeapi.RouteTargetReference{route.Spec.To}, route.Spec.AlternateBackends...)
	totalWeight := int32(0)
	for _, backend := range backends {
		if backend.Weight != nil {
			totalWeight += *backend.Weight
		}
	}
	var backendInfo []string
	for _, backend := range backends {
		switch {
		case backend.Weight == nil, len(backends) == 1 && totalWeight != 0:
			backendInfo = append(backendInfo, backend.Name)
		case totalWeight == 0:
			backendInfo = append(backendInfo, fmt.Sprintf("%s(0%%)", backend.Name))
		default:
			backendInfo = append(backendInfo, fmt.Sprintf("%s(%d%%)", backend.Name, *backend.Weight*100/totalWeight))
		}
	}

	var port string
	if route.Spec.Port != nil {
		port = route.Spec.Port.TargetPort.String()
	} else {
		port = "<all>"
	}

	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s", name, host, route.Spec.Path, strings.Join(backendInfo, ","), port, policy, route.Spec.WildcardPolicy); err != nil {
		return err
	}

	err := appendItemLabels(route.Labels, w, opts.ColumnLabels, opts.ShowLabels)

	return err
}

func ingressConditionStatus(ingress *routeapi.RouteIngress, t routeapi.RouteIngressConditionType) (kapi.ConditionStatus, routeapi.RouteIngressCondition) {
	for _, condition := range ingress.Conditions {
		if t != condition.Type {
			continue
		}
		return condition.Status, condition
	}
	return kapi.ConditionUnknown, routeapi.RouteIngressCondition{}
}

func printRouteList(routeList *routeapi.RouteList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, route := range routeList.Items {
		if err := printRoute(&route, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printDeploymentConfig(dc *appsapi.DeploymentConfig, w io.Writer, opts kprinters.PrintOptions) error {
	var desired string
	if dc.Spec.Test {
		desired = fmt.Sprintf("%d (during test)", dc.Spec.Replicas)
	} else {
		desired = fmt.Sprintf("%d", dc.Spec.Replicas)
	}

	containers := sets.NewString()
	if dc.Spec.Template != nil {
		for _, c := range dc.Spec.Template.Spec.Containers {
			containers.Insert(c.Name)
		}
	}
	//names := containers.List()
	referencedContainers := sets.NewString()

	triggers := sets.String{}
	for _, trigger := range dc.Spec.Triggers {
		switch t := trigger.Type; t {
		case appsapi.DeploymentTriggerOnConfigChange:
			triggers.Insert("config")
		case appsapi.DeploymentTriggerOnImageChange:
			if p := trigger.ImageChangeParams; p != nil && p.Automatic {
				var prefix string
				if len(containers) != 1 && !containers.HasAll(p.ContainerNames...) {
					sort.Sort(sort.StringSlice(p.ContainerNames))
					prefix = strings.Join(p.ContainerNames, ",") + ":"
				}
				referencedContainers.Insert(p.ContainerNames...)
				switch p.From.Kind {
				case "ImageStreamTag":
					triggers.Insert(fmt.Sprintf("image(%s%s)", prefix, p.From.Name))
				default:
					triggers.Insert(fmt.Sprintf("%s(%s%s)", p.From.Kind, prefix, p.From.Name))
				}
			}
		default:
			triggers.Insert(string(t))
		}
	}

	name := formatResourceName(opts.Kind, dc.Name, opts.WithKind)
	trigger := strings.Join(triggers.List(), ",")

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", dc.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s", name, dc.Status.LatestVersion, desired, dc.Status.UpdatedReplicas, trigger); err != nil {
		return err
	}
	err := appendItemLabels(dc.Labels, w, opts.ColumnLabels, opts.ShowLabels)
	return err
}

func printDeploymentConfigList(list *appsapi.DeploymentConfigList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, dc := range list.Items {
		if err := printDeploymentConfig(&dc, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printClusterRole(role *authorizationapi.ClusterRole, w io.Writer, opts kprinters.PrintOptions) error {
	return printRole(authorizationhelpers.ToRole(role), w, opts)
}

func printClusterRoleList(list *authorizationapi.ClusterRoleList, w io.Writer, opts kprinters.PrintOptions) error {
	return printRoleList(authorizationhelpers.ToRoleList(list), w, opts)
}

func printClusterRoleBinding(roleBinding *authorizationapi.ClusterRoleBinding, w io.Writer, opts kprinters.PrintOptions) error {
	return printRoleBinding(authorizationhelpers.ToRoleBinding(roleBinding), w, opts)
}

func printClusterRoleBindingList(list *authorizationapi.ClusterRoleBindingList, w io.Writer, opts kprinters.PrintOptions) error {
	return printRoleBindingList(authorizationhelpers.ToRoleBindingList(list), w, opts)
}

func printIsPersonalSubjectAccessReview(a *authorizationapi.IsPersonalSubjectAccessReview, w io.Writer, opts kprinters.PrintOptions) error {
	_, err := fmt.Fprintf(w, "IsPersonalSubjectAccessReview\n")
	return err
}

func printRole(role *authorizationapi.Role, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, role.Name, opts.WithKind)
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", role.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if err := appendItemLabels(role.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printRoleList(list *authorizationapi.RoleList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, role := range list.Items {
		if err := printRole(&role, w, opts); err != nil {
			return err
		}
	}

	return nil
}

func truncatedList(list []string, maxLength int) string {
	if len(list) > maxLength {
		return fmt.Sprintf("%s (%d more)", strings.Join(list[0:maxLength], ", "), len(list)-maxLength)
	}
	return strings.Join(list, ", ")
}

func printRoleBinding(roleBinding *authorizationapi.RoleBinding, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, roleBinding.Name, opts.WithKind)
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", roleBinding.Namespace); err != nil {
			return err
		}
	}
	users, groups, sas, others := authorizationhelpers.SubjectsStrings(roleBinding.Namespace, roleBinding.Subjects)

	if _, err := fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%v\t%v", name,
		roleBinding.RoleRef.Namespace+"/"+roleBinding.RoleRef.Name, truncatedList(users, 5),
		truncatedList(groups, 5), strings.Join(sas, ", "), strings.Join(others, ", ")); err != nil {
		return err
	}
	if err := appendItemLabels(roleBinding.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printRoleBindingList(list *authorizationapi.RoleBindingList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, roleBinding := range list.Items {
		if err := printRoleBinding(&roleBinding, w, opts); err != nil {
			return err
		}
	}

	return nil
}

func printOAuthClient(client *oauthapi.OAuthClient, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, client.Name, opts.WithKind)
	challenge := "FALSE"
	if client.RespondWithChallenges {
		challenge = "TRUE"
	}

	var maxAge string
	switch {
	case client.AccessTokenMaxAgeSeconds == nil:
		maxAge = "default"
	case *client.AccessTokenMaxAgeSeconds == 0:
		maxAge = "unexpiring"
	default:
		duration := time.Duration(*client.AccessTokenMaxAgeSeconds) * time.Second
		maxAge = duration.String()
	}

	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v", name, client.Secret, challenge, maxAge, strings.Join(client.RedirectURIs, ",")); err != nil {
		return err
	}
	if err := appendItemLabels(client.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printOAuthClientList(list *oauthapi.OAuthClientList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthClient(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printOAuthClientAuthorization(auth *oauthapi.OAuthClientAuthorization, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, auth.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", name, auth.UserName, auth.ClientName, strings.Join(auth.Scopes, ","))
	return err
}

func printOAuthClientAuthorizationList(list *oauthapi.OAuthClientAuthorizationList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthClientAuthorization(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printOAuthAccessToken(token *oauthapi.OAuthAccessToken, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, token.Name, opts.WithKind)
	created := token.CreationTimestamp
	expires := "never"
	if token.ExpiresIn > 0 {
		expires = created.Add(time.Duration(token.ExpiresIn) * time.Second).String()
	}
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, token.UserName, token.ClientName, created, expires, token.RedirectURI, strings.Join(token.Scopes, ","))
	return err
}

func printOAuthAccessTokenList(list *oauthapi.OAuthAccessTokenList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthAccessToken(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printOAuthAuthorizeToken(token *oauthapi.OAuthAuthorizeToken, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, token.Name, opts.WithKind)
	created := token.CreationTimestamp
	expires := created.Add(time.Duration(token.ExpiresIn) * time.Second)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, token.UserName, token.ClientName, created, expires, token.RedirectURI, strings.Join(token.Scopes, ","))
	return err
}

func printOAuthAuthorizeTokenList(list *oauthapi.OAuthAuthorizeTokenList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthAuthorizeToken(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printUser(user *userapi.User, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, user.Name, opts.WithKind)
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s", name, user.UID, user.FullName, strings.Join(user.Identities, ", ")); err != nil {
		return err
	}
	if err := appendItemLabels(user.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printUserList(list *userapi.UserList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printUser(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printIdentity(identity *userapi.Identity, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, identity.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, identity.ProviderName, identity.ProviderUserName, identity.User.Name, identity.User.UID)
	return err
}

func printIdentityList(list *userapi.IdentityList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printIdentity(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printUserIdentityMapping(mapping *userapi.UserIdentityMapping, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, mapping.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, mapping.Identity.Name, mapping.User.Name, mapping.User.UID)
	return err
}

func printGroup(group *userapi.Group, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, group.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\n", name, strings.Join(group.Users, ", "))
	return err
}

func printGroupList(list *userapi.GroupList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printGroup(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printHostSubnet(h *networkapi.HostSubnet, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, h.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t[%s]\t[%s]\n", name, h.Host, h.HostIP, h.Subnet, strings.Join(h.EgressCIDRs, ", "), strings.Join(h.EgressIPs, ", "))
	return err
}

func printHostSubnetList(list *networkapi.HostSubnetList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printHostSubnet(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printNetNamespace(n *networkapi.NetNamespace, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, n.NetName, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%d\t[%s]\n", name, n.NetID, strings.Join(n.EgressIPs, ", "))
	return err
}

func printNetNamespaceList(list *networkapi.NetNamespaceList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printNetNamespace(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printClusterNetwork(n *networkapi.ClusterNetwork, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, n.Name, opts.WithKind)
	const numOfNetworksShown = 3
	var networksList []string
	var networks string
	for _, cidr := range n.ClusterNetworks {
		networksList = append(networksList, fmt.Sprintf("%s:%d", cidr.CIDR, cidr.HostSubnetLength))
	}

	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if len(networksList) > numOfNetworksShown {
		networks = fmt.Sprintf("%s + %d more...",
			strings.Join(networksList[:numOfNetworksShown], ", "),
			len(networksList)-numOfNetworksShown)
	} else {
		networks = strings.Join(networksList, ", ")
	}
	_, err := fmt.Fprintf(w, "\t%s\t%s\t%s\n", networks, n.ServiceNetwork, n.PluginName)
	return err
}

func printClusterNetworkList(list *networkapi.ClusterNetworkList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printClusterNetwork(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printEgressNetworkPolicy(n *networkapi.EgressNetworkPolicy, w io.Writer, opts kprinters.PrintOptions) error {
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", n.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\n", n.Name); err != nil {
		return err
	}
	return nil
}

func printEgressNetworkPolicyList(list *networkapi.EgressNetworkPolicyList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printEgressNetworkPolicy(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func appendItemLabels(itemLabels map[string]string, w io.Writer, columnLabels []string, showLabels bool) error {
	if _, err := fmt.Fprint(w, kprinters.AppendLabels(itemLabels, columnLabels)); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, kprinters.AppendAllLabels(showLabels, itemLabels)); err != nil {
		return err
	}
	return nil
}

func printClusterResourceQuota(resourceQuota *quotaapi.ClusterResourceQuota, w io.Writer, options kprinters.PrintOptions) error {
	name := formatResourceName(options.Kind, resourceQuota.Name, options.WithKind)

	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t%s", metav1.FormatLabelSelector(resourceQuota.Spec.Selector.LabelSelector)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t%s", resourceQuota.Spec.Selector.AnnotationSelector); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, kprinters.AppendLabels(resourceQuota.Labels, options.ColumnLabels)); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, kprinters.AppendAllLabels(options.ShowLabels, resourceQuota.Labels))
	return err
}

func printClusterResourceQuotaList(list *quotaapi.ClusterResourceQuotaList, w io.Writer, options kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printClusterResourceQuota(&list.Items[i], w, options); err != nil {
			return err
		}
	}
	return nil
}

func printAppliedClusterResourceQuota(resourceQuota *quotaapi.AppliedClusterResourceQuota, w io.Writer, options kprinters.PrintOptions) error {
	return printClusterResourceQuota(quotahelpers.ConvertAppliedClusterResourceQuotaToClusterResourceQuota(resourceQuota), w, options)
}

func printAppliedClusterResourceQuotaList(list *quotaapi.AppliedClusterResourceQuotaList, w io.Writer, options kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printClusterResourceQuota(quotahelpers.ConvertAppliedClusterResourceQuotaToClusterResourceQuota(&list.Items[i]), w, options); err != nil {
			return err
		}
	}
	return nil
}

func printRoleBindingRestriction(rbr *authorizationapi.RoleBindingRestriction, w io.Writer, options kprinters.PrintOptions) error {
	name := formatResourceName(options.Kind, rbr.Name, options.WithKind)
	subjectType := roleBindingRestrictionType(rbr)
	subjectList := []string{}
	const numOfSubjectsShown = 3
	switch {
	case rbr.Spec.UserRestriction != nil:
		for _, user := range rbr.Spec.UserRestriction.Users {
			subjectList = append(subjectList, user)
		}
		for _, group := range rbr.Spec.UserRestriction.Groups {
			subjectList = append(subjectList, fmt.Sprintf("group(%s)", group))
		}
		for _, selector := range rbr.Spec.UserRestriction.Selectors {
			subjectList = append(subjectList,
				metav1.FormatLabelSelector(&selector))
		}
	case rbr.Spec.GroupRestriction != nil:
		for _, group := range rbr.Spec.GroupRestriction.Groups {
			subjectList = append(subjectList, group)
		}
		for _, selector := range rbr.Spec.GroupRestriction.Selectors {
			subjectList = append(subjectList,
				metav1.FormatLabelSelector(&selector))
		}
	case rbr.Spec.ServiceAccountRestriction != nil:
		for _, sa := range rbr.Spec.ServiceAccountRestriction.ServiceAccounts {
			subjectList = append(subjectList, fmt.Sprintf("%s/%s",
				sa.Namespace, sa.Name))
		}
		for _, ns := range rbr.Spec.ServiceAccountRestriction.Namespaces {
			subjectList = append(subjectList, fmt.Sprintf("%s/*", ns))
		}
	}

	if options.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", rbr.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t%s", subjectType); err != nil {
		return err
	}
	subjects := "<none>"
	if len(subjectList) > numOfSubjectsShown {
		subjects = fmt.Sprintf("%s + %d more...",
			strings.Join(subjectList[:numOfSubjectsShown], ", "),
			len(subjectList)-numOfSubjectsShown)
	} else if len(subjectList) > 0 {
		subjects = strings.Join(subjectList, ", ")
	}
	_, err := fmt.Fprintf(w, "\t%s\n", subjects)
	return err
}

func printRoleBindingRestrictionList(list *authorizationapi.RoleBindingRestrictionList, w io.Writer, options kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printRoleBindingRestriction(&list.Items[i], w, options); err != nil {
			return err
		}
	}
	return nil
}

func printTemplateInstance(templateInstance *templateapi.TemplateInstance, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, templateInstance.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", templateInstance.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s", name, templateInstance.Spec.Template.Name); err != nil {
		return err
	}
	if err := appendItemLabels(templateInstance.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printTemplateInstanceList(list *templateapi.TemplateInstanceList, w io.Writer, opts kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printTemplateInstance(&list.Items[i], w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printBrokerTemplateInstance(brokerTemplateInstance *templateapi.BrokerTemplateInstance, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, brokerTemplateInstance.Name, opts.WithKind)

	if _, err := fmt.Fprintf(w, "%s\t%s/%s", name, brokerTemplateInstance.Spec.TemplateInstance.Namespace, brokerTemplateInstance.Spec.TemplateInstance.Name); err != nil {
		return err
	}
	if err := appendItemLabels(brokerTemplateInstance.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printBrokerTemplateInstanceList(list *templateapi.BrokerTemplateInstanceList, w io.Writer, opts kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printBrokerTemplateInstance(&list.Items[i], w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printSecurityContextConstraints(item *securityapi.SecurityContextConstraints, w io.Writer, options kprinters.PrintOptions) error {
	priority := "<none>"
	if item.Priority != nil {
		priority = fmt.Sprintf("%d", *item.Priority)
	}

	_, err := fmt.Fprintf(w, "%s\t%t\t%v\t%s\t%s\t%s\t%s\t%s\t%t\t%v\n", item.Name, item.AllowPrivilegedContainer,
		item.AllowedCapabilities, item.SELinuxContext.Type,
		item.RunAsUser.Type, item.FSGroup.Type, item.SupplementalGroups.Type, priority, item.ReadOnlyRootFilesystem, item.Volumes)
	return err
}

func printSecurityContextConstraintsList(list *securityapi.SecurityContextConstraintsList, w io.Writer, options kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printSecurityContextConstraints(&item, w, options); err != nil {
			return err
		}
	}

	return nil
}

func printRangeAllocation(item *securityapi.RangeAllocation, w io.Writer, options kprinters.PrintOptions) error {
	_, err := fmt.Fprintf(w, "%s\t%s\t0x%x\n", item.Name, item.Range, item.Data)
	return err
}

func printRangeAllocationList(list *securityapi.RangeAllocationList, w io.Writer, options kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printRangeAllocation(&item, w, options); err != nil {
			return err
		}
	}

	return nil
}
