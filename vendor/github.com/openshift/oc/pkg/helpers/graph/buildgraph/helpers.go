package buildgraph

import (
	"sort"

	"github.com/gonum/graph"

	buildv1 "github.com/openshift/api/build/v1"
	buildgraph "github.com/openshift/oc/pkg/helpers/graph/buildgraph/nodes"
	osgraph "github.com/openshift/oc/pkg/helpers/graph/genericgraph"
)

// RelevantBuilds returns the lastSuccessful build, lastUnsuccessful build, and a list of active builds
func RelevantBuilds(g osgraph.Graph, bcNode *buildgraph.BuildConfigNode) (*buildgraph.BuildNode, *buildgraph.BuildNode, []*buildgraph.BuildNode) {
	var (
		lastSuccessfulBuild   *buildgraph.BuildNode
		lastUnsuccessfulBuild *buildgraph.BuildNode
	)
	activeBuilds := []*buildgraph.BuildNode{}
	allBuilds := []*buildgraph.BuildNode{}
	uncastBuilds := g.SuccessorNodesByEdgeKind(bcNode, BuildEdgeKind)

	for i := range uncastBuilds {
		buildNode := uncastBuilds[i].(*buildgraph.BuildNode)
		if belongsToBuildConfig(bcNode.BuildConfig, buildNode.Build) {
			allBuilds = append(allBuilds, buildNode)
		}
	}

	if len(allBuilds) == 0 {
		return nil, nil, []*buildgraph.BuildNode{}
	}

	sort.Sort(RecentBuildReferences(allBuilds))

	for i := range allBuilds {
		switch allBuilds[i].Build.Status.Phase {
		case buildv1.BuildPhaseComplete:
			if lastSuccessfulBuild == nil {
				lastSuccessfulBuild = allBuilds[i]
			}
		case buildv1.BuildPhaseFailed, buildv1.BuildPhaseCancelled, buildv1.BuildPhaseError:
			if lastUnsuccessfulBuild == nil {
				lastUnsuccessfulBuild = allBuilds[i]
			}
		default:
			activeBuilds = append(activeBuilds, allBuilds[i])
		}
	}

	return lastSuccessfulBuild, lastUnsuccessfulBuild, activeBuilds
}

func belongsToBuildConfig(config *buildv1.BuildConfig, b *buildv1.Build) bool {
	if b.Labels == nil {
		return false
	}
	if b.Annotations != nil && b.Annotations[buildv1.BuildConfigAnnotation] == config.Name {
		return true
	}
	if b.Labels[buildv1.BuildConfigLabel] == config.Name {
		return true
	}
	if b.Labels[buildv1.BuildConfigLabelDeprecated] == config.Name {
		return true
	}
	return false
}

type RecentBuildReferences []*buildgraph.BuildNode

func (m RecentBuildReferences) Len() int      { return len(m) }
func (m RecentBuildReferences) Swap(i, j int) { m[i], m[j] = m[j], m[i] }
func (m RecentBuildReferences) Less(i, j int) bool {
	return m[i].Build.CreationTimestamp.After(m[j].Build.CreationTimestamp.Time)
}

func defaultNamespace(value, defaultValue string) string {
	if len(value) == 0 {
		return defaultValue
	}
	return value
}

// BuildConfigsForTag returns the buildConfig that points to the provided imageStreamTag.
func BuildConfigsForTag(g osgraph.Graph, istag graph.Node) []*buildgraph.BuildConfigNode {
	bcs := []*buildgraph.BuildConfigNode{}
	for _, bcNode := range g.PredecessorNodesByEdgeKind(istag, BuildOutputEdgeKind) {
		bcs = append(bcs, bcNode.(*buildgraph.BuildConfigNode))
	}
	return bcs
}

// GetLatestBuild returns the latest build for the provided buildConfig.
func GetLatestBuild(g osgraph.Graph, bc graph.Node) *buildgraph.BuildNode {
	builds := g.SuccessorNodesByEdgeKind(bc, BuildEdgeKind)
	if len(builds) == 0 {
		return nil
	}
	latestBuild := builds[0].(*buildgraph.BuildNode)

	for _, buildNode := range builds[1:] {
		if build, ok := buildNode.(*buildgraph.BuildNode); ok {
			if latestBuild.Build.CreationTimestamp.Before(&build.Build.CreationTimestamp) {
				latestBuild = build
			}
		}
	}

	return latestBuild
}
