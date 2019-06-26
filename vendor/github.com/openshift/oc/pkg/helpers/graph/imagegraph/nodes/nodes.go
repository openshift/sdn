package nodes

import (
	"github.com/gonum/graph"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	imagev1 "github.com/openshift/api/image/v1"
	"github.com/openshift/library-go/pkg/image/imageutil"
	"github.com/openshift/library-go/pkg/image/reference"
	osgraph "github.com/openshift/oc/pkg/helpers/graph/genericgraph"
)

func EnsureImageNode(g osgraph.MutableUniqueGraph, img *imagev1.Image) graph.Node {
	return osgraph.EnsureUnique(g,
		ImageNodeName(img),
		func(node osgraph.Node) graph.Node {
			return &ImageNode{node, img}
		},
	)
}

// EnsureAllImageStreamTagNodes creates all the ImageStreamTagNodes that are guaranteed to be present based on the ImageStream.
// This is different than inferring the presence of an object, since the IST is an object derived from a join between the ImageStream
// and the Image it references.
func EnsureAllImageStreamTagNodes(g osgraph.MutableUniqueGraph, is *imagev1.ImageStream) []*ImageStreamTagNode {
	ret := []*ImageStreamTagNode{}

	for _, tag := range is.Status.Tags {
		ist := &imagev1.ImageStreamTag{}
		ist.Namespace = is.Namespace
		ist.Name = imageutil.JoinImageStreamTag(is.Name, tag.Tag)

		istNode := EnsureImageStreamTagNode(g, ist)
		ret = append(ret, istNode)
	}

	return ret
}

func FindImage(g osgraph.MutableUniqueGraph, imageName string) *ImageNode {
	n := g.Find(ImageNodeName(&imagev1.Image{ObjectMeta: metav1.ObjectMeta{Name: imageName}}))
	if imageNode, ok := n.(*ImageNode); ok {
		return imageNode
	}
	return nil
}

// EnsureDockerRepositoryNode adds the named Docker repository tag reference to the graph if it does
// not already exist. If the reference is invalid, the Name field of the graph will be used directly.
func EnsureDockerRepositoryNode(g osgraph.MutableUniqueGraph, name, tag string) graph.Node {
	ref, err := reference.Parse(name)
	if err == nil {
		if len(tag) != 0 {
			ref.Tag = tag
		}
		ref = ref.DockerClientDefaults()
	} else {
		ref = reference.DockerImageReference{Name: name}
	}

	return osgraph.EnsureUnique(g,
		DockerImageRepositoryNodeName(ref),
		func(node osgraph.Node) graph.Node {
			return &DockerImageRepositoryNode{node, ref}
		},
	)
}

// MakeImageStreamTagObjectMeta returns an ImageStreamTag that has enough information to join the graph, but it is not
// based on a full IST object.  This can be used to properly initialize the graph without having to retrieve all ISTs
func MakeImageStreamTagObjectMeta(namespace, name, tag string) *imagev1.ImageStreamTag {
	return &imagev1.ImageStreamTag{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      imageutil.JoinImageStreamTag(name, tag),
		},
	}
}

// MakeImageStreamTagObjectMeta2 returns an ImageStreamTag that has enough information to join the graph, but it is not
// based on a full IST object.  This can be used to properly initialize the graph without having to retrieve all ISTs
func MakeImageStreamTagObjectMeta2(namespace, name string) *imagev1.ImageStreamTag {
	return &imagev1.ImageStreamTag{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}

// EnsureImageStreamTagNode adds a graph node for the specific tag in an Image Stream if it does not already exist.
func EnsureImageStreamTagNode(g osgraph.MutableUniqueGraph, ist *imagev1.ImageStreamTag) *ImageStreamTagNode {
	return osgraph.EnsureUnique(g,
		ImageStreamTagNodeName(ist),
		func(node osgraph.Node) graph.Node {
			return &ImageStreamTagNode{node, ist, true}
		},
	).(*ImageStreamTagNode)
}

// FindOrCreateSyntheticImageStreamTagNode returns the existing ISTNode or creates a synthetic node in its place
func FindOrCreateSyntheticImageStreamTagNode(g osgraph.MutableUniqueGraph, ist *imagev1.ImageStreamTag) *ImageStreamTagNode {
	return osgraph.EnsureUnique(g,
		ImageStreamTagNodeName(ist),
		func(node osgraph.Node) graph.Node {
			return &ImageStreamTagNode{node, ist, false}
		},
	).(*ImageStreamTagNode)
}

// MakeImageStreamImageObjectMeta returns an ImageStreamImage that has enough information to join the graph, but it is not
// based on a full ISI object.  This can be used to properly initialize the graph without having to retrieve all ISIs
func MakeImageStreamImageObjectMeta(namespace, name string) *imagev1.ImageStreamImage {
	return &imagev1.ImageStreamImage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}

// EnsureImageStreamImageNode adds a graph node for the specific ImageStreamImage if it
// does not already exist.
func EnsureImageStreamImageNode(g osgraph.MutableUniqueGraph, namespace, name string) graph.Node {
	isi := &imagev1.ImageStreamImage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
	return osgraph.EnsureUnique(g,
		ImageStreamImageNodeName(isi),
		func(node osgraph.Node) graph.Node {
			return &ImageStreamImageNode{node, isi, true}
		},
	)
}

// FindOrCreateSyntheticImageStreamImageNode returns the existing ISINode or creates a synthetic node in its place
func FindOrCreateSyntheticImageStreamImageNode(g osgraph.MutableUniqueGraph, isi *imagev1.ImageStreamImage) *ImageStreamImageNode {
	return osgraph.EnsureUnique(g,
		ImageStreamImageNodeName(isi),
		func(node osgraph.Node) graph.Node {
			return &ImageStreamImageNode{node, isi, false}
		},
	).(*ImageStreamImageNode)
}

// EnsureImageStreamNode adds a graph node for the Image Stream if it does not already exist.
func EnsureImageStreamNode(g osgraph.MutableUniqueGraph, is *imagev1.ImageStream) graph.Node {
	return osgraph.EnsureUnique(g,
		ImageStreamNodeName(is),
		func(node osgraph.Node) graph.Node {
			return &ImageStreamNode{node, is, true}
		},
	)
}

// FindOrCreateSyntheticImageStreamNode returns the existing ISNode or creates a synthetic node in its place
func FindOrCreateSyntheticImageStreamNode(g osgraph.MutableUniqueGraph, is *imagev1.ImageStream) *ImageStreamNode {
	return osgraph.EnsureUnique(g,
		ImageStreamNodeName(is),
		func(node osgraph.Node) graph.Node {
			return &ImageStreamNode{node, is, false}
		},
	).(*ImageStreamNode)
}

func ensureImageComponentNode(g osgraph.MutableUniqueGraph, name string, t ImageComponentType) graph.Node {
	node := osgraph.EnsureUnique(g,
		ImageComponentNodeName(name),
		func(node osgraph.Node) graph.Node {
			return &ImageComponentNode{
				Node:      node,
				Component: name,
				Type:      t,
			}
		},
	)

	// If at least one image referers to the blob as its config, treat it as a config even if it is a layer of
	// some other image.
	if t == ImageComponentTypeConfig {
		cn := node.(*ImageComponentNode)
		if cn.Type != ImageComponentTypeConfig {
			cn.Type = ImageComponentTypeConfig
		}
	}

	return node
}

// EnsureImageComponentConfigNode adds a graph node for the image config if it does not already exist.
func EnsureImageComponentConfigNode(g osgraph.MutableUniqueGraph, name string) graph.Node {
	return ensureImageComponentNode(g, name, ImageComponentTypeConfig)
}

// EnsureImageComponentLayerNode adds a graph node for the image layer if it does not already exist.
func EnsureImageComponentLayerNode(g osgraph.MutableUniqueGraph, name string) graph.Node {
	return ensureImageComponentNode(g, name, ImageComponentTypeLayer)
}

// EnsureImageComponentLayerNode adds a graph node for the image layer if it does not already exist.
func EnsureImageComponentManifestNode(g osgraph.MutableUniqueGraph, name string) graph.Node {
	return ensureImageComponentNode(g, name, ImageComponentTypeManifest)
}
