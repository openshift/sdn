package signature

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/containers/image/docker"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	imagev1 "github.com/openshift/api/image/v1"
	"github.com/openshift/library-go/pkg/image/imageutil"
)

type containerImageSignatureDownloader struct {
	ctx     context.Context
	timeout time.Duration
}

func NewContainerImageSignatureDownloader(ctx context.Context, timeout time.Duration) SignatureDownloader {
	return &containerImageSignatureDownloader{
		ctx:     ctx,
		timeout: timeout,
	}
}

type GetSignaturesError struct {
	error
}

func (s *containerImageSignatureDownloader) DownloadImageSignatures(image *imagev1.Image) ([]imagev1.ImageSignature, error) {
	reference, err := docker.ParseReference("//" + image.DockerImageReference)
	if err != nil {
		return nil, err
	}
	source, err := reference.NewImageSource(nil, nil)
	if err != nil {
		// In case we fail to talk to registry to get the image metadata (private
		// registry, internal registry, etc...), do not fail with error to avoid
		// spamming logs.
		klog.V(4).Infof("Failed to get %q: %v", image.DockerImageReference, err)
		return []imagev1.ImageSignature{}, nil
	}
	defer source.Close()

	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()

	signatures, err := source.GetSignatures(ctx)
	if err != nil {
		klog.V(4).Infof("Failed to get signatures for %v due to: %v", source.Reference(), err)
		return []imagev1.ImageSignature{}, GetSignaturesError{err}
	}

	ret := []imagev1.ImageSignature{}
	for _, blob := range signatures {
		sig := imagev1.ImageSignature{Type: imagev1.ImageSignatureTypeAtomicImageV1}
		// This will use the name of the image (sha256:xxxx) and the SHA256 of the
		// signature itself as the signature name has to be unique for each
		// signature.
		sig.Name = imageutil.JoinImageStreamImage(image.Name, fmt.Sprintf("%x", sha256.Sum256(blob)))
		sig.Content = blob
		sig.CreationTimestamp = metav1.Now()
		ret = append(ret, sig)
	}
	return ret, nil
}
