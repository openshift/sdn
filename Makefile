all: build
.PHONY: all

GO_BUILD_PACKAGES = \
    ./cmd/... \
    ./vendor/github.com/containernetworking/plugins/plugins/ipam/host-local \
    ./vendor/k8s.io/kubernetes/cmd/kube-proxy

# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/library-go/alpha-build-machinery/make/, \
	golang.mk \
	targets/openshift/deps.mk \
	targets/openshift/images.mk \
)

# This will call a macro called "build-image" which will generate image specific targets based on the parameters:
# $0 - macro name
# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context directory for image build
# It will generate target "image-$(1)" for builing the image and binding it as a prerequisite to target "images".
$(call build-image,sdn,origin-sdn,./images/sdn/Dockerfile,.)
$(call build-image,node,origin-node,./images/node/Dockerfile,.)
$(call build-image,sdn-controller,origin-sdn-controller,./images/sdn-controller/Dockerfile,.)
$(call build-image,kube-proxy,origin-kube-proxy,./images/kube-proxy/Dockerfile,.)

# The "real" Dockerfiles depend on OVS from the Fast Datapath channel, which requires
# fiddling with RHEL subscriptions. For testing purposes it's easier to just build a
# Fedora-based image
build-image-sdn-test:
	podman build --no-cache -f images/sdn/Dockerfile.fedora -t sdn-test .

.PHONY: build-image-sdn-test
