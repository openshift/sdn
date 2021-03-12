module github.com/openshift/sdn

go 1.13

require (
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.6.0
	github.com/coreos/go-iptables v0.0.0-00010101000000-000000000000 // indirect
	github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/fsnotify/fsnotify v1.4.7
	github.com/gorilla/mux v1.7.4-0.20190830121156-884b5ffcbd3a
	github.com/miekg/dns v1.1.4
	github.com/openshift/api v0.0.0-20200424083944-0422dc17083e
	github.com/openshift/build-machinery-go v0.0.0-20200424080330-082bf86082cc
	github.com/openshift/client-go v0.0.0-20200422192633-6f6c07fc2a70
	github.com/openshift/library-go v0.0.0-20200424095618-2aeb4725dadf
	github.com/prometheus/client_golang v1.1.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.1.0
	k8s.io/api v0.18.2
	k8s.io/apimachinery v0.18.2
	k8s.io/apiserver v0.18.2
	k8s.io/client-go v0.18.2
	k8s.io/component-base v0.18.2
	k8s.io/cri-api v0.0.0
	k8s.io/klog v1.0.0
	k8s.io/kubectl v0.0.0
	k8s.io/kubernetes v1.18.2
	k8s.io/utils v0.0.0-20200324210504-a9aa75ae1b89 // same as sdn-4.5-kubernetes-1.18.2
)

replace (
	github.com/certifi/gocertifi => github.com/certifi/gocertifi v0.0.0-20180905225744-ee1a9a0726d2
	github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0-rc1
	github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.0
	github.com/coreos/go-iptables => github.com/coreos/go-iptables v0.2.0
	github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/fsnotify/fsnotify => github.com/fsnotify/fsnotify v1.4.7
	github.com/golang/glog => github.com/openshift/golang-glog v0.0.0-20190322123450-3c92600d7533
	github.com/gorilla/mux => github.com/gorilla/mux v1.7.4-0.20190830121156-884b5ffcbd3a
	github.com/grpc-ecosystem/go-grpc-prometheus => github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/golang-lru => github.com/hashicorp/golang-lru v0.5.1
	github.com/imdario/mergo => github.com/imdario/mergo v0.3.5
	github.com/inconshreveable/mousetrap => github.com/inconshreveable/mousetrap v1.0.0
	github.com/json-iterator/go => github.com/json-iterator/go v1.1.7
	github.com/konsorten/go-windows-terminal-sequences => github.com/konsorten/go-windows-terminal-sequences v1.0.1
	github.com/lithammer/dedent => github.com/lithammer/dedent v1.1.1-0.20190124093549-bacd562a6875
	github.com/mailru/easyjson => github.com/mailru/easyjson v0.0.0-20190614124828-94de47d64c63
	github.com/matttproud/golang_protobuf_extensions => github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/miekg/dns => github.com/miekg/dns v1.0.8
	github.com/mitchellh/go-wordwrap => github.com/mitchellh/go-wordwrap v1.0.0
	github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v1.0.1
	github.com/munnerz/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc8.0.20190926150303-84373aaa560b
	github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.0.2-0.20190911013453-52e2591aa9f7
	github.com/peterbourgon/diskv => github.com/peterbourgon/diskv v2.0.1+incompatible
	github.com/pkg/errors => github.com/pkg/errors v0.8.0
	github.com/pkg/profile => github.com/pkg/profile v1.3.0
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model => github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910
	github.com/prometheus/common => github.com/prometheus/common v0.0.0-20181126121408-4724e9255275
	github.com/prometheus/procfs => github.com/prometheus/procfs v0.0.0-20181204211112-1dc9a6cbc91a
	github.com/spf13/cobra => github.com/spf13/cobra v0.0.4
	github.com/spf13/pflag => github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink => ./patch/github.com/vishvananda/netlink
	github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20170219233438-54f0e4339ce7
	k8s.io/api => github.com/openshift/kubernetes/staging/src/k8s.io/api v0.0.0-20200506150957-662762e23e80
	k8s.io/apiextensions-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20200506150957-662762e23e80
	k8s.io/apimachinery => github.com/openshift/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20200506150957-662762e23e80
	k8s.io/apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20200506150957-662762e23e80
	k8s.io/cli-runtime => github.com/openshift/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20200506150957-662762e23e80
	k8s.io/client-go => github.com/openshift/kubernetes/staging/src/k8s.io/client-go v0.0.0-20200506150957-662762e23e80
	k8s.io/cloud-provider => github.com/openshift/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20200506150957-662762e23e80
	k8s.io/cluster-bootstrap => github.com/openshift/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20200506150957-662762e23e80
	k8s.io/code-generator => github.com/openshift/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20200506150957-662762e23e80
	k8s.io/component-base => github.com/openshift/kubernetes/staging/src/k8s.io/component-base v0.0.0-20200506150957-662762e23e80
	k8s.io/cri-api => github.com/openshift/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20200506150957-662762e23e80
	k8s.io/csi-translation-lib => github.com/openshift/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20200506150957-662762e23e80
	k8s.io/kube-aggregator => github.com/openshift/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20200506150957-662762e23e80
	k8s.io/kube-controller-manager => github.com/openshift/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20200506150957-662762e23e80
	k8s.io/kube-proxy => github.com/openshift/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20200506150957-662762e23e80
	k8s.io/kube-scheduler => github.com/openshift/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20200506150957-662762e23e80
	k8s.io/kubectl => github.com/openshift/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20200506150957-662762e23e80
	k8s.io/kubelet => github.com/openshift/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20200506150957-662762e23e80
	k8s.io/kubernetes => github.com/openshift/kubernetes v1.19.0-alpha.0.0.20210304151414-a18cff1620e7
	k8s.io/legacy-cloud-providers => github.com/openshift/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20200506150957-662762e23e80
	k8s.io/metrics => github.com/openshift/kubernetes/staging/src/k8s.io/metrics v0.0.0-20200506150957-662762e23e80
	k8s.io/sample-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20200506150957-662762e23e80
	k8s.io/sample-cli-plugin => github.com/openshift/kubernetes/staging/src/k8s.io/sample-cli-plugin v0.0.0-20200506150957-662762e23e80
	k8s.io/sample-controller => github.com/openshift/kubernetes/staging/src/k8s.io/sample-controller v0.0.0-20200506150957-662762e23e80
	k8s.io/utils => k8s.io/utils v0.0.0-20200324210504-a9aa75ae1b89 // same as sdn-4.4-kubernetes-1.18.2
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)
