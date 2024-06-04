module github.com/openshift/sdn

go 1.17

require (
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.6.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gorilla/mux v1.8.0
	github.com/miekg/dns v1.1.35
	github.com/opencontainers/runc v1.0.2
	github.com/openshift/api v0.0.0-20211209173311-a19f3b9052a6
	github.com/openshift/build-machinery-go v0.0.0-20210806203541-4ea9b6da3a37
	github.com/openshift/client-go v0.0.0-20211209144617-7385dd6338e3
	github.com/openshift/library-go v0.0.0-20211209153216-ed9bc958bd8a
	github.com/prometheus/client_golang v1.11.1
	github.com/spf13/cobra v1.2.1
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.13.0
	k8s.io/api v1.23.4
	k8s.io/apimachinery v1.23.4
	k8s.io/apiserver v1.23.4
	k8s.io/client-go v1.23.4
	k8s.io/cloud-provider v0.0.0
	k8s.io/component-base v1.23.4
	k8s.io/component-helpers v0.0.0
	k8s.io/cri-api v1.23.4
	k8s.io/klog/v2 v2.30.0
	k8s.io/kubernetes v1.23.4 // actually branch sdn-4.10-kubernetes-1.23.4 in openshift/kubernetes
	k8s.io/utils v0.0.0-20211116205334-6203023598ed
	sigs.k8s.io/yaml v1.2.0
)

require (
	github.com/Microsoft/go-winio v0.4.17 // indirect
	github.com/Microsoft/hcsshim v0.8.22 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/containerd/cgroups v1.0.1 // indirect
	github.com/coreos/go-iptables v0.0.0-00010101000000-000000000000 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/godbus/dbus/v5 v5.0.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/cadvisor v0.43.0 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/hpcloud/tail v1.0.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/lithammer/dedent v1.1.0 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible // indirect
	github.com/moby/ipvs v1.0.1 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.4.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417 // indirect
	github.com/opencontainers/selinux v1.8.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.3.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.28.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	go.etcd.io/etcd/api/v3 v3.5.0 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.0 // indirect
	go.etcd.io/etcd/client/v3 v3.5.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.opentelemetry.io/contrib v0.20.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.20.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0 // indirect
	go.opentelemetry.io/otel v0.20.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp v0.20.0 // indirect
	go.opentelemetry.io/otel/metric v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk/export/metric v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v0.20.0 // indirect
	go.opentelemetry.io/otel/trace v0.20.0 // indirect
	go.opentelemetry.io/proto/otlp v0.7.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.19.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210831024726-fe130286e0e2 // indirect
	google.golang.org/grpc v1.40.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/kube-proxy v0.0.0 // indirect
	k8s.io/mount-utils v0.0.0 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.0.27 // indirect
	sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
)

replace (
	github.com/certifi/gocertifi => github.com/certifi/gocertifi v0.0.0-20180905225744-ee1a9a0726d2
	github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0-rc1
	github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.0
	github.com/coreos/go-iptables => github.com/coreos/go-iptables v0.2.0
	github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/fsnotify/fsnotify => github.com/fsnotify/fsnotify v1.4.7
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
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
	github.com/miekg/dns => github.com/miekg/dns v1.1.35
	github.com/mitchellh/go-wordwrap => github.com/mitchellh/go-wordwrap v1.0.0
	github.com/moby/ipvs => github.com/moby/ipvs v1.0.1
	github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v1.0.1
	github.com/munnerz/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/onsi/ginkgo => github.com/openshift/onsi-ginkgo v4.7.0-origin.0+incompatible
	github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc95
	github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/peterbourgon/diskv => github.com/peterbourgon/diskv v2.0.1+incompatible
	github.com/pkg/errors => github.com/pkg/errors v0.9.1
	github.com/pkg/profile => github.com/pkg/profile v1.3.0
	github.com/prometheus/client_model => github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common => github.com/prometheus/common v0.10.0
	github.com/prometheus/procfs => github.com/prometheus/procfs v0.1.3
	github.com/spf13/cobra => github.com/spf13/cobra v0.0.4
	github.com/spf13/pflag => github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink => github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	k8s.io/api => github.com/openshift/kubernetes/staging/src/k8s.io/api v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/apiextensions-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/apimachinery => github.com/openshift/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/cli-runtime => github.com/openshift/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/client-go => github.com/openshift/kubernetes/staging/src/k8s.io/client-go v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/cloud-provider => github.com/openshift/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/cluster-bootstrap => github.com/openshift/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/code-generator => github.com/openshift/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/component-base => github.com/openshift/kubernetes/staging/src/k8s.io/component-base v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/component-helpers => github.com/openshift/kubernetes/staging/src/k8s.io/component-helpers v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/controller-manager => github.com/openshift/kubernetes/staging/src/k8s.io/controller-manager v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/cri-api => github.com/openshift/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/csi-translation-lib => github.com/openshift/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kube-aggregator => github.com/openshift/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kube-controller-manager => github.com/openshift/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kube-proxy => github.com/openshift/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kube-scheduler => github.com/openshift/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kubectl => github.com/openshift/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kubelet => github.com/openshift/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/kubernetes => github.com/openshift/kubernetes v1.24.0-alpha.0.0.20221205144249-c51fc87b33fe
	k8s.io/legacy-cloud-providers => github.com/openshift/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/metrics => github.com/openshift/kubernetes/staging/src/k8s.io/metrics v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/mount-utils => github.com/openshift/kubernetes/staging/src/k8s.io/mount-utils v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/pod-security-admission => github.com/openshift/kubernetes/staging/src/k8s.io/pod-security-admission v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/sample-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/sample-cli-plugin => github.com/openshift/kubernetes/staging/src/k8s.io/sample-cli-plugin v0.0.0-20221205144249-c51fc87b33fe
	k8s.io/sample-controller => github.com/openshift/kubernetes/staging/src/k8s.io/sample-controller v0.0.0-20221205144249-c51fc87b33fe
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)
