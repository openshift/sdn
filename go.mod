module github.com/openshift/sdn

go 1.22.0

require (
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.6.0
	github.com/fsnotify/fsnotify v1.7.0
	github.com/gorilla/mux v1.8.0
	github.com/miekg/dns v1.1.35
	github.com/opencontainers/runc v1.1.12
	github.com/openshift/api v0.0.0-20231010075512-1ccc6058c62d
	github.com/openshift/build-machinery-go v0.0.0-20220913142420-e25cf57ea46d
	github.com/openshift/client-go v0.0.0-20230926161409-848405da69e1
	github.com/openshift/library-go v0.0.0-20231101160200-9e6e65ed2a52
	github.com/prometheus/client_golang v1.16.0
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.1.0
	go.opentelemetry.io/otel/trace v1.19.0
	golang.org/x/sys v0.18.0
	k8s.io/api v1.30.5
	k8s.io/apimachinery v1.30.5
	k8s.io/apiserver v1.30.5
	k8s.io/client-go v1.30.5
	k8s.io/cloud-provider v1.30.5
	k8s.io/component-base v1.30.5
	k8s.io/component-helpers v1.30.5
	k8s.io/cri-api v1.30.5
	k8s.io/klog/v2 v2.130.1
	k8s.io/kubernetes v1.30.5
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8
	sigs.k8s.io/knftables v0.0.16
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Microsoft/hcsshim v0.8.25 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/coreos/go-iptables v0.0.0-00010101000000-000000000000 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-logr/zapr v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/cadvisor v0.49.0 // indirect
	github.com/google/cel-go v0.17.8 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/lithammer/dedent v1.1.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible // indirect
	github.com/moby/ipvs v1.1.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.6.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20220909204839-494a5a6aca78 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.3.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.etcd.io/etcd/api/v3 v3.5.10 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.10 // indirect
	go.etcd.io/etcd/client/v3 v3.5.10 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.42.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.44.0 // indirect
	go.opentelemetry.io/otel v1.19.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.19.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.19.0 // indirect
	go.opentelemetry.io/otel/metric v1.19.0 // indirect
	go.opentelemetry.io/otel/sdk v1.19.0 // indirect
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e // indirect
	golang.org/x/mod v0.15.0 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/oauth2 v0.10.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/term v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.18.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230803162519-f966b187b2e5 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230726155614-23370e0ffb3e // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/grpc v1.58.3 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v1.30.5 // indirect
	k8s.io/controller-manager v1.30.5 // indirect
	k8s.io/csi-translation-lib v1.30.5 // indirect
	k8s.io/kms v1.30.5 // indirect
	k8s.io/kube-openapi v0.0.0-20240228011516-70dd3763d340 // indirect
	k8s.io/kube-proxy v1.30.5 // indirect
	k8s.io/kubelet v1.30.5 // indirect
	k8s.io/mount-utils v1.30.5 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.29.0 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

replace (
	github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0-rc1
	github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.0
	github.com/coreos/go-iptables => github.com/coreos/go-iptables v0.2.0
	github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
	github.com/gorilla/mux => github.com/gorilla/mux v1.7.4-0.20190830121156-884b5ffcbd3a
	github.com/grpc-ecosystem/go-grpc-prometheus => github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/imdario/mergo => github.com/imdario/mergo v0.3.5
	github.com/inconshreveable/mousetrap => github.com/inconshreveable/mousetrap v1.0.0
	github.com/json-iterator/go => github.com/json-iterator/go v1.1.7
	github.com/lithammer/dedent => github.com/lithammer/dedent v1.1.1-0.20190124093549-bacd562a6875
	github.com/mailru/easyjson => github.com/mailru/easyjson v0.0.0-20190614124828-94de47d64c63
	github.com/matttproud/golang_protobuf_extensions => github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/miekg/dns => github.com/miekg/dns v1.1.35
	github.com/moby/ipvs => github.com/moby/ipvs v1.0.1
	github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v1.0.1
	github.com/munnerz/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc95
	github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pkg/errors => github.com/pkg/errors v0.9.1
	github.com/pkg/profile => github.com/pkg/profile v1.3.0
	github.com/prometheus/common => github.com/prometheus/common v0.10.0
	github.com/prometheus/procfs => github.com/prometheus/procfs v0.1.3
	github.com/spf13/cobra => github.com/spf13/cobra v0.0.4
	github.com/spf13/pflag => github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink => github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	k8s.io/api => github.com/openshift/kubernetes/staging/src/k8s.io/api v0.0.0-20241023210935-d7454a2f918b
	k8s.io/apiextensions-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20241023210935-d7454a2f918b
	k8s.io/apimachinery => github.com/openshift/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20241023210935-d7454a2f918b
	k8s.io/apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20241023210935-d7454a2f918b
	k8s.io/cli-runtime => github.com/openshift/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20241023210935-d7454a2f918b
	k8s.io/client-go => github.com/openshift/kubernetes/staging/src/k8s.io/client-go v0.0.0-20241023210935-d7454a2f918b
	k8s.io/cloud-provider => github.com/openshift/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20241023210935-d7454a2f918b
	k8s.io/cluster-bootstrap => github.com/openshift/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20241023210935-d7454a2f918b
	k8s.io/code-generator => github.com/openshift/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20241023210935-d7454a2f918b
	k8s.io/component-base => github.com/openshift/kubernetes/staging/src/k8s.io/component-base v0.0.0-20241023210935-d7454a2f918b
	k8s.io/component-helpers => github.com/openshift/kubernetes/staging/src/k8s.io/component-helpers v0.0.0-20241023210935-d7454a2f918b
	k8s.io/controller-manager => github.com/openshift/kubernetes/staging/src/k8s.io/controller-manager v0.0.0-20241023210935-d7454a2f918b
	k8s.io/cri-api => github.com/openshift/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20241023210935-d7454a2f918b
	k8s.io/csi-translation-lib => github.com/openshift/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kms => github.com/openshift/kubernetes/staging/src/k8s.io/kms v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kube-aggregator => github.com/openshift/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kube-controller-manager => github.com/openshift/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kube-proxy => github.com/openshift/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kube-scheduler => github.com/openshift/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kubectl => github.com/openshift/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kubelet => github.com/openshift/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20241023210935-d7454a2f918b
	k8s.io/kubernetes => github.com/openshift/kubernetes v1.30.1-0.20241023210935-d7454a2f918b
	k8s.io/legacy-cloud-providers => github.com/openshift/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20241023210935-d7454a2f918b
	k8s.io/metrics => github.com/openshift/kubernetes/staging/src/k8s.io/metrics v0.0.0-20241023210935-d7454a2f918b
	k8s.io/mount-utils => github.com/openshift/kubernetes/staging/src/k8s.io/mount-utils v0.0.0-20241023210935-d7454a2f918b
	k8s.io/pod-security-admission => github.com/openshift/kubernetes/staging/src/k8s.io/pod-security-admission v0.0.0-20241023210935-d7454a2f918b
	k8s.io/sample-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20241023210935-d7454a2f918b
	k8s.io/sample-cli-plugin => github.com/openshift/kubernetes/staging/src/k8s.io/sample-cli-plugin v0.0.0-20241023210935-d7454a2f918b
	k8s.io/sample-controller => github.com/openshift/kubernetes/staging/src/k8s.io/sample-controller v0.0.0-20241023210935-d7454a2f918b
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)
