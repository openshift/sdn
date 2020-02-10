module github.com/openshift/sdn

go 1.12

require (
	github.com/Microsoft/hcsshim v0.8.7-0.20190926181021-82c7525d98c8 // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.6.0
	github.com/coreos/go-iptables v0.2.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/docker/docker v1.4.2-0.20190327010347-be7ac8be2ae0 // indirect
	github.com/docker/libnetwork v0.8.0-dev.2.0.20190731215715-7f13a5c99f4b // indirect
	github.com/fsnotify/fsnotify v1.4.7
	github.com/getsentry/raven-go v0.2.1-0.20190513200303-c977f96e1095 // indirect
	github.com/golang/glog v0.0.0-00010101000000-000000000000 // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/gorilla/mux v1.7.4-0.20190830121156-884b5ffcbd3a
	github.com/lithammer/dedent v1.1.1-0.20190124093549-bacd562a6875 // indirect
	github.com/miekg/dns v1.1.4
	github.com/opencontainers/runc v1.0.0-rc8.0.20190926150303-84373aaa560b // indirect
	github.com/opencontainers/runtime-spec v1.0.2-0.20190911013453-52e2591aa9f7 // indirect
	github.com/openshift/api v0.0.0-20200116145750-0e2ff1e215dd
	github.com/openshift/client-go v0.0.0-20200116152001-92a2713fa240
	github.com/openshift/library-go v0.0.0-20200130090538-26ae77929944
	github.com/prometheus/client_golang v1.1.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.1.0
	k8s.io/api v0.17.1
	k8s.io/apimachinery v0.17.1
	k8s.io/client-go v0.17.1
	k8s.io/component-base v0.17.1
	k8s.io/cri-api v0.0.0
	k8s.io/klog v1.0.0
	k8s.io/kubectl v0.0.0
	k8s.io/kubernetes v1.13.0
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
)

replace (
	github.com/Azure/go-ansiterm => github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78
	github.com/MakeNowJust/heredoc => github.com/MakeNowJust/heredoc v0.0.0-20170808103936-bb23615498cd
	github.com/Microsoft/go-winio => github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5
	github.com/Microsoft/hcsshim => github.com/Microsoft/hcsshim v0.8.7-0.20190926181021-82c7525d98c8
	github.com/NYTimes/gziphandler => github.com/NYTimes/gziphandler v0.0.0-20170623195520-56545f4a5d46
	github.com/PuerkitoBio/purell => github.com/PuerkitoBio/purell v1.0.0
	github.com/PuerkitoBio/urlesc => github.com/PuerkitoBio/urlesc v0.0.0-20160726150825-5bd2802263f2
	github.com/beorn7/perks => github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973
	github.com/blang/semver => github.com/blang/semver v3.5.0+incompatible
	github.com/certifi/gocertifi => github.com/certifi/gocertifi v0.0.0-20180905225744-ee1a9a0726d2
	github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0-rc1
	github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.0
	github.com/coreos/etcd => github.com/coreos/etcd v3.3.10+incompatible
	github.com/coreos/go-iptables => github.com/coreos/go-iptables v0.2.0
	github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a
	github.com/davecgh/go-spew => github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution => github.com/docker/distribution v2.6.0-rc.1.0.20180920194744-16128bbac47f+incompatible
	github.com/docker/docker => github.com/docker/docker v1.4.2-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-units => github.com/docker/go-units v0.3.3
	github.com/docker/libnetwork => github.com/docker/libnetwork v0.8.0-dev.2.0.20190731215715-7f13a5c99f4b
	github.com/docker/spdystream => github.com/docker/spdystream v0.0.0-20160310174837-449fdfce4d96
	github.com/emicklei/go-restful => github.com/emicklei/go-restful v1.1.4-0.20170410110728-ff4f55a20633
	github.com/evanphx/json-patch => github.com/evanphx/json-patch v4.2.0+incompatible
	github.com/exponent-io/jsonpath => github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d
	github.com/fsnotify/fsnotify => github.com/fsnotify/fsnotify v1.4.7
	github.com/getsentry/raven-go => github.com/getsentry/raven-go v0.2.1-0.20190513200303-c977f96e1095
	github.com/ghodss/yaml => github.com/ghodss/yaml v0.0.0-20150909031657-73d445a93680
	github.com/go-openapi/jsonpointer => github.com/go-openapi/jsonpointer v0.0.0-20160704185906-46af16f9f7b1
	github.com/go-openapi/jsonreference => github.com/go-openapi/jsonreference v0.0.0-20160704190145-13c6e3589ad9
	github.com/go-openapi/spec => github.com/go-openapi/spec v0.0.0-20160808142527-6aced65f8501
	github.com/go-openapi/swag => github.com/go-openapi/swag v0.0.0-20160704191624-1d0bd113de87
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/golang/glog => github.com/openshift/golang-glog v0.0.0-20190322123450-3c92600d7533
	github.com/golang/groupcache => github.com/golang/groupcache v0.0.0-20160516000752-02826c3e7903
	github.com/golang/protobuf => github.com/golang/protobuf v1.3.1
	github.com/google/btree => github.com/google/btree v1.0.0
	github.com/google/go-cmp => github.com/google/go-cmp v0.3.0
	github.com/google/gofuzz => github.com/google/gofuzz v1.0.0
	github.com/google/uuid => github.com/google/uuid v1.1.1
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.0.0-20170729233727-0c5108395e2d
	github.com/gorilla/mux => github.com/gorilla/mux v1.7.4-0.20190830121156-884b5ffcbd3a
	github.com/gregjones/httpcache => github.com/gregjones/httpcache v0.0.0-20170728041850-787624de3eb7
	github.com/grpc-ecosystem/go-grpc-prometheus => github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/golang-lru => github.com/hashicorp/golang-lru v0.5.1
	github.com/imdario/mergo => github.com/imdario/mergo v0.3.5
	github.com/inconshreveable/mousetrap => github.com/inconshreveable/mousetrap v1.0.0
	github.com/json-iterator/go => github.com/json-iterator/go v1.1.7
	github.com/konsorten/go-windows-terminal-sequences => github.com/konsorten/go-windows-terminal-sequences v1.0.1
	github.com/lithammer/dedent => github.com/lithammer/dedent v1.1.1-0.20190124093549-bacd562a6875
	github.com/mailru/easyjson => github.com/mailru/easyjson v0.0.0-20160728113105-d5b7844b561a
	github.com/matttproud/golang_protobuf_extensions => github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/miekg/dns => github.com/miekg/dns v1.0.8
	github.com/mitchellh/go-wordwrap => github.com/mitchellh/go-wordwrap v1.0.0
	github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v1.0.1
	github.com/munnerz/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc8.0.20190926150303-84373aaa560b
	github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.0.2-0.20190911013453-52e2591aa9f7
	github.com/openshift/api => github.com/openshift/api v0.0.0-20190923092516-169848dd8137
	github.com/openshift/client-go => github.com/openshift/client-go v0.0.0-20190923092832-6afefc9bb372
	github.com/pborman/uuid => github.com/pborman/uuid v1.2.0
	github.com/peterbourgon/diskv => github.com/peterbourgon/diskv v2.0.1+incompatible
	github.com/pkg/errors => github.com/pkg/errors v0.8.0
	github.com/pkg/profile => github.com/pkg/profile v1.3.0
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model => github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910
	github.com/prometheus/common => github.com/prometheus/common v0.0.0-20181126121408-4724e9255275
	github.com/prometheus/procfs => github.com/prometheus/procfs v0.0.0-20181204211112-1dc9a6cbc91a
	github.com/russross/blackfriday => github.com/russross/blackfriday v1.5.2
	github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero => github.com/spf13/afero v1.2.2
	github.com/spf13/cobra => github.com/spf13/cobra v0.0.4
	github.com/spf13/pflag => github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink => ./patch/github.com/vishvananda/netlink
	github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20170219233438-54f0e4339ce7
	go.opencensus.io => go.opencensus.io v0.21.0
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20181025213731-e84da0312774
	golang.org/x/net => golang.org/x/net v0.0.0-20190812203447-cdfb69ac37fc
	golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20190402181905-9f3314589c9a
	golang.org/x/sys => golang.org/x/sys v0.0.0-20190209173611-3b5209105503
	golang.org/x/text => golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db
	golang.org/x/time => golang.org/x/time v0.0.0-20161028155119-f51c12702a4d
	google.golang.org/appengine => google.golang.org/appengine v1.5.0
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20190418145605-e7d98fc518a7
	google.golang.org/grpc => google.golang.org/grpc v1.13.0
	gopkg.in/inf.v0 => gopkg.in/inf.v0 v0.9.0
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.2
	k8s.io/api => github.com/openshift/kubernetes/staging/src/k8s.io/api v0.0.0-20190924141618-7eb200efda20
	k8s.io/apiextensions-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20190924141618-7eb200efda20
	k8s.io/apimachinery => github.com/openshift/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20190924141618-7eb200efda20
	k8s.io/apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20190924141618-7eb200efda20
	k8s.io/cli-runtime => github.com/openshift/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20190924141618-7eb200efda20
	k8s.io/client-go => github.com/openshift/kubernetes/staging/src/k8s.io/client-go v0.0.0-20190924141618-7eb200efda20
	k8s.io/cloud-provider => github.com/openshift/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20190924141618-7eb200efda20
	k8s.io/cluster-bootstrap => github.com/openshift/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20190924141618-7eb200efda20
	k8s.io/code-generator => github.com/openshift/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20190924141618-7eb200efda20
	k8s.io/component-base => github.com/openshift/kubernetes/staging/src/k8s.io/component-base v0.0.0-20190924141618-7eb200efda20
	k8s.io/cri-api => github.com/openshift/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20190924141618-7eb200efda20
	k8s.io/csi-translation-lib => github.com/openshift/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20190924141618-7eb200efda20
	k8s.io/kube-aggregator => github.com/openshift/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20190924141618-7eb200efda20
	k8s.io/kube-controller-manager => github.com/openshift/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20190924141618-7eb200efda20
	k8s.io/kube-proxy => github.com/openshift/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20190924141618-7eb200efda20
	k8s.io/kube-scheduler => github.com/openshift/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20190924141618-7eb200efda20
	k8s.io/kubectl => github.com/openshift/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20190924141618-7eb200efda20
	k8s.io/kubelet => github.com/openshift/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20190924141618-7eb200efda20
	k8s.io/kubernetes => github.com/openshift/kubernetes v1.17.0-alpha.0.0.20190924141618-7eb200efda20
	k8s.io/legacy-cloud-providers => github.com/openshift/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20190924141618-7eb200efda20
	k8s.io/metrics => github.com/openshift/kubernetes/staging/src/k8s.io/metrics v0.0.0-20190924141618-7eb200efda20
	k8s.io/node-api => github.com/openshift/kubernetes/staging/src/k8s.io/node-api v0.0.0-20190924141618-7eb200efda20
	k8s.io/sample-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20190924141618-7eb200efda20
	k8s.io/sample-cli-plugin => github.com/openshift/kubernetes/staging/src/k8s.io/sample-cli-plugin v0.0.0-20190924141618-7eb200efda20
	k8s.io/sample-controller => github.com/openshift/kubernetes/staging/src/k8s.io/sample-controller v0.0.0-20190924141618-7eb200efda20
	k8s.io/util => github.com/openshift/kubernetes/staging/src/k8s.io/util v0.0.0-20190924141618-7eb200efda20
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)
