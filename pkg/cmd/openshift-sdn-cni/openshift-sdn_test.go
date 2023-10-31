package openshift_sdn_cni

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cniskel "github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cni020 "github.com/containernetworking/cni/pkg/types/020"
	cni040 "github.com/containernetworking/cni/pkg/types/040"
	cni100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/openshift/sdn/pkg/network/common/cniserver"
	utiltesting "k8s.io/client-go/util/testing"
)

var resultFromServer cnitypes.Result
var generateError bool

func serverHandleCNI(request *cniserver.PodRequest) ([]byte, error) {
	if request.Command == cniserver.CNI_ADD {
		return json.Marshal(&resultFromServer)
	} else if request.Command == cniserver.CNI_DEL {
		return nil, nil
	}
	return nil, fmt.Errorf("unhandled CNI command %v", request.Command)
}

const (
	CNI_COMMAND     string = "CNI_COMMAND"
	CNI_CONTAINERID string = "CNI_CONTAINERID"
	CNI_NETNS       string = "CNI_NETNS"
	CNI_IFNAME      string = "CNI_IFNAME"
	CNI_ARGS        string = "CNI_ARGS"
	CNI_PATH        string = "CNI_PATH"
)

func skelArgsToEnv(command cniserver.CNICommand, args *cniskel.CmdArgs) {
	os.Setenv(CNI_COMMAND, fmt.Sprintf("%v", command))
	os.Setenv(CNI_CONTAINERID, args.ContainerID)
	os.Setenv(CNI_NETNS, args.Netns)
	os.Setenv(CNI_IFNAME, args.IfName)
	os.Setenv(CNI_ARGS, args.Args)
	os.Setenv(CNI_PATH, args.Path)
}

func clearEnv() {
	for _, ev := range []string{CNI_COMMAND, CNI_CONTAINERID, CNI_NETNS, CNI_IFNAME, CNI_ARGS, CNI_PATH} {
		os.Unsetenv(ev)
	}
}

type dummyHostNS struct{}

func (ns *dummyHostNS) Do(toRun func(ns.NetNS) error) error {
	return toRun(ns)
}
func (ns *dummyHostNS) Set() error {
	panic("should not be reached")
}
func (ns *dummyHostNS) Path() string {
	panic("should not be reached")
}
func (ns *dummyHostNS) Fd() uintptr {
	panic("should not be reached")
}
func (ns *dummyHostNS) Close() error {
	panic("should not be reached")
}

func TestOpenshiftSdnCNIPlugin(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("cniserver")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, cniserver.CNIServerSocketName)
	server := cniserver.NewCNIServer(tmpDir, &cniserver.Config{OverlayMTU: 1500})
	if err := server.Start(serverHandleCNI); err != nil {
		t.Fatalf("error starting CNI server: %v", err)
	}

	cniPlugin := NewCNIPlugin(path, &dummyHostNS{})

	expectedIP, expectedNet, _ := net.ParseCIDR("10.0.0.2/24")
	expectedGateway := net.ParseIP("10.0.0.1")
	resultFromServer = &cni100.Result{
		CNIVersion: "1.0.0",
		IPs: []*cni100.IPConfig{
			{
				Address: net.IPNet{
					IP:   expectedIP,
					Mask: expectedNet.Mask,
				},
				Gateway: expectedGateway,
			},
		},
		Routes: []*cnitypes.Route{
			{
				Dst: net.IPNet{
					IP:   expectedIP,
					Mask: expectedNet.Mask,
				},
				GW: nil,
			},
		},
	}

	type testcase struct {
		name        string
		skelArgs    *cniskel.CmdArgs
		reqType     cniserver.CNICommand
		result      cnitypes.Result
		errorPrefix string
	}

	testcases := []testcase{
		// Normal ADD request
		{
			name:    "ADD",
			reqType: cniserver.CNI_ADD,
			skelArgs: &cniskel.CmdArgs{
				ContainerID: "adsfadsfasfdasdfasf",
				Netns:       "/path/to/something",
				IfName:      "eth0",
				Args:        "K8S_POD_NAMESPACE=awesome-namespace;K8S_POD_NAME=awesome-name",
				Path:        "/some/path",
				StdinData:   []byte("{\"cniVersion\": \"0.1.0\",\"name\": \"openshift-sdn\",\"type\": \"openshift-sdn\"}"),
			},
			result: &cni020.Result{
				CNIVersion: "0.1.0",
				IP4: &cni020.IPConfig{
					IP: net.IPNet{
						IP:   expectedIP,
						Mask: expectedNet.Mask,
					},
					Gateway: expectedGateway,
					Routes: []cnitypes.Route{
						{
							Dst: net.IPNet{
								IP:   expectedIP,
								Mask: expectedNet.Mask,
							},
						},
					},
				},
			},
		},
		// ADD request using cniVersion 0.3.1
		{
			name:    "ADD-0.3.1",
			reqType: cniserver.CNI_ADD,
			skelArgs: &cniskel.CmdArgs{
				ContainerID: "adsfadsfasfdasdfasf",
				Netns:       "/path/to/something",
				IfName:      "eth0",
				Args:        "K8S_POD_NAMESPACE=awesome-namespace;K8S_POD_NAME=awesome-name",
				Path:        "/some/path",
				StdinData:   []byte("{\"cniVersion\": \"0.3.1\",\"name\": \"openshift-sdn\",\"type\": \"openshift-sdn\"}"),
			},
			result: &cni040.Result{
				CNIVersion: "0.3.1",
				IPs: []*cni040.IPConfig{
					{
						Version: "4",
						Address: net.IPNet{
							IP:   expectedIP,
							Mask: expectedNet.Mask,
						},
						Gateway: expectedGateway,
					},
				},
				Routes: []*cnitypes.Route{
					{
						Dst: net.IPNet{
							IP:   expectedIP,
							Mask: expectedNet.Mask,
						},
						GW: nil,
					},
				},
			},
		},
		// ADD request using cniVersion 0.4.0
		{
			name:    "ADD-0.4.0",
			reqType: cniserver.CNI_ADD,
			skelArgs: &cniskel.CmdArgs{
				ContainerID: "adsfadsfasfdasdfasf",
				Netns:       "/path/to/something",
				IfName:      "eth0",
				Args:        "K8S_POD_NAMESPACE=awesome-namespace;K8S_POD_NAME=awesome-name",
				Path:        "/some/path",
				StdinData:   []byte("{\"cniVersion\": \"0.4.0\",\"name\": \"openshift-sdn\",\"type\": \"openshift-sdn\"}"),
			},
			result: &cni040.Result{
				CNIVersion: "0.4.0",
				IPs: []*cni040.IPConfig{
					{
						Version: "4",
						Address: net.IPNet{
							IP:   expectedIP,
							Mask: expectedNet.Mask,
						},
						Gateway: expectedGateway,
					},
				},
				Routes: []*cnitypes.Route{
					{
						Dst: net.IPNet{
							IP:   expectedIP,
							Mask: expectedNet.Mask,
						},
						GW: nil,
					},
				},
			},
		},
		// ADD request using cniVersion 1.0.0
		{
			name:    "ADD-1.0.0",
			reqType: cniserver.CNI_ADD,
			skelArgs: &cniskel.CmdArgs{
				ContainerID: "adsfadsfasfdasdfasf",
				Netns:       "/path/to/something",
				IfName:      "eth0",
				Args:        "K8S_POD_NAMESPACE=awesome-namespace;K8S_POD_NAME=awesome-name",
				Path:        "/some/path",
				StdinData:   []byte("{\"cniVersion\": \"1.0.0\",\"name\": \"openshift-sdn\",\"type\": \"openshift-sdn\"}"),
			},
			result: &cni100.Result{
				CNIVersion: "1.0.0",
				IPs: []*cni100.IPConfig{
					{
						Address: net.IPNet{
							IP:   expectedIP,
							Mask: expectedNet.Mask,
						},
						Gateway: expectedGateway,
					},
				},
				Routes: []*cnitypes.Route{
					{
						Dst: net.IPNet{
							IP:   expectedIP,
							Mask: expectedNet.Mask,
						},
						GW: nil,
					},
				},
			},
		},
		// Normal DEL request
		{
			name:    "DEL",
			reqType: cniserver.CNI_DEL,
			skelArgs: &cniskel.CmdArgs{
				ContainerID: "adsfadsfasfdasdfasf",
				Netns:       "/path/to/something",
				IfName:      "eth0",
				Args:        "K8S_POD_NAMESPACE=awesome-namespace;K8S_POD_NAME=awesome-name",
				Path:        "/some/path",
				StdinData:   []byte("{\"cniVersion\": \"0.1.0\",\"name\": \"openshift-sdn\",\"type\": \"openshift-sdn\"}"),
			},
		},
		// Missing args
		{
			name:    "NO ARGS",
			reqType: cniserver.CNI_ADD,
			skelArgs: &cniskel.CmdArgs{
				ContainerID: "adsfadsfasfdasdfasf",
				Netns:       "/path/to/something",
				IfName:      "eth0",
				Path:        "/some/path",
				StdinData:   []byte("{\"cniVersion\": \"0.1.0\",\"name\": \"openshift-sdn\",\"type\": \"openshift-sdn\"}"),
			},
			errorPrefix: "CNI request failed with status 400: 'invalid CNI_ARG",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var result cnitypes.Result
			var err error

			skelArgsToEnv(tc.reqType, tc.skelArgs)
			switch tc.reqType {
			case cniserver.CNI_ADD:
				result, err = cniPlugin.testCmdAdd(tc.skelArgs)
			case cniserver.CNI_DEL:
				err = cniPlugin.CmdDel(tc.skelArgs)
			default:
				t.Fatalf("[%s] unhandled CNI command type", tc.name)
			}
			clearEnv()

			if tc.errorPrefix == "" {
				if err != nil {
					t.Fatalf("[%s] expected result %v but got error: %v", tc.name, tc.result, err)
				}
				if tc.result != nil && !reflect.DeepEqual(result, tc.result) {
					t.Fatalf("[%s] expected result:\n%v\nbut got:\n%v", tc.name, tc.result, result)
				}
			} else if !strings.HasPrefix(fmt.Sprintf("%v", err), tc.errorPrefix) {
				t.Fatalf("[%s] unexpected error message '%v'", tc.name, err)
			}
		})
	}
}
