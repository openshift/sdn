package openshift_sdn_cni

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/sdn/pkg/network/common/cniserver"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
)

type cniPlugin struct {
	socketPath string
	hostNS     ns.NetNS
}

func NewCNIPlugin(socketPath string, hostNS ns.NetNS) *cniPlugin {
	return &cniPlugin{socketPath: socketPath, hostNS: hostNS}
}

// Create and fill a CNIRequest with this plugin's environment and stdin which
// contain the CNI variables and configuration
func newCNIRequest(args *skel.CmdArgs) *cniserver.CNIRequest {
	envMap := make(map[string]string)
	for _, item := range os.Environ() {
		idx := strings.Index(item, "=")
		if idx > 0 {
			envMap[strings.TrimSpace(item[:idx])] = item[idx+1:]
		}
	}

	return &cniserver.CNIRequest{
		Env:    envMap,
		Config: args.StdinData,
	}
}

// Send a CNI request to the CNI server via JSON + HTTP over a root-owned unix socket,
// and return the result
func (p *cniPlugin) doCNI(url string, req *cniserver.CNIRequest) ([]byte, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CNI request %v: %v", req, err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(proto, addr string) (net.Conn, error) {
				return net.Dial("unix", p.socketPath)
			},
		},
	}

	var resp *http.Response
	err = p.hostNS.Do(func(ns.NetNS) error {
		resp, err = client.Post(url, "application/json", bytes.NewReader(data))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send CNI request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CNI result: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CNI request failed with status %v: '%s'", resp.StatusCode, string(body))
	}

	return body, nil
}

// Send the ADD command environment and config to the CNI server, returning
// the IPAM result to the caller
func (p *cniPlugin) doCNIServerAdd(req *cniserver.CNIRequest, hostVeth string) (*current.Result, error) {
	req.HostVeth = hostVeth
	body, err := p.doCNI("http://dummy/", req)
	if err != nil {
		return nil, err
	}

	// We currently expect CNI version 0.3.1 results, because that's the
	// CNIVersion we pass in our config JSON
	result, err := current.NewResult(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response '%s': %v", string(body), err)
	}

	return result.(*current.Result), nil
}

func (p *cniPlugin) testCmdAdd(args *skel.CmdArgs) (types.Result, error) {
	result, err := p.doCNIServerAdd(newCNIRequest(args), "dummy0")
	if err != nil {
		return nil, err
	}
	return convertToRequestedVersion(args.StdinData, result)
}

// sets up the host side of a veth for UDP Generic Receive Offload
func setupUDPOffloadHost(ifname string) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("failed to initialize ethtool: %v", err)
	}
	defer e.Close()

	err = e.Change(ifname, map[string]bool{
		"rx-gro":                true,
		"rx-udp-gro-forwarding": true,
	})
	if err != nil {
		return fmt.Errorf("could not enable UDP offload features: %v", err)
	}
	channels, err := e.GetChannels(ifname)
	if err != nil {
		return fmt.Errorf("could not query interface channels: %v", err)
	}
	channels.RxCount = uint32(runtime.NumCPU())
	_, err = e.SetChannels(ifname, channels)
	if err != nil {
		return fmt.Errorf("could not update interface channels: %v", err)
	}

	timeoutFile := fmt.Sprintf("/sys/class/net/%s/gro_flush_timeout", ifname)
	err = os.WriteFile(timeoutFile, []byte("50000\n"), 0644)
	if err != nil {
		return fmt.Errorf("could not set UDP flush timeout: %v", err)
	}

	return nil
}

// sets up the container side of a veth for UDP Generic Receive Offload
func setupUDPOffloadContainer(ifname string) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("failed to initialize ethtool: %v", err)
	}
	defer e.Close()

	channels, err := e.GetChannels(ifname)
	if err != nil {
		return fmt.Errorf("could not query interface channels: %v", err)
	}
	channels.TxCount = uint32(runtime.NumCPU())
	_, err = e.SetChannels(ifname, channels)
	if err != nil {
		return fmt.Errorf("could not update interface channels: %v", err)
	}

	return nil
}

func generateIPTablesCommands(platformType string) [][]string {
	metadataServiceIP := "169.254.169.254"
	if platformType == string(configv1.AlibabaCloudPlatformType) {
		metadataServiceIP = "100.100.100.200"
	}
	return [][]string{
		// Block MCS
		{"-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "22623", "--syn", "-j", "REJECT"},
		{"-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "22624", "--syn", "-j", "REJECT"},
		{"-A", "FORWARD", "-p", "tcp", "-m", "tcp", "--dport", "22623", "--syn", "-j", "REJECT"},
		{"-A", "FORWARD", "-p", "tcp", "-m", "tcp", "--dport", "22624", "--syn", "-j", "REJECT"},

		// Block cloud provider metadata IP except DNS
		{"-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "-d", metadataServiceIP, "!", "--dport", "53", "-j", "REJECT"},
		{"-A", "OUTPUT", "-p", "udp", "-m", "udp", "-d", metadataServiceIP, "!", "--dport", "53", "-j", "REJECT"},
		{"-A", "FORWARD", "-p", "tcp", "-m", "tcp", "-d", metadataServiceIP, "!", "--dport", "53", "-j", "REJECT"},
		{"-A", "FORWARD", "-p", "udp", "-m", "udp", "-d", metadataServiceIP, "!", "--dport", "53", "-j", "REJECT"},
	}
}

func (p *cniPlugin) CmdAdd(args *skel.CmdArgs) error {
	req := newCNIRequest(args)
	config, err := cniserver.ReadConfig(cniserver.CNIServerConfigFilePath)
	if err != nil {
		return err
	}

	var hostVeth, contVeth net.Interface
	err = ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
		hostVeth, contVeth, err = ip.SetupVeth(args.IfName, int(config.OverlayMTU), hostNS)
		if err != nil {
			return fmt.Errorf("failed to create container veth: %v", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	result, err := p.doCNIServerAdd(req, hostVeth.Name)
	if err != nil {
		return err
	}

	if err != nil || len(result.IPs) != 1 || result.IPs[0].Version != "4" {
		return fmt.Errorf("Unexpected IPAM result: %v", err)
	}

	// ipam.ConfigureIface handles the Routes "incorrectly" (if there is no gateway
	// specified it uses the interface's default gateway as the next hop rather than
	// passing nil as the next hop. Additionally, we may need to set the MTU on the
	// routes. So pull out the routes to handle on our own.
	defaultGW := result.IPs[0].Gateway
	routes := result.Routes
	result.Routes = nil

	// Add a sandbox interface record which ConfigureInterface expects.
	// The only interface we report is the pod interface.
	result.Interfaces = []*current.Interface{
		{
			Name:    args.IfName,
			Mac:     contVeth.HardwareAddr.String(),
			Sandbox: args.Netns,
		},
	}
	result.IPs[0].Interface = current.Int(0)

	err = ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
		// Set up eth0
		if err := ip.SetHWAddrByIP(args.IfName, result.IPs[0].Address.IP, nil); err != nil {
			return fmt.Errorf("failed to set pod interface MAC address: %v", err)
		}
		if err := ipam.ConfigureIface(args.IfName, result); err != nil {
			return fmt.Errorf("failed to configure container IPAM: %v", err)
		}

		// Set up lo
		link, err := netlink.LinkByName("lo")
		if err == nil {
			err = netlink.LinkSetUp(link)
		}
		if err != nil {
			return fmt.Errorf("failed to configure container loopback: %v", err)
		}

		// Set up macvlan0 (if it exists)
		link, err = netlink.LinkByName("macvlan0")
		if err == nil {
			err = netlink.LinkSetUp(link)
			if err != nil {
				return fmt.Errorf("failed to enable macvlan device: %v", err)
			}

			// A macvlan can't reach its parent interface's IP, so we need to
			// add a route to that via the SDN
			var addrs []netlink.Addr
			err = hostNS.Do(func(ns.NetNS) error {
				// workaround for https://bugzilla.redhat.com/show_bug.cgi?id=1705686
				parentIndex := link.Attrs().ParentIndex
				if parentIndex == 0 {
					parentIndex = link.Attrs().Index
				}

				parent, err := netlink.LinkByIndex(parentIndex)
				if err != nil {
					return err
				}
				addrs, err = netlink.AddrList(parent, netlink.FAMILY_V4)
				return err
			})
			if err != nil {
				return fmt.Errorf("failed to configure macvlan device: %v", err)
			}
			for _, addr := range addrs {
				routes = append(routes, &types.Route{
					Dst: net.IPNet{IP: addr.IP, Mask: net.CIDRMask(32, 32)},
					GW:  defaultGW,
				})
			}
		}

		link, err = netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to configure network interface %q: %v", args.IfName, err)
		}
		for _, cniroute := range routes {
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       &cniroute.Dst,
				Gw:        cniroute.GW,
				MTU:       int(config.RoutableMTU),
			}
			if err := netlink.RouteAdd(route); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to add route to %s via SDN: %v", route.Dst.String(), err)
			}
		}

		// Block access to certain things
		for _, args := range generateIPTablesCommands(config.PlatformType) {
			out, err := exec.Command("iptables", append([]string{"-w"}, args...)...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("could not set up pod iptables rules: %s", string(out))
			}
		}

		// Enable UDP GRO
		err = setupUDPOffloadContainer(args.IfName)
		if err != nil {
			return fmt.Errorf("could not enable UDP GRO: %v", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Enable UDP GRO
	err = setupUDPOffloadHost(hostVeth.Name)
	if err != nil {
		return fmt.Errorf("could not enable UDP GRO: %v", err)
	}

	convertedResult, err := convertToRequestedVersion(req.Config, result)
	if err != nil {
		return err
	}
	return convertedResult.Print()
}

func convertToRequestedVersion(stdinData []byte, result *current.Result) (types.Result, error) {
	// Plugin must return result in same version as specified in netconf
	versionDecoder := &version.ConfigDecoder{}
	confVersion, err := versionDecoder.Decode(stdinData)
	if err != nil {
		return nil, err
	}

	newResult, err := result.GetAsVersion(confVersion)
	if err != nil {
		return nil, err
	}
	return newResult, nil
}

func (p *cniPlugin) CmdDel(args *skel.CmdArgs) error {
	_, err := p.doCNI("http://dummy/", newCNIRequest(args))
	return err
}
