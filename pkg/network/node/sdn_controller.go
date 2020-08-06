// +build linux

package node

import (
	"errors"
	"fmt"
	"net"
	"time"

	"k8s.io/klog"

	"github.com/openshift/sdn/pkg/network/common"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/pkg/util/sysctl"

	"github.com/vishvananda/netlink"
)

func (plugin *OsdnNode) alreadySetUp() error {
	var found bool

	l, err := netlink.LinkByName(Tun0)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	found = false
	for _, addr := range addrs {
		if addr.IPNet.String() == plugin.localGatewayCIDR {
			found = true
			break
		}
	}
	if !found {
		return errors.New("local subnet gateway CIDR not found")
	}

	routes, err := netlink.RouteList(l, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, clusterCIDR := range plugin.clusterCIDRs {
		found = false
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == clusterCIDR {
				found = true
				break
			}
		}
		if !found {
			return errors.New("cluster CIDR not found")
		}
	}

	if !plugin.oc.AlreadySetUp(plugin.networkInfo.VXLANPort) {
		return errors.New("plugin is not setup")
	}

	return nil
}

func deleteLocalSubnetRoute(device, localSubnetCIDR string) {
	// ~1 sec total
	backoff := utilwait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.25,
		Steps:    7,
	}
	err := utilwait.ExponentialBackoff(backoff, func() (bool, error) {
		l, err := netlink.LinkByName(device)
		if err != nil {
			return false, fmt.Errorf("could not get interface %s: %v", device, err)
		}
		routes, err := netlink.RouteList(l, netlink.FAMILY_V4)
		if err != nil {
			return false, fmt.Errorf("could not get routes: %v", err)
		}
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == localSubnetCIDR {
				err = netlink.RouteDel(&route)
				if err != nil {
					return false, fmt.Errorf("could not delete route: %v", err)
				}
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Error removing %s route from dev %s: %v; if the route appears later it will not be deleted.", localSubnetCIDR, device, err))
	}
}

func (plugin *OsdnNode) SetupSDN() (bool, map[string]podNetworkInfo, error) {
	// Make sure IPv4 forwarding state is 1
	sysctl := sysctl.New()
	val, err := sysctl.GetSysctl("net/ipv4/ip_forward")
	if err != nil {
		return false, nil, fmt.Errorf("could not get IPv4 forwarding state: %s", err)
	}
	if val != 1 {
		return false, nil, fmt.Errorf("net/ipv4/ip_forward=0, it must be set to 1")
	}

	localSubnetCIDR := plugin.localSubnetCIDR
	_, ipnet, err := net.ParseCIDR(localSubnetCIDR)
	if err != nil {
		return false, nil, fmt.Errorf("invalid local subnet CIDR: %v", err)
	}
	localSubnetMaskLength, _ := ipnet.Mask.Size()
	localSubnetGateway := common.GenerateDefaultGateway(ipnet).String()

	klog.V(5).Infof("[SDN setup] node pod subnet %s gateway %s", ipnet.String(), localSubnetGateway)

	plugin.localGatewayCIDR = fmt.Sprintf("%s/%d", localSubnetGateway, localSubnetMaskLength)

	if err := waitForOVS(ovsDialDefaultNetwork, ovsDialDefaultAddress); err != nil {
		return false, nil, err
	}

	var changed bool
	existingPods, err := plugin.oc.GetPodNetworkInfo()
	if err != nil {
		klog.Warningf("[SDN setup] Could not get details of existing pods: %v", err)
	}

	if err := plugin.alreadySetUp(); err == nil {
		klog.Infof("[SDN setup] SDN is already set up")
	} else {
		klog.Infof("[SDN setup] full SDN setup required (%v)", err)
		if err := plugin.setup(localSubnetCIDR, localSubnetGateway); err != nil {
			return false, nil, err
		}
		changed = true
	}

	return changed, existingPods, nil
}

func (plugin *OsdnNode) FinishSetupSDN() error {
	err := plugin.oc.FinishSetupOVS()
	if err != nil {
		return err
	}

	// TODO: make it possible to safely reestablish node configuration after restart
	// If OVS goes down and fails the health check, restart the entire process
	runOVSHealthCheck(ovsDialDefaultNetwork, ovsDialDefaultAddress, plugin.alreadySetUp)

	return nil
}

func (plugin *OsdnNode) setup(localSubnetCIDR, localSubnetGateway string) error {
	serviceNetworkCIDR := plugin.networkInfo.ServiceNetwork.String()

	if err := plugin.oc.SetupOVS(plugin.clusterCIDRs, serviceNetworkCIDR, localSubnetCIDR, localSubnetGateway, plugin.networkInfo.MTU, plugin.networkInfo.VXLANPort); err != nil {
		return err
	}

	l, err := netlink.LinkByName(Tun0)
	if err == nil {
		gwIP, _ := netlink.ParseIPNet(plugin.localGatewayCIDR)
		err = netlink.AddrAdd(l, &netlink.Addr{IPNet: gwIP})
		if err == nil {
			defer deleteLocalSubnetRoute(Tun0, localSubnetCIDR)
		}
	}
	if err == nil {
		err = netlink.LinkSetUp(l)
	}
	if err == nil {
		for _, clusterNetwork := range plugin.networkInfo.ClusterNetworks {
			route := &netlink.Route{
				LinkIndex: l.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       clusterNetwork.ClusterCIDR,
			}
			if err = netlink.RouteAdd(route); err != nil {
				return err
			}
		}
	}
	if err == nil {
		route := &netlink.Route{
			LinkIndex: l.Attrs().Index,
			Dst:       plugin.networkInfo.ServiceNetwork,
		}
		err = netlink.RouteAdd(route)
	}
	if err != nil {
		return err
	}

	return nil
}

func (plugin *OsdnNode) updateEgressNetworkPolicyRules(vnid uint32) {
	policies := plugin.egressPolicies[vnid]
	namespaces := plugin.policy.GetNamespaces(vnid)
	if err := plugin.oc.UpdateEgressNetworkPolicyRules(policies, vnid, namespaces, plugin.egressDNS); err != nil {
		utilruntime.HandleError(fmt.Errorf("Error updating OVS flows for EgressNetworkPolicy: %v", err))
	}
}
