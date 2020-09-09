This is openshift-sdn, the default network plugin for OpenShift (both
OKD and OCP). It uses Open vSwitch to connect pods locally, with VXLAN
tunnels to connect different nodes.

OpenShift SDN is designed to be installed by the [OpenShift Network
Operator](https://github.com/openshift/cluster-network-operator), and
certain components of it (such as the Deployment and DaemonSet
objects) are found there.

This module defines two images: the sdn image, which contains OpenShift SDN
(both controller and node components) and the kube-proxy image, which is
deployed by the Network Operator for third-party network plugins that need it.
(Kube-proxy is built from here rather than from the origin repo so
that we only have to maintain kube-proxy bugfix/security backports in
one place.)

## OpenShift SDN Types

For historical reasons, OpenShift SDN's types are defined in the
`network.openshift.io` namespace and are part of the
[`openshift/api`](https://github.com/openshift/api) module, despite
being used only when OpenShift SDN is the configured network plugin.

Because the OpenShift aggregated apiserver runs in the pod network,
not on the host network, OpenShift SDN cannot depend on it. Therefore,
although the types are defined in `openshift/api`, they are actually
implemented as `CustomResourceDefinition`s in the main apiserver. The
Network Operator creates the CRD definitions.

## The OpenShift SDN Controller

The network controller is run on
the masters to handle cluster-level processing:

  - Creating `NetNamespace` objects corresponding to `Namespace`s
  - Creating `HostSubnet` objects corresponding to `Node`s
  - Implementing high availability for egress IPs

In older releases, the controller was also responsible for reading the
cluster master configuration and creating the `ClusterNetwork` object
containing configuration information to be used by the nodes. As of
OpenShift 4.2, the `ClusterNetwork` is created by the Network
Operator.

## OpenShift SDN Nodes

The `openshift-sdn` daemon runs on every node,
reads the `ClusterNetwork` object and the `HostSubnet` object for the
node it is running on, and uses that information to configure the node
as part of the cluster. This includes:

  - Providing networking to Pods, as requested by the `openshift-sdn`
    CNI plugin  (which is a small shim that just talks to the daemon).

  - Setting up the OVS bridge, and managing OVS flows as needed for
    Pods, Services, NetworkPolicy, and EgressNetworkPolicy; and adding
    and removing flows as needed for communicating with other nodes.

  - Setting up iptables rules for masquerading outbound traffic, and
    ensure that OpenShift's own traffic does not get firewalled.

  - Updating OVS flows and iptables rules for static egress IPs.

  - Implementing the Service proxy via a built-in copy of kube-proxy,
    in either the "userspace" mode, "iptables" mode, or the hybrid
    "unidling" mode.
