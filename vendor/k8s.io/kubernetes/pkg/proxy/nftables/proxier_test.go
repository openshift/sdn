/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nftables

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danwinship/nftables"
	"github.com/lithammer/dedent"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/component-base/metrics/testutil"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/conntrack"
	"k8s.io/kubernetes/pkg/proxy/metrics"

	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	proxyutiliptables "k8s.io/kubernetes/pkg/proxy/util/iptables"
	proxyutiltest "k8s.io/kubernetes/pkg/proxy/util/testing"
	"k8s.io/kubernetes/pkg/util/async"
	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
	netutils "k8s.io/utils/net"
	"k8s.io/utils/pointer"
)

// (Note that we don't use UDP ports in most of the tests here, because if you create UDP
// services you have to deal with setting up the FakeExec correctly for the conntrack
// cleanup calls.)
var tcpProtocol = v1.ProtocolTCP
var sctpProtocol = v1.ProtocolSCTP

func TestDeleteEndpointConnections(t *testing.T) {
	const (
		UDP  = v1.ProtocolUDP
		TCP  = v1.ProtocolTCP
		SCTP = v1.ProtocolSCTP
	)

	testCases := []struct {
		description  string
		svcName      string
		svcIP        string
		svcPort      int32
		protocol     v1.Protocol
		endpoint     string // IP:port endpoint
		simulatedErr string
	}{
		{
			description: "V4 UDP",
			svcName:     "v4-udp",
			svcIP:       "172.30.1.1",
			svcPort:     80,
			protocol:    UDP,
			endpoint:    "10.240.0.3:80",
		},
		{
			description: "V4 TCP",
			svcName:     "v4-tcp",
			svcIP:       "172.30.2.2",
			svcPort:     80,
			protocol:    TCP,
			endpoint:    "10.240.0.4:80",
		},
		{
			description: "V4 SCTP",
			svcName:     "v4-sctp",
			svcIP:       "172.30.3.3",
			svcPort:     80,
			protocol:    SCTP,
			endpoint:    "10.240.0.5:80",
		},
		{
			description:  "V4 UDP, nothing to delete, benign error",
			svcName:      "v4-udp-nothing-to-delete",
			svcIP:        "172.30.4.4",
			svcPort:      80,
			protocol:     UDP,
			endpoint:     "10.240.0.6:80",
			simulatedErr: conntrack.NoConnectionToDelete,
		},
		{
			description:  "V4 UDP, unexpected error, should be glogged",
			svcName:      "v4-udp-simulated-error",
			svcIP:        "172.30.5.5",
			svcPort:      80,
			protocol:     UDP,
			endpoint:     "10.240.0.7:80",
			simulatedErr: "simulated error",
		},
		{
			description: "V6 UDP",
			svcName:     "v6-udp",
			svcIP:       "fd00:1234::20",
			svcPort:     80,
			protocol:    UDP,
			endpoint:    "[2001:db8::2]:80",
		},
		{
			description: "V6 TCP",
			svcName:     "v6-tcp",
			svcIP:       "fd00:1234::30",
			svcPort:     80,
			protocol:    TCP,
			endpoint:    "[2001:db8::3]:80",
		},
		{
			description: "V6 SCTP",
			svcName:     "v6-sctp",
			svcIP:       "fd00:1234::40",
			svcPort:     80,
			protocol:    SCTP,
			endpoint:    "[2001:db8::4]:80",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			priorGlogErrs := klog.Stats.Error.Lines()

			// Create a fake executor for the conntrack utility.
			fcmd := fakeexec.FakeCmd{}
			fexec := &fakeexec.FakeExec{
				LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
			}
			execFunc := func(cmd string, args ...string) exec.Cmd {
				return fakeexec.InitFakeCmd(&fcmd, cmd, args...)
			}

			if tc.protocol == UDP {
				cmdOutput := "1 flow entries have been deleted"
				var simErr error

				// First call outputs cmdOutput and succeeds
				fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript,
					func() ([]byte, []byte, error) { return []byte(cmdOutput), nil, nil },
				)
				fexec.CommandScript = append(fexec.CommandScript, execFunc)

				// Second call may succeed or fail
				if tc.simulatedErr != "" {
					cmdOutput = ""
					simErr = fmt.Errorf(tc.simulatedErr)
				}
				fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript,
					func() ([]byte, []byte, error) { return []byte(cmdOutput), nil, simErr },
				)
				fexec.CommandScript = append(fexec.CommandScript, execFunc)
			}

			endpointIP := proxyutil.IPPart(tc.endpoint)
			isIPv6 := netutils.IsIPv6String(endpointIP)

			var fp *Proxier
			if isIPv6 {
				nft := nftables.NewFake(nftables.IPv6Family, kubeProxyTable)
				fp = NewFakeProxier(nft, v1.IPv6Protocol)
			} else {
				nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
				fp = NewFakeProxier(nft, v1.IPv4Protocol)
			}
			fp.exec = fexec

			makeServiceMap(fp,
				makeTestService("ns1", tc.svcName, func(svc *v1.Service) {
					svc.Spec.ClusterIP = tc.svcIP
					svc.Spec.Ports = []v1.ServicePort{{
						Name:     "p80",
						Port:     tc.svcPort,
						Protocol: tc.protocol,
					}}
					svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
				}),
			)
			fp.svcPortMap.Update(fp.serviceChanges)

			slice := makeTestEndpointSlice("ns1", tc.svcName, 1, func(eps *discovery.EndpointSlice) {
				if isIPv6 {
					eps.AddressType = discovery.AddressTypeIPv6
				} else {
					eps.AddressType = discovery.AddressTypeIPv4
				}
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{endpointIP},
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tc.protocol,
				}}
			})

			// Add and then remove the endpoint slice
			fp.OnEndpointSliceAdd(slice)
			fp.syncProxyRules()
			fp.OnEndpointSliceDelete(slice)
			fp.syncProxyRules()

			// Check the executed conntrack command
			if tc.protocol == UDP {
				if fexec.CommandCalls != 2 {
					t.Fatalf("Expected conntrack to be executed 2 times, but got %d", fexec.CommandCalls)
				}

				// First clear conntrack entries for the clusterIP when the
				// endpoint is first added.
				expectCommand := fmt.Sprintf("conntrack -D --orig-dst %s -p udp", tc.svcIP)
				if isIPv6 {
					expectCommand += " -f ipv6"
				}
				actualCommand := strings.Join(fcmd.CombinedOutputLog[0], " ")
				if actualCommand != expectCommand {
					t.Errorf("Expected command: %s, but executed %s", expectCommand, actualCommand)
				}

				// Then clear conntrack entries for the endpoint when it is
				// deleted.
				expectCommand = fmt.Sprintf("conntrack -D --orig-dst %s --dst-nat %s -p udp", tc.svcIP, endpointIP)
				if isIPv6 {
					expectCommand += " -f ipv6"
				}
				actualCommand = strings.Join(fcmd.CombinedOutputLog[1], " ")
				if actualCommand != expectCommand {
					t.Errorf("Expected command: %s, but executed %s", expectCommand, actualCommand)
				}
			} else if fexec.CommandCalls != 0 {
				t.Fatalf("Expected conntrack to be executed 0 times, but got %d", fexec.CommandCalls)
			}

			// Check the number of new glog errors
			var expGlogErrs int64
			if tc.simulatedErr != "" && tc.simulatedErr != conntrack.NoConnectionToDelete {
				expGlogErrs = 1
			}
			glogErrs := klog.Stats.Error.Lines() - priorGlogErrs
			if glogErrs != expGlogErrs {
				t.Errorf("Expected %d glogged errors, but got %d", expGlogErrs, glogErrs)
			}
		})
	}
}

// Conventions for tests using NewFakeProxier:
//
// Pod IPs:             10.0.0.0/8
// Service ClusterIPs:  172.30.0.0/16
// Node IPs:            192.168.0.0/24
// Local Node IP:       192.168.0.2
// Service ExternalIPs: 192.168.99.0/24
// LoadBalancer IPs:    1.2.3.4, 5.6.7.8, 9.10.11.12
// Non-cluster IPs:     203.0.113.0/24
// LB Source Range:     203.0.113.0/25

const testHostname = "test-hostname"
const testNodeIP = "192.168.0.2"
const testNodeIPAlt = "192.168.1.2"
const testExternalIP = "192.168.99.11"
const testNodeIPv6 = "2001:db8::1"
const testNodeIPv6Alt = "2001:db8:1::2"
const testExternalClient = "203.0.113.2"
const testExternalClientBlocked = "203.0.113.130"

var testNodeIPs = []string{testNodeIP, testNodeIPAlt, testExternalIP, testNodeIPv6, testNodeIPv6Alt}

func NewFakeProxier(nft nftables.Interface, ipFamily v1.IPFamily) *Proxier {
	// TODO: Call NewProxier after refactoring out the goroutine
	// invocation into a Run() method.
	podCIDR := "10.0.0.0/8"
	nftablesFamily := nftables.IPv4Family
	if ipFamily == v1.IPv6Protocol {
		podCIDR = "fd00:10::/64"
		nftablesFamily = nftables.IPv6Family
	}
	detectLocal, _ := proxyutiliptables.NewDetectLocalByCIDR(podCIDR)

	networkInterfacer := proxyutiltest.NewFakeNetwork()
	itf := net.Interface{Index: 0, MTU: 0, Name: "lo", HardwareAddr: nil, Flags: 0}
	addrs := []net.Addr{
		&net.IPNet{IP: netutils.ParseIPSloppy("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy("::1/128"), Mask: net.CIDRMask(128, 128)},
	}
	networkInterfacer.AddInterfaceAddr(&itf, addrs)
	itf1 := net.Interface{Index: 1, MTU: 0, Name: "eth0", HardwareAddr: nil, Flags: 0}
	addrs1 := []net.Addr{
		&net.IPNet{IP: netutils.ParseIPSloppy(testNodeIP), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy(testNodeIPAlt), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy(testExternalIP), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy(testNodeIPv6), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: netutils.ParseIPSloppy(testNodeIPv6Alt), Mask: net.CIDRMask(64, 128)},
	}
	networkInterfacer.AddInterfaceAddr(&itf1, addrs1)

	p := &Proxier{
		exec:                &fakeexec.FakeExec{},
		svcPortMap:          make(proxy.ServicePortMap),
		serviceChanges:      proxy.NewServiceChangeTracker(newServiceInfo, ipFamily, nil, nil),
		endpointsMap:        make(proxy.EndpointsMap),
		endpointsChanges:    proxy.NewEndpointChangeTracker(testHostname, newEndpointInfo, ipFamily, nil, nil),
		nftables:            nft,
		nftablesFamily:      nftablesFamily,
		masqueradeMark:      "0x4000",
		localDetector:       detectLocal,
		hostname:            testHostname,
		serviceHealthServer: healthcheck.NewFakeServiceHealthServer(),
		nodeIP:              netutils.ParseIPSloppy(testNodeIP),
		nodePortAddresses:   proxyutil.NewNodePortAddresses(ipFamily, nil),
		networkInterfacer:   networkInterfacer,
	}
	p.setInitialized(true)
	p.syncRunner = async.NewBoundedFrequencyRunner("test-sync-runner", p.syncProxyRules, 0, time.Minute, 1)
	return p
}

// TestOverallNFTablesRules creates a variety of services and verifies that the generated
// rules are exactly as expected.
func TestOverallNFTablesRules(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)
	metrics.RegisterMetrics()

	makeServiceMap(fp,
		// create ClusterIP service
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		// create LoadBalancer service with Local traffic policy
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
				NodePort: 3001,
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: "1.2.3.4",
			}}
			svc.Spec.ExternalIPs = []string{"192.168.99.22"}
			svc.Spec.HealthCheckNodePort = 30000
		}),
		// create NodePort service
		makeTestService("ns3", "svc3", func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = "172.30.0.43"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
				NodePort: 3003,
			}}
		}),
		// create ExternalIP service
		makeTestService("ns4", "svc4", func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = "172.30.0.44"
			svc.Spec.ExternalIPs = []string{"192.168.99.33"}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       "p80",
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt32(80),
			}}
		}),
		// create LoadBalancer service with Cluster traffic policy, source ranges,
		// and session affinity
		makeTestService("ns5", "svc5", func(svc *v1.Service) {
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyCluster
			svc.Spec.ClusterIP = "172.30.0.45"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
				NodePort: 3002,
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: "5.6.7.8",
			}}
			svc.Spec.HealthCheckNodePort = 30000
			// Extra whitespace to ensure that invalid value will not result
			// in a crash, for backward compatibility.
			svc.Spec.LoadBalancerSourceRanges = []string{" 203.0.113.0/25"}

			svcSessionAffinityTimeout := int32(10800)
			svc.Spec.SessionAffinity = v1.ServiceAffinityClientIP
			svc.Spec.SessionAffinityConfig = &v1.SessionAffinityConfig{
				ClientIP: &v1.ClientIPConfig{TimeoutSeconds: &svcSessionAffinityTimeout},
			}
		}),
		// create ClusterIP service with no endpoints
		makeTestService("ns6", "svc6", func(svc *v1.Service) {
			svc.Spec.Type = "ClusterIP"
			svc.Spec.ClusterIP = "172.30.0.46"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       "p80",
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt32(80),
			}}
		}),
	)
	populateEndpointSlices(fp,
		// create ClusterIP service endpoints
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create Local LoadBalancer endpoints. Note that since we aren't setting
		// its NodeName, this endpoint will be considered non-local and ignored.
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.2"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create NodePort service endpoints
		makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.3"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create ExternalIP service endpoints
		makeTestEndpointSlice("ns4", "svc4", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.4"},
			}, {
				Addresses: []string{"10.180.0.5"},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create Cluster LoadBalancer endpoints
		makeTestEndpointSlice("ns5", "svc5", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.3"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	expected := dedent.Dedent(`
		add table ip kube-proxy { comment "rules for kube-proxy" ; }

		add chain ip kube-proxy forward
		add rule ip kube-proxy forward ct state invalid drop
		add chain ip kube-proxy mark-for-masquerade
		add rule ip kube-proxy mark-for-masquerade mark set mark or 0x4000
		add chain ip kube-proxy masquerading
		add rule ip kube-proxy masquerading mark and 0x4000 == 0 return
		add rule ip kube-proxy masquerading mark set mark xor 0x4000
		add rule ip kube-proxy masquerading masquerade fully-random
		add chain ip kube-proxy services
		add chain ip kube-proxy filter-forward { type filter hook forward priority -101 ; }
		add rule ip kube-proxy filter-forward ct state new jump endpoints-check
		add rule ip kube-proxy filter-forward jump forward
		add rule ip kube-proxy filter-forward ct state new jump firewall-check
		add chain ip kube-proxy filter-input { type filter hook input priority -101 ; }
		add rule ip kube-proxy filter-input ct state new jump endpoints-check
		add rule ip kube-proxy filter-input ct state new jump firewall-check
		add chain ip kube-proxy filter-output { type filter hook output priority -101 ; }
		add rule ip kube-proxy filter-output ct state new jump endpoints-check
		add rule ip kube-proxy filter-output ct state new jump firewall-check
		add chain ip kube-proxy nat-output { type nat hook output priority -100 ; }
		add rule ip kube-proxy nat-output jump services
		add chain ip kube-proxy nat-postrouting { type nat hook postrouting priority 100 ; }
		add rule ip kube-proxy nat-postrouting jump masquerading
		add chain ip kube-proxy nat-prerouting { type nat hook prerouting priority -100 ; }
		add rule ip kube-proxy nat-prerouting jump services

		add set ip kube-proxy firewall { type ipv4_addr . inet_proto . inet_service ; comment "destinations that are subject to LoadBalancerSourceRanges" ; }
		add set ip kube-proxy firewall-allow { type ipv4_addr . inet_proto . inet_service . ipv4_addr ; flags interval ; comment "destinations+sources that are allowed by LoadBalancerSourceRanges" ; }
		add chain ip kube-proxy firewall-check
		add chain ip kube-proxy firewall-allow-check
		add rule ip kube-proxy firewall-allow-check ip daddr . ip protocol . th dport . ip saddr @firewall-allow return
		add rule ip kube-proxy firewall-allow-check drop
		add rule ip kube-proxy firewall-check ip daddr . ip protocol . th dport @firewall jump firewall-allow-check

		add chain ip kube-proxy reject-chain { comment "helper for @no-endpoint-services / @no-endpoint-nodeports" ; }
		add rule ip kube-proxy reject-chain reject

		add map ip kube-proxy no-endpoint-services { type ipv4_addr . inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to services with no endpoints" ; }
		add map ip kube-proxy no-endpoint-nodeports { type inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to service nodeports with no endpoints" ; }

		add chain ip kube-proxy endpoints-check
		add rule ip kube-proxy endpoints-check ip daddr . ip protocol . th dport vmap @no-endpoint-services
		add rule ip kube-proxy endpoints-check fib daddr type local fib oif != "lo" ip protocol . th dport vmap @no-endpoint-nodeports

		add map ip kube-proxy service-ips { type ipv4_addr . inet_proto . inet_service : verdict ; comment "ClusterIP, ExternalIP and LoadBalancer IP traffic" ; }
		add map ip kube-proxy service-nodeports { type inet_proto . inet_service : verdict ; comment "NodePort traffic" ; }
		add rule ip kube-proxy services ip daddr . ip protocol . th dport vmap @service-ips
		add rule ip kube-proxy services fib daddr type local fib oif != "lo" ip protocol . th dport vmap @service-nodeports

		# svc1
		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80 }

		add chain ip kube-proxy endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80
		add rule ip kube-proxy endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80 ip saddr 10.180.0.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80 ip protocol tcp dnat to 10.180.0.1:80

		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }

		# svc2
		add chain ip kube-proxy service-42NFTM6N-ns2/svc2/tcp/p80
		add rule ip kube-proxy service-42NFTM6N-ns2/svc2/tcp/p80 ip daddr 172.30.0.42 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-42NFTM6N-ns2/svc2/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80 }
		add chain ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80
		add rule ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80 ip saddr 10.0.0.0/8 goto service-42NFTM6N-ns2/svc2/tcp/p80 comment "short-circuit pod traffic"
		add rule ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80 fib saddr type local jump mark-for-masquerade comment "masquerade local traffic"
		add rule ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80 fib saddr type local goto service-42NFTM6N-ns2/svc2/tcp/p80 comment "short-circuit local traffic"
		add chain ip kube-proxy endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80
		add rule ip kube-proxy endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80 ip saddr 10.180.0.2 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80 ip protocol tcp dnat to 10.180.0.2:80

		add element ip kube-proxy service-ips { 172.30.0.42 . tcp . 80 : goto service-42NFTM6N-ns2/svc2/tcp/p80 }
		add element ip kube-proxy service-ips { 192.168.99.22 . tcp . 80 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }
		add element ip kube-proxy service-ips { 1.2.3.4 . tcp . 80 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }
		add element ip kube-proxy service-nodeports { tcp . 3001 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }

		add element ip kube-proxy no-endpoint-nodeports { tcp . 3001 comment "ns2/svc2:p80" : drop }
		add element ip kube-proxy no-endpoint-services { 1.2.3.4 . tcp . 80 comment "ns2/svc2:p80" : drop }
		add element ip kube-proxy no-endpoint-services { 192.168.99.22 . tcp . 80 comment "ns2/svc2:p80" : drop }

		# svc3
		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80 }
		add chain ip kube-proxy external-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy external-4AT6LBPK-ns3/svc3/tcp/p80 jump mark-for-masquerade
		add rule ip kube-proxy external-4AT6LBPK-ns3/svc3/tcp/p80 goto service-4AT6LBPK-ns3/svc3/tcp/p80
		add chain ip kube-proxy endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80
		add rule ip kube-proxy endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80 ip saddr 10.180.0.3 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80 ip protocol tcp dnat to 10.180.0.3:80

		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }
		add element ip kube-proxy service-nodeports { tcp . 3003 : goto external-4AT6LBPK-ns3/svc3/tcp/p80 }

		# svc4
		add chain ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 ip daddr 172.30.0.44 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 numgen random mod 2 vmap { 0 : goto endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80 , 1 : goto endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80 }
		add chain ip kube-proxy external-LAUZTJTB-ns4/svc4/tcp/p80
		add rule ip kube-proxy external-LAUZTJTB-ns4/svc4/tcp/p80 jump mark-for-masquerade
		add rule ip kube-proxy external-LAUZTJTB-ns4/svc4/tcp/p80 goto service-LAUZTJTB-ns4/svc4/tcp/p80
		add chain ip kube-proxy endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80
		add rule ip kube-proxy endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80 ip saddr 10.180.0.5 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80 ip protocol tcp dnat to 10.180.0.5:80
		add chain ip kube-proxy endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80
		add rule ip kube-proxy endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80 ip saddr 10.180.0.4 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80 ip protocol tcp dnat to 10.180.0.4:80

		add element ip kube-proxy service-ips { 172.30.0.44 . tcp . 80 : goto service-LAUZTJTB-ns4/svc4/tcp/p80 }
		add element ip kube-proxy service-ips { 192.168.99.33 . tcp . 80 : goto external-LAUZTJTB-ns4/svc4/tcp/p80 }

		# svc5
		add set ip kube-proxy affinity-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 { type ipv4_addr ; flags timeout ; timeout 10800 ; }
		add chain ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80
		add rule ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80 ip daddr 172.30.0.45 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80 ip saddr @affinity-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 goto endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80
		add rule ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 }
		add chain ip kube-proxy external-HVFWP5L3-ns5/svc5/tcp/p80
		add rule ip kube-proxy external-HVFWP5L3-ns5/svc5/tcp/p80 jump mark-for-masquerade
		add rule ip kube-proxy external-HVFWP5L3-ns5/svc5/tcp/p80 goto service-HVFWP5L3-ns5/svc5/tcp/p80

		add chain ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80
		add rule ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 ip saddr 10.180.0.3 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 update @affinity-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 { ip saddr }
		add rule ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 ip protocol tcp dnat to 10.180.0.3:80

		add element ip kube-proxy service-ips { 172.30.0.45 . tcp . 80 : goto service-HVFWP5L3-ns5/svc5/tcp/p80 }
		add element ip kube-proxy service-ips { 5.6.7.8 . tcp . 80 : goto external-HVFWP5L3-ns5/svc5/tcp/p80 }
		add element ip kube-proxy service-nodeports { tcp . 3002 : goto external-HVFWP5L3-ns5/svc5/tcp/p80 }
		add element ip kube-proxy firewall { 5.6.7.8 . tcp . 80 comment "ns5/svc5:p80" }
		add element ip kube-proxy firewall-allow { 5.6.7.8 . tcp . 80 . 203.0.113.0/25 comment "ns5/svc5:p80" }

		# svc6
		add element ip kube-proxy no-endpoint-services { 172.30.0.46 . tcp . 80 comment "ns6/svc6:p80" : goto reject-chain }
		`)

	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())
}

// TestNoEndpointsReject tests that a service with no endpoints rejects connections to
// its ClusterIP, ExternalIPs, NodePort, and LoadBalancer IP.
func TestNoEndpointsReject(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)
	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcExternalIPs := "192.168.99.11"
	svcLBIP := "1.2.3.4"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Protocol: v1.ProtocolTCP,
				Port:     int32(svcPort),
				NodePort: int32(svcNodePort),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: svcLBIP,
			}}
		}),
	)
	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
		{
			name:     "pod to cluster IP with no endpoints",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   "REJECT",
		},
		{
			name:     "external to external IP with no endpoints",
			sourceIP: testExternalClient,
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   "REJECT",
		},
		{
			name:     "pod to NodePort with no endpoints",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   "REJECT",
		},
		{
			name:     "external to NodePort with no endpoints",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   "REJECT",
		},
		{
			name:     "pod to LoadBalancer IP with no endpoints",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   "REJECT",
		},
		{
			name:     "external to LoadBalancer IP with no endpoints",
			sourceIP: testExternalClient,
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   "REJECT",
		},
	})
}

// TestClusterIPGeneral tests various basic features of a ClusterIP service
func TestClusterIPGeneral(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	makeServiceMap(fp,
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "http",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{
				{
					Name:     "http",
					Port:     80,
					Protocol: v1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       443,
					Protocol:   v1.ProtocolTCP,
					TargetPort: intstr.FromInt32(8443),
				},
				{
					// Of course this should really be UDP, but if we
					// create a service with UDP ports, the Proxier will
					// try to do conntrack cleanup and we'd have to set
					// the FakeExec up to be able to deal with that...
					Name:     "dns-sctp",
					Port:     53,
					Protocol: v1.ProtocolSCTP,
				},
				{
					Name:     "dns-tcp",
					Port:     53,
					Protocol: v1.ProtocolTCP,
					// We use TargetPort on TCP but not SCTP to help
					// disambiguate the output.
					TargetPort: intstr.FromInt32(5353),
				},
			}
		}),
	)

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.1"},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("http"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{
				{
					Addresses: []string{"10.180.0.1"},
					NodeName:  pointer.String(testHostname),
				},
				{
					Addresses: []string{"10.180.2.1"},
					NodeName:  pointer.String("host2"),
				},
			}
			eps.Ports = []discovery.EndpointPort{
				{
					Name:     pointer.String("http"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				},
				{
					Name:     pointer.String("https"),
					Port:     pointer.Int32(8443),
					Protocol: &tcpProtocol,
				},
				{
					Name:     pointer.String("dns-sctp"),
					Port:     pointer.Int32(53),
					Protocol: &sctpProtocol,
				},
				{
					Name:     pointer.String("dns-tcp"),
					Port:     pointer.Int32(5353),
					Protocol: &tcpProtocol,
				},
			}
		}),
	)

	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
		{
			name:     "simple clusterIP",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80",
			masq:     false,
		},
		{
			name:     "hairpin to cluster IP",
			sourceIP: "10.180.0.1",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80",
			masq:     true,
		},
		{
			name:     "clusterIP with multiple endpoints",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.42",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.2.1:80",
			masq:     false,
		},
		{
			name:     "clusterIP with TargetPort",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.42",
			destPort: 443,
			output:   "10.180.0.1:8443, 10.180.2.1:8443",
			masq:     false,
		},
		{
			name:     "clusterIP with TCP and SCTP on same port (TCP)",
			sourceIP: "10.180.0.2",
			protocol: v1.ProtocolTCP,
			destIP:   "172.30.0.42",
			destPort: 53,
			output:   "10.180.0.1:5353, 10.180.2.1:5353",
			masq:     false,
		},
		{
			name:     "clusterIP with TCP and SCTP on same port (SCTP)",
			sourceIP: "10.180.0.2",
			protocol: v1.ProtocolSCTP,
			destIP:   "172.30.0.42",
			destPort: 53,
			output:   "10.180.0.1:53, 10.180.2.1:53",
			masq:     false,
		},
		{
			name:     "TCP-only port does not match UDP traffic",
			sourceIP: "10.180.0.2",
			protocol: v1.ProtocolUDP,
			destIP:   "172.30.0.42",
			destPort: 80,
			output:   "",
		},
		{
			name:     "svc1 does not accept svc2's ports",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.41",
			destPort: 443,
			output:   "",
		},
	})
}

func TestLoadBalancer(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)
	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcLBIP1 := "1.2.3.4"
	svcLBIP2 := "5.6.7.8"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
				{IP: svcLBIP1},
				{IP: svcLBIP2},
			}
			svc.Spec.LoadBalancerSourceRanges = []string{
				"192.168.0.0/24",

				// Regression test that excess whitespace gets ignored
				" 203.0.113.0/25",
			}
		}),
	)

	epIP := "10.180.0.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
		{
			name:     "pod to cluster IP",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     false,
		},
		{
			name:     "external to nodePort",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "nodePort bypasses LoadBalancerSourceRanges",
			sourceIP: testExternalClientBlocked,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "accepted external to LB1",
			sourceIP: testExternalClient,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "accepted external to LB2",
			sourceIP: testExternalClient,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "blocked external to LB1",
			sourceIP: testExternalClientBlocked,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "blocked external to LB2",
			sourceIP: testExternalClientBlocked,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "pod to LB1 (blocked by LoadBalancerSourceRanges)",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "pod to LB2 (blocked by LoadBalancerSourceRanges)",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "node to LB1 (allowed by LoadBalancerSourceRanges)",
			sourceIP: testNodeIP,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "node to LB2 (allowed by LoadBalancerSourceRanges)",
			sourceIP: testNodeIP,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},

		// The LB rules assume that when you connect from a node to a LB IP, that
		// something external to kube-proxy will cause the connection to be
		// SNATted to the LB IP, so if the LoadBalancerSourceRanges include the
		// node IP, then we add a rule allowing traffic from the LB IP as well...
		{
			name:     "same node to LB1, SNATted to LB1 (implicitly allowed)",
			sourceIP: svcLBIP1,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "same node to LB2, SNATted to LB2 (implicitly allowed)",
			sourceIP: svcLBIP2,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
	})
}

// TestNodePorts tests NodePort services under various combinations of the
// --nodeport-addresses and --localhost-nodeports flags.
func TestNodePorts(t *testing.T) {
	testCases := []struct {
		name string

		family            v1.IPFamily
		nodePortAddresses []string

		// allowAltNodeIP is true if we expect NodePort traffic on the alternate
		// node IP to be accepted
		allowAltNodeIP bool

		// expectFirewall is true if we expect firewall to be filled in with
		// an anti-martian-packet rule
		expectFirewall bool
	}{
		{
			name: "ipv4",

			family:            v1.IPv4Protocol,
			nodePortAddresses: nil,

			allowAltNodeIP: true,
			expectFirewall: true,
		},
		{
			name: "ipv4, multiple nodeport-addresses",

			family:            v1.IPv4Protocol,
			nodePortAddresses: []string{"192.168.0.0/24", "192.168.1.0/24", "2001:db8::/64"},

			allowAltNodeIP: true,
			expectFirewall: false,
		},
		{
			name: "ipv6",

			family:            v1.IPv6Protocol,
			nodePortAddresses: nil,

			allowAltNodeIP: true,
			expectFirewall: false,
		},
		{
			name: "ipv6, multiple nodeport-addresses",

			family:            v1.IPv6Protocol,
			nodePortAddresses: []string{"192.168.0.0/24", "192.168.1.0/24", "2001:db8::/64"},

			allowAltNodeIP: false,
			expectFirewall: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var nft *nftables.Fake
			var fp *Proxier
			var svcIP, epIP1, epIP2 string
			if tc.family == v1.IPv4Protocol {
				nft = nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
				fp = NewFakeProxier(nft, v1.IPv4Protocol)
				svcIP = "172.30.0.41"
				epIP1 = "10.180.0.1"
				epIP2 = "10.180.2.1"
			} else {
				nft = nftables.NewFake(nftables.IPv6Family, kubeProxyTable)
				fp = NewFakeProxier(nft, v1.IPv6Protocol)
				svcIP = "fd00:172:30::41"
				epIP1 = "fd00:10:180::1"
				epIP2 = "fd00:10:180::2:1"
			}
			if tc.nodePortAddresses != nil {
				fp.nodePortAddresses = proxyutil.NewNodePortAddresses(tc.family, tc.nodePortAddresses)
			}

			makeServiceMap(fp,
				makeTestService("ns1", "svc1", func(svc *v1.Service) {
					svc.Spec.Type = v1.ServiceTypeNodePort
					svc.Spec.ClusterIP = svcIP
					svc.Spec.Ports = []v1.ServicePort{{
						Name:     "p80",
						Port:     80,
						Protocol: v1.ProtocolTCP,
						NodePort: 3001,
					}}
				}),
			)

			populateEndpointSlices(fp,
				makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
					if tc.family == v1.IPv4Protocol {
						eps.AddressType = discovery.AddressTypeIPv4
					} else {
						eps.AddressType = discovery.AddressTypeIPv6
					}
					eps.Endpoints = []discovery.Endpoint{{
						Addresses: []string{epIP1},
						NodeName:  nil,
					}, {
						Addresses: []string{epIP2},
						NodeName:  pointer.String(testHostname),
					}}
					eps.Ports = []discovery.EndpointPort{{
						Name:     pointer.String("p80"),
						Port:     pointer.Int32(80),
						Protocol: &tcpProtocol,
					}}
				}),
			)

			fp.syncProxyRules()

			var podIP, externalClientIP, nodeIP, altNodeIP string
			if tc.family == v1.IPv4Protocol {
				podIP = "10.0.0.2"
				externalClientIP = testExternalClient
				nodeIP = testNodeIP
				altNodeIP = testNodeIPAlt
			} else {
				podIP = "fd00:10::2"
				externalClientIP = "2600:5200::1"
				nodeIP = testNodeIPv6
				altNodeIP = testNodeIPv6Alt
			}
			output := net.JoinHostPort(epIP1, "80") + ", " + net.JoinHostPort(epIP2, "80")

			// Basic tests are the same for all cases
			runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
				{
					name:     "pod to cluster IP",
					sourceIP: podIP,
					destIP:   svcIP,
					destPort: 80,
					output:   output,
					masq:     false,
				},
				{
					name:     "external to nodePort",
					sourceIP: externalClientIP,
					destIP:   nodeIP,
					destPort: 3001,
					output:   output,
					masq:     true,
				},
				{
					name:     "node to nodePort",
					sourceIP: nodeIP,
					destIP:   nodeIP,
					destPort: 3001,
					output:   output,
					masq:     true,
				},
			})

			// NodePort on altNodeIP should be allowed, unless
			// nodePortAddressess excludes altNodeIP
			if tc.allowAltNodeIP {
				runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
					{
						name:     "external to nodePort on secondary IP",
						sourceIP: externalClientIP,
						destIP:   altNodeIP,
						destPort: 3001,
						output:   output,
						masq:     true,
					},
				})
			} else {
				runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
					{
						name:     "secondary nodeIP ignores NodePorts",
						sourceIP: externalClientIP,
						destIP:   altNodeIP,
						destPort: 3001,
						output:   "",
					},
				})
			}
		})
	}
}

func TestDropInvalidRule(t *testing.T) {
	for _, tcpLiberal := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcpLiberal %t", tcpLiberal), func(t *testing.T) {
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.conntrackTCPLiberal = tcpLiberal
			fp.syncProxyRules()

			var expected string
			if !tcpLiberal {
				expected = "ct state invalid drop"
			}

			assertNFTablesChainEqual(t, getLine(), nft, kubeForwardChain, expected)
		})
	}
}

// TestExternalTrafficPolicyLocal tests that traffic to externally-facing IPs does not get
// masqueraded when using Local traffic policy. For traffic from external sources, that
// means it can also only be routed to local endpoints, but for traffic from internal
// sources, it gets routed to all endpoints.
func TestExternalTrafficPolicyLocal(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcHealthCheckNodePort := 30000
	svcExternalIPs := "192.168.99.11"
	svcLBIP := "1.2.3.4"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       svcPortName.Port,
				Port:       int32(svcPort),
				Protocol:   v1.ProtocolTCP,
				NodePort:   int32(svcNodePort),
				TargetPort: intstr.FromInt32(int32(svcPort)),
			}}
			svc.Spec.HealthCheckNodePort = int32(svcHealthCheckNodePort)
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: svcLBIP,
			}}
		}),
	)

	epIP1 := "10.180.0.1"
	epIP2 := "10.180.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
		{
			name:     "pod to cluster IP hits both endpoints, unmasqueraded",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "pod to external IP hits both endpoints, unmasqueraded",
			sourceIP: "10.0.0.2",
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to external IP hits only local endpoint, unmasqueraded",
			sourceIP: testExternalClient,
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "pod to LB IP hits only both endpoints, unmasqueraded",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to LB IP hits only local endpoint, unmasqueraded",
			sourceIP: testExternalClient,
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "pod to NodePort hits both endpoints, unmasqueraded",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to NodePort hits only local endpoint, unmasqueraded",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
	})
}

// TestExternalTrafficPolicyCluster tests that traffic to an externally-facing IP gets
// masqueraded when using Cluster traffic policy.
func TestExternalTrafficPolicyCluster(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcExternalIPs := "192.168.99.11"
	svcLBIP := "1.2.3.4"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       svcPortName.Port,
				Port:       int32(svcPort),
				Protocol:   v1.ProtocolTCP,
				NodePort:   int32(svcNodePort),
				TargetPort: intstr.FromInt32(int32(svcPort)),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: svcLBIP,
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyCluster
		}),
	)

	epIP1 := "10.180.0.1"
	epIP2 := "10.180.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), nft, testNodeIPs, []packetFlowTest{
		{
			name:     "pod to cluster IP hits both endpoints, unmasqueraded",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "pod to external IP hits both endpoints, masqueraded",
			sourceIP: "10.0.0.2",
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
		{
			name:     "external to external IP hits both endpoints, masqueraded",
			sourceIP: testExternalClient,
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
		{
			name:     "pod to LB IP hits both endpoints, masqueraded",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
		{
			name:     "external to LB IP hits both endpoints, masqueraded",
			sourceIP: testExternalClient,
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
		{
			name:     "pod to NodePort hits both endpoints, masqueraded",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
		{
			name:     "external to NodePort hits both endpoints, masqueraded",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
	})
}

func makeTestService(namespace, name string, svcFunc func(*v1.Service)) *v1.Service {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{},
		},
		Spec:   v1.ServiceSpec{},
		Status: v1.ServiceStatus{},
	}
	svcFunc(svc)
	return svc
}

func addTestPort(array []v1.ServicePort, name string, protocol v1.Protocol, port, nodeport int32, targetPort int) []v1.ServicePort {
	svcPort := v1.ServicePort{
		Name:       name,
		Protocol:   protocol,
		Port:       port,
		NodePort:   nodeport,
		TargetPort: intstr.FromInt32(int32(targetPort)),
	}
	return append(array, svcPort)
}

func TestBuildServiceMapAddRemove(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	services := []*v1.Service{
		makeTestService("somewhere-else", "cluster-ip", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.55.4"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "UDP", 1235, 5321, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "sctpport", "SCTP", 1236, 6321, 0)
		}),
		makeTestService("somewhere-else", "node-port", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeNodePort
			svc.Spec.ClusterIP = "172.30.55.10"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "blahblah", "UDP", 345, 678, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "moreblahblah", "TCP", 344, 677, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "muchmoreblah", "SCTP", 343, 676, 0)
		}),
		makeTestService("somewhere", "load-balancer", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = "172.30.55.11"
			svc.Spec.LoadBalancerIP = "1.2.3.4"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "foobar", "UDP", 8675, 30061, 7000)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "baz", "UDP", 8676, 30062, 7001)
			svc.Status.LoadBalancer = v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			}
		}),
		makeTestService("somewhere", "only-local-load-balancer", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = "172.30.55.12"
			svc.Spec.LoadBalancerIP = "5.6.7.8"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "foobar2", "UDP", 8677, 30063, 7002)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "baz", "UDP", 8678, 30064, 7003)
			svc.Status.LoadBalancer = v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "5.6.7.8"},
				},
			}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
			svc.Spec.HealthCheckNodePort = 345
		}),
	}

	for i := range services {
		fp.OnServiceAdd(services[i])
	}
	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 10 {
		t.Errorf("expected service map length 10, got %v", fp.svcPortMap)
	}

	if len(result.DeletedUDPClusterIPs) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}

	// The only-local-loadbalancer ones get added
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 1 {
		t.Errorf("expected 1 healthcheck port, got %v", healthCheckNodePorts)
	} else {
		nsn := makeNSN("somewhere", "only-local-load-balancer")
		if port, found := healthCheckNodePorts[nsn]; !found || port != 345 {
			t.Errorf("expected healthcheck port [%q]=345: got %v", nsn, healthCheckNodePorts)
		}
	}

	// Remove some stuff
	// oneService is a modification of services[0] with removed first port.
	oneService := makeTestService("somewhere-else", "cluster-ip", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeClusterIP
		svc.Spec.ClusterIP = "172.30.55.4"
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "UDP", 1235, 5321, 0)
	})

	fp.OnServiceUpdate(services[0], oneService)
	fp.OnServiceDelete(services[1])
	fp.OnServiceDelete(services[2])
	fp.OnServiceDelete(services[3])

	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 1 {
		t.Errorf("expected service map length 1, got %v", fp.svcPortMap)
	}

	// All services but one were deleted. While you'd expect only the ClusterIPs
	// from the three deleted services here, we still have the ClusterIP for
	// the not-deleted service, because one of it's ServicePorts was deleted.
	expectedStaleUDPServices := []string{"172.30.55.10", "172.30.55.4", "172.30.55.11", "172.30.55.12"}
	if len(result.DeletedUDPClusterIPs) != len(expectedStaleUDPServices) {
		t.Errorf("expected stale UDP services length %d, got %v", len(expectedStaleUDPServices), result.DeletedUDPClusterIPs.UnsortedList())
	}
	for _, ip := range expectedStaleUDPServices {
		if !result.DeletedUDPClusterIPs.Has(ip) {
			t.Errorf("expected stale UDP service service %s", ip)
		}
	}

	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected 0 healthcheck ports, got %v", healthCheckNodePorts)
	}
}

func TestBuildServiceMapServiceHeadless(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	makeServiceMap(fp,
		makeTestService("somewhere-else", "headless", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = v1.ClusterIPNone
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "rpc", "UDP", 1234, 0, 0)
		}),
		makeTestService("somewhere-else", "headless-without-port", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = v1.ClusterIPNone
		}),
	)

	// Headless service should be ignored
	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 0 {
		t.Errorf("expected service map length 0, got %d", len(fp.svcPortMap))
	}

	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}

	// No proxied services, so no healthchecks
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %d", len(healthCheckNodePorts))
	}
}

func TestBuildServiceMapServiceTypeExternalName(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	makeServiceMap(fp,
		makeTestService("somewhere-else", "external-name", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeExternalName
			svc.Spec.ClusterIP = "172.30.55.4" // Should be ignored
			svc.Spec.ExternalName = "foo2.bar.com"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "blah", "UDP", 1235, 5321, 0)
		}),
	)

	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 0 {
		t.Errorf("expected service map length 0, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", result.DeletedUDPClusterIPs)
	}
	// No proxied services, so no healthchecks
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %v", healthCheckNodePorts)
	}
}

func TestBuildServiceMapServiceUpdate(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	servicev1 := makeTestService("somewhere", "some-service", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeClusterIP
		svc.Spec.ClusterIP = "172.30.55.4"
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 0)
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "TCP", 1235, 5321, 0)
	})
	servicev2 := makeTestService("somewhere", "some-service", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeLoadBalancer
		svc.Spec.ClusterIP = "172.30.55.4"
		svc.Spec.LoadBalancerIP = "1.2.3.4"
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 7002)
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "TCP", 1235, 5321, 7003)
		svc.Status.LoadBalancer = v1.LoadBalancerStatus{
			Ingress: []v1.LoadBalancerIngress{
				{IP: "1.2.3.4"},
			},
		}
		svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		svc.Spec.HealthCheckNodePort = 345
	})

	fp.OnServiceAdd(servicev1)

	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %v", healthCheckNodePorts)
	}

	// Change service to load-balancer
	fp.OnServiceUpdate(servicev1, servicev2)
	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", result.DeletedUDPClusterIPs.UnsortedList())
	}
	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 1 {
		t.Errorf("expected healthcheck ports length 1, got %v", healthCheckNodePorts)
	}

	// No change; make sure the service map stays the same and there are
	// no health-check changes
	fp.OnServiceUpdate(servicev2, servicev2)
	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", result.DeletedUDPClusterIPs.UnsortedList())
	}
	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 1 {
		t.Errorf("expected healthcheck ports length 1, got %v", healthCheckNodePorts)
	}

	// And back to ClusterIP
	fp.OnServiceUpdate(servicev2, servicev1)
	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}
	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %v", healthCheckNodePorts)
	}
}

func populateEndpointSlices(proxier *Proxier, allEndpointSlices ...*discovery.EndpointSlice) {
	for i := range allEndpointSlices {
		proxier.OnEndpointSliceAdd(allEndpointSlices[i])
	}
}

func makeTestEndpointSlice(namespace, name string, sliceNum int, epsFunc func(*discovery.EndpointSlice)) *discovery.EndpointSlice {
	eps := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", name, sliceNum),
			Namespace: namespace,
			Labels:    map[string]string{discovery.LabelServiceName: name},
		},
	}
	epsFunc(eps)
	return eps
}

func makeNSN(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func makeServicePortName(ns, name, port string, protocol v1.Protocol) proxy.ServicePortName {
	return proxy.ServicePortName{
		NamespacedName: makeNSN(ns, name),
		Port:           port,
		Protocol:       protocol,
	}
}

func makeServiceMap(proxier *Proxier, allServices ...*v1.Service) {
	for i := range allServices {
		proxier.OnServiceAdd(allServices[i])
	}

	proxier.mu.Lock()
	defer proxier.mu.Unlock()
	proxier.servicesSynced = true
}

func compareEndpointsMapsExceptChainName(t *testing.T, tci int, newMap proxy.EndpointsMap, expected map[proxy.ServicePortName][]*endpointsInfo) {
	if len(newMap) != len(expected) {
		t.Errorf("[%d] expected %d results, got %d: %v", tci, len(expected), len(newMap), newMap)
	}
	for x := range expected {
		if len(newMap[x]) != len(expected[x]) {
			t.Errorf("[%d] expected %d endpoints for %v, got %d", tci, len(expected[x]), x, len(newMap[x]))
		} else {
			for i := range expected[x] {
				newEp, ok := newMap[x][i].(*endpointsInfo)
				if !ok {
					t.Errorf("Failed to cast endpointsInfo")
					continue
				}
				if newEp.Endpoint != expected[x][i].Endpoint ||
					newEp.IsLocal != expected[x][i].IsLocal {
					t.Errorf("[%d] expected new[%v][%d] to be %v, got %v", tci, x, i, expected[x][i], newEp)
				}
			}
		}
	}
}

func TestUpdateEndpointsMap(t *testing.T) {
	var nodeName = testHostname
	udpProtocol := v1.ProtocolUDP

	emptyEndpointSlices := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, func(*discovery.EndpointSlice) {}),
	}
	subset1 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}}
	}
	subset2 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.2"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	namedPortLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
					NodeName:  &nodeName,
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11"),
					Port:     pointer.Int32(11),
					Protocol: &udpProtocol,
				}}
			}),
	}
	namedPort := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
	}
	namedPortRenamed := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11-2"),
					Port:     pointer.Int32(11),
					Protocol: &udpProtocol,
				}}
			}),
	}
	namedPortRenumbered := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11"),
					Port:     pointer.Int32(22),
					Protocol: &udpProtocol,
				}}
			}),
	}
	namedPortsLocalNoLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
				}, {
					Addresses: []string{"10.1.1.2"},
					NodeName:  &nodeName,
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11"),
					Port:     pointer.Int32(11),
					Protocol: &udpProtocol,
				}, {
					Name:     pointer.String("p12"),
					Port:     pointer.Int32(12),
					Protocol: &udpProtocol,
				}}
			}),
	}
	multipleSubsets := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
		makeTestEndpointSlice("ns1", "ep1", 2, subset2),
	}
	subsetLocal := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.2"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	multipleSubsetsWithLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
		makeTestEndpointSlice("ns1", "ep1", 2, subsetLocal),
	}
	subsetMultiplePortsLocal := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	subset3 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.3"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p13"),
			Port:     pointer.Int32(13),
			Protocol: &udpProtocol,
		}}
	}
	multipleSubsetsMultiplePortsLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subsetMultiplePortsLocal),
		makeTestEndpointSlice("ns1", "ep1", 2, subset3),
	}
	subsetMultipleIPsPorts1 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
		}, {
			Addresses: []string{"10.1.1.2"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	subsetMultipleIPsPorts2 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.3"},
		}, {
			Addresses: []string{"10.1.1.4"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p13"),
			Port:     pointer.Int32(13),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p14"),
			Port:     pointer.Int32(14),
			Protocol: &udpProtocol,
		}}
	}
	subsetMultipleIPsPorts3 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.2.2.1"},
		}, {
			Addresses: []string{"10.2.2.2"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p21"),
			Port:     pointer.Int32(21),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p22"),
			Port:     pointer.Int32(22),
			Protocol: &udpProtocol,
		}}
	}
	multipleSubsetsIPsPorts := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subsetMultipleIPsPorts1),
		makeTestEndpointSlice("ns1", "ep1", 2, subsetMultipleIPsPorts2),
		makeTestEndpointSlice("ns2", "ep2", 1, subsetMultipleIPsPorts3),
	}
	complexSubset1 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.2.2.2"},
			NodeName:  &nodeName,
		}, {
			Addresses: []string{"10.2.2.22"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p22"),
			Port:     pointer.Int32(22),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset2 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.2.2.3"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p23"),
			Port:     pointer.Int32(23),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset3 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.4.4"},
			NodeName:  &nodeName,
		}, {
			Addresses: []string{"10.4.4.5"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p44"),
			Port:     pointer.Int32(44),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset4 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.4.6"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p45"),
			Port:     pointer.Int32(45),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset5 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
		}, {
			Addresses: []string{"10.1.1.11"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset6 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.2"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p122"),
			Port:     pointer.Int32(122),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset7 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.3.3.3"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p33"),
			Port:     pointer.Int32(33),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset8 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.4.4"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p44"),
			Port:     pointer.Int32(44),
			Protocol: &udpProtocol,
		}}
	}
	complexBefore := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
		nil,
		makeTestEndpointSlice("ns2", "ep2", 1, complexSubset1),
		makeTestEndpointSlice("ns2", "ep2", 2, complexSubset2),
		nil,
		makeTestEndpointSlice("ns4", "ep4", 1, complexSubset3),
		makeTestEndpointSlice("ns4", "ep4", 2, complexSubset4),
	}
	complexAfter := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, complexSubset5),
		makeTestEndpointSlice("ns1", "ep1", 2, complexSubset6),
		nil,
		nil,
		makeTestEndpointSlice("ns3", "ep3", 1, complexSubset7),
		makeTestEndpointSlice("ns4", "ep4", 1, complexSubset8),
		nil,
	}

	testCases := []struct {
		// previousEndpoints and currentEndpoints are used to call appropriate
		// handlers OnEndpoints* (based on whether corresponding values are nil
		// or non-nil) and must be of equal length.
		name                           string
		previousEndpoints              []*discovery.EndpointSlice
		currentEndpoints               []*discovery.EndpointSlice
		oldEndpoints                   map[proxy.ServicePortName][]*endpointsInfo
		expectedResult                 map[proxy.ServicePortName][]*endpointsInfo
		expectedDeletedUDPEndpoints    []proxy.ServiceEndpoint
		expectedNewlyActiveUDPServices map[proxy.ServicePortName]bool
		expectedLocalEndpoints         map[types.NamespacedName]int
	}{{
		// Case[0]: nothing
		name:                           "nothing",
		oldEndpoints:                   map[proxy.ServicePortName][]*endpointsInfo{},
		expectedResult:                 map[proxy.ServicePortName][]*endpointsInfo{},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[1]: no change, named port, local
		name:              "no change, named port, local",
		previousEndpoints: namedPortLocal,
		currentEndpoints:  namedPortLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[2]: no change, multiple subsets
		name:              "no change, multiple subsets",
		previousEndpoints: multipleSubsets,
		currentEndpoints:  multipleSubsets,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[3]: no change, multiple subsets, multiple ports, local
		name:              "no change, multiple subsets, multiple ports, local",
		previousEndpoints: multipleSubsetsMultiplePortsLocal,
		currentEndpoints:  multipleSubsetsMultiplePortsLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[4]: no change, multiple endpoints, subsets, IPs, and ports
		name:              "no change, multiple endpoints, subsets, IPs, and ports",
		previousEndpoints: multipleSubsetsIPsPorts,
		currentEndpoints:  multipleSubsetsIPsPorts,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:13", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p14", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:14", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:14", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p21", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:21", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:21", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:22", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:13", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p14", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:14", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:14", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p21", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:21", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:21", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:22", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 2,
			makeNSN("ns2", "ep2"): 1,
		},
	}, {
		// Case[5]: add an Endpoints
		name:              "add an Endpoints",
		previousEndpoints: []*discovery.EndpointSlice{nil},
		currentEndpoints:  namedPortLocal,
		oldEndpoints:      map[proxy.ServicePortName][]*endpointsInfo{},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[6]: remove an Endpoints
		name:              "remove an Endpoints",
		previousEndpoints: namedPortLocal,
		currentEndpoints:  []*discovery.EndpointSlice{nil},
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.1:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[7]: add an IP and port
		name:              "add an IP and port",
		previousEndpoints: namedPort,
		currentEndpoints:  namedPortsLocalNoLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[8]: remove an IP and port
		name:              "remove an IP and port",
		previousEndpoints: namedPortsLocalNoLocal,
		currentEndpoints:  namedPort,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.2:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.1.1.1:12",
			ServicePortName: makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.1.1.2:12",
			ServicePortName: makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[9]: add a subset
		name:              "add a subset",
		previousEndpoints: []*discovery.EndpointSlice{namedPort[0], nil},
		currentEndpoints:  multipleSubsetsWithLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[10]: remove a subset
		name:              "remove a subset",
		previousEndpoints: multipleSubsets,
		currentEndpoints:  []*discovery.EndpointSlice{namedPort[0], nil},
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.2:12",
			ServicePortName: makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[11]: rename a port
		name:              "rename a port",
		previousEndpoints: namedPort,
		currentEndpoints:  namedPortRenamed,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11-2", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.1:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p11-2", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{},
	}, {
		// Case[12]: renumber a port
		name:              "renumber a port",
		previousEndpoints: namedPort,
		currentEndpoints:  namedPortRenumbered,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:22", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.1:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[13]: complex add and remove
		name:              "complex add and remove",
		previousEndpoints: complexBefore,
		currentEndpoints:  complexAfter,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.22:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p23", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.3:23", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns4", "ep4", "p44", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.4:44", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.5:44", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns4", "ep4", "p45", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.6:45", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.11:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p122", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:122", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns3", "ep3", "p33", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.3.3.3:33", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns4", "ep4", "p44", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.4:44", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.2.2.2:22",
			ServicePortName: makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.2.2.22:22",
			ServicePortName: makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.2.2.3:23",
			ServicePortName: makeServicePortName("ns2", "ep2", "p23", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.4.4.5:44",
			ServicePortName: makeServicePortName("ns4", "ep4", "p44", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.4.4.6:45",
			ServicePortName: makeServicePortName("ns4", "ep4", "p45", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP):  true,
			makeServicePortName("ns1", "ep1", "p122", v1.ProtocolUDP): true,
			makeServicePortName("ns3", "ep3", "p33", v1.ProtocolUDP):  true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns4", "ep4"): 1,
		},
	}, {
		// Case[14]: change from 0 endpoint address to 1 unnamed port
		name:              "change from 0 endpoint address to 1 unnamed port",
		previousEndpoints: emptyEndpointSlices,
		currentEndpoints:  namedPort,
		oldEndpoints:      map[proxy.ServicePortName][]*endpointsInfo{},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{},
	},
	}

	for tci, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.hostname = nodeName

			// First check that after adding all previous versions of endpoints,
			// the fp.oldEndpoints is as we expect.
			for i := range tc.previousEndpoints {
				if tc.previousEndpoints[i] != nil {
					fp.OnEndpointSliceAdd(tc.previousEndpoints[i])
				}
			}
			fp.endpointsMap.Update(fp.endpointsChanges)
			compareEndpointsMapsExceptChainName(t, tci, fp.endpointsMap, tc.oldEndpoints)

			// Now let's call appropriate handlers to get to state we want to be.
			if len(tc.previousEndpoints) != len(tc.currentEndpoints) {
				t.Fatalf("[%d] different lengths of previous and current endpoints", tci)
			}

			for i := range tc.previousEndpoints {
				prev, curr := tc.previousEndpoints[i], tc.currentEndpoints[i]
				switch {
				case prev == nil:
					fp.OnEndpointSliceAdd(curr)
				case curr == nil:
					fp.OnEndpointSliceDelete(prev)
				default:
					fp.OnEndpointSliceUpdate(prev, curr)
				}
			}
			result := fp.endpointsMap.Update(fp.endpointsChanges)
			newMap := fp.endpointsMap
			compareEndpointsMapsExceptChainName(t, tci, newMap, tc.expectedResult)
			if len(result.DeletedUDPEndpoints) != len(tc.expectedDeletedUDPEndpoints) {
				t.Errorf("[%d] expected %d staleEndpoints, got %d: %v", tci, len(tc.expectedDeletedUDPEndpoints), len(result.DeletedUDPEndpoints), result.DeletedUDPEndpoints)
			}
			for _, x := range tc.expectedDeletedUDPEndpoints {
				found := false
				for _, stale := range result.DeletedUDPEndpoints {
					if stale == x {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("[%d] expected staleEndpoints[%v], but didn't find it: %v", tci, x, result.DeletedUDPEndpoints)
				}
			}
			if len(result.NewlyActiveUDPServices) != len(tc.expectedNewlyActiveUDPServices) {
				t.Errorf("[%d] expected %d staleServiceNames, got %d: %v", tci, len(tc.expectedNewlyActiveUDPServices), len(result.NewlyActiveUDPServices), result.NewlyActiveUDPServices)
			}
			for svcName := range tc.expectedNewlyActiveUDPServices {
				found := false
				for _, stale := range result.NewlyActiveUDPServices {
					if stale == svcName {
						found = true
					}
				}
				if !found {
					t.Errorf("[%d] expected staleServiceNames[%v], but didn't find it: %v", tci, svcName, result.NewlyActiveUDPServices)
				}
			}
			localReadyEndpoints := fp.endpointsMap.LocalReadyEndpoints()
			if !reflect.DeepEqual(localReadyEndpoints, tc.expectedLocalEndpoints) {
				t.Errorf("[%d] expected local endpoints %v, got %v", tci, tc.expectedLocalEndpoints, localReadyEndpoints)
			}
		})
	}
}

// TestHealthCheckNodePortWhenTerminating tests that health check node ports are not enabled when all local endpoints are terminating
func TestHealthCheckNodePortWhenTerminating(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)
	fp.OnServiceSynced()
	fp.OnEndpointSlicesSynced()

	serviceName := "svc1"
	namespaceName := "ns1"

	fp.OnServiceAdd(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespaceName},
		Spec: v1.ServiceSpec{
			ClusterIP: "172.30.1.1",
			Selector:  map[string]string{"foo": "bar"},
			Ports:     []v1.ServicePort{{Name: "", TargetPort: intstr.FromInt32(80), Protocol: v1.ProtocolTCP}},
		},
	})

	endpointSlice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-1", serviceName),
			Namespace: namespaceName,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{{
			Name:     pointer.String(""),
			Port:     pointer.Int32(80),
			Protocol: &tcpProtocol,
		}},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{{
			Addresses:  []string{"10.0.1.1"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
			NodeName:   pointer.String(testHostname),
		}, {
			Addresses:  []string{"10.0.1.2"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
			NodeName:   pointer.String(testHostname),
		}, {
			Addresses:  []string{"10.0.1.3"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
			NodeName:   pointer.String(testHostname),
		}, { // not ready endpoints should be ignored
			Addresses:  []string{"10.0.1.4"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(false)},
			NodeName:   pointer.String(testHostname),
		}},
	}

	fp.OnEndpointSliceAdd(endpointSlice)
	_ = fp.endpointsMap.Update(fp.endpointsChanges)
	localReadyEndpoints := fp.endpointsMap.LocalReadyEndpoints()
	if len(localReadyEndpoints) != 1 {
		t.Errorf("unexpected number of local ready endpoints, expected 1 but got: %d", len(localReadyEndpoints))
	}

	// set all endpoints to terminating
	endpointSliceTerminating := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-1", serviceName),
			Namespace: namespaceName,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{{
			Name:     pointer.String(""),
			Port:     pointer.Int32(80),
			Protocol: &tcpProtocol,
		}},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{{
			Addresses: []string{"10.0.1.1"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(true),
				Terminating: pointer.Bool(false),
			},
			NodeName: pointer.String(testHostname),
		}, {
			Addresses: []string{"10.0.1.2"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(true),
				Terminating: pointer.Bool(true),
			},
			NodeName: pointer.String(testHostname),
		}, {
			Addresses: []string{"10.0.1.3"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(true),
				Terminating: pointer.Bool(true),
			},
			NodeName: pointer.String(testHostname),
		}, { // not ready endpoints should be ignored
			Addresses: []string{"10.0.1.4"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(false),
				Terminating: pointer.Bool(true),
			},
			NodeName: pointer.String(testHostname),
		}},
	}

	fp.OnEndpointSliceUpdate(endpointSlice, endpointSliceTerminating)
	_ = fp.endpointsMap.Update(fp.endpointsChanges)
	localReadyEndpoints = fp.endpointsMap.LocalReadyEndpoints()
	if len(localReadyEndpoints) != 0 {
		t.Errorf("unexpected number of local ready endpoints, expected 0 but got: %d", len(localReadyEndpoints))
	}
}

func TestProxierDeleteNodePortStaleUDP(t *testing.T) {
	fcmd := fakeexec.FakeCmd{}
	fexec := &fakeexec.FakeExec{
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
	}
	execFunc := func(cmd string, args ...string) exec.Cmd {
		return fakeexec.InitFakeCmd(&fcmd, cmd, args...)
	}
	cmdOutput := "1 flow entries have been deleted"
	cmdFunc := func() ([]byte, []byte, error) { return []byte(cmdOutput), nil, nil }

	// Delete ClusterIP entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)
	// Delete ExternalIP entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)
	// Delete LoadBalancerIP entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)
	// Delete NodePort entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)

	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)
	fp.exec = fexec

	svcIP := "172.30.0.41"
	extIP := "192.168.99.11"
	lbIngressIP := "1.2.3.4"
	svcPort := 80
	nodePort := 31201
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolUDP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{extIP}
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolUDP,
				NodePort: int32(nodePort),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: lbIngressIP,
			}}
		}),
	)

	fp.syncProxyRules()
	if fexec.CommandCalls != 0 {
		t.Fatalf("Created service without endpoints must not clear conntrack entries")
	}

	epIP := "10.180.0.1"
	udpProtocol := v1.ProtocolUDP
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
				Conditions: discovery.EndpointConditions{
					Serving: pointer.Bool(false),
				},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &udpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	if fexec.CommandCalls != 0 {
		t.Fatalf("Updated UDP service with not ready endpoints must not clear UDP entries")
	}

	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
				Conditions: discovery.EndpointConditions{
					Serving: pointer.Bool(true),
				},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &udpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	if fexec.CommandCalls != 4 {
		t.Fatalf("Updated UDP service with new endpoints must clear UDP entries 4 times: ClusterIP, NodePort, ExternalIP and LB")
	}

	// the order is not guaranteed so we have to compare the strings in any order
	expectedCommands := []string{
		// Delete ClusterIP Conntrack entries
		fmt.Sprintf("conntrack -D --orig-dst %s -p %s", svcIP, strings.ToLower(string((v1.ProtocolUDP)))),
		// Delete ExternalIP Conntrack entries
		fmt.Sprintf("conntrack -D --orig-dst %s -p %s", extIP, strings.ToLower(string((v1.ProtocolUDP)))),
		// Delete LoadBalancerIP Conntrack entries
		fmt.Sprintf("conntrack -D --orig-dst %s -p %s", lbIngressIP, strings.ToLower(string((v1.ProtocolUDP)))),
		// Delete NodePort Conntrack entrie
		fmt.Sprintf("conntrack -D -p %s --dport %d", strings.ToLower(string((v1.ProtocolUDP))), nodePort),
	}
	actualCommands := []string{
		strings.Join(fcmd.CombinedOutputLog[0], " "),
		strings.Join(fcmd.CombinedOutputLog[1], " "),
		strings.Join(fcmd.CombinedOutputLog[2], " "),
		strings.Join(fcmd.CombinedOutputLog[3], " "),
	}
	sort.Strings(expectedCommands)
	sort.Strings(actualCommands)

	if !reflect.DeepEqual(expectedCommands, actualCommands) {
		t.Errorf("Expected commands: %v, but executed %v", expectedCommands, actualCommands)
	}
}

// TODO(thockin): add *more* tests for syncProxyRules() or break it down further and test the pieces.

// This test ensures that the iptables proxier supports translating Endpoints to
// iptables output when internalTrafficPolicy is specified
func TestInternalTrafficPolicy(t *testing.T) {
	type endpoint struct {
		ip       string
		hostname string
	}

	cluster := v1.ServiceInternalTrafficPolicyCluster
	local := v1.ServiceInternalTrafficPolicyLocal

	testCases := []struct {
		name                  string
		line                  int
		internalTrafficPolicy *v1.ServiceInternalTrafficPolicy
		endpoints             []endpoint
		flowTests             []packetFlowTest
	}{
		{
			name:                  "internalTrafficPolicy is cluster",
			line:                  getLine(),
			internalTrafficPolicy: &cluster,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to ClusterIP hits all endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.3:80",
					masq:     false,
				},
			},
		},
		{
			name:                  "internalTrafficPolicy is local and there is one local endpoint",
			line:                  getLine(),
			internalTrafficPolicy: &local,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to ClusterIP hits only local endpoint",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80",
					masq:     false,
				},
			},
		},
		{
			name:                  "internalTrafficPolicy is local and there are multiple local endpoints",
			line:                  getLine(),
			internalTrafficPolicy: &local,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", testHostname},
				{"10.0.1.3", "host2"},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to ClusterIP hits all local endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80",
					masq:     false,
				},
			},
		},
		{
			name:                  "internalTrafficPolicy is local and there are no local endpoints",
			line:                  getLine(),
			internalTrafficPolicy: &local,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			flowTests: []packetFlowTest{
				{
					name:     "no endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "DROP",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			serviceName := "svc1"
			namespaceName := "ns1"

			svc := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespaceName},
				Spec: v1.ServiceSpec{
					ClusterIP: "172.30.1.1",
					Selector:  map[string]string{"foo": "bar"},
					Ports:     []v1.ServicePort{{Name: "", Port: 80, Protocol: v1.ProtocolTCP}},
				},
			}
			if tc.internalTrafficPolicy != nil {
				svc.Spec.InternalTrafficPolicy = tc.internalTrafficPolicy
			}

			fp.OnServiceAdd(svc)

			endpointSlice := &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", serviceName),
					Namespace: namespaceName,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
			}
			for _, ep := range tc.endpoints {
				endpointSlice.Endpoints = append(endpointSlice.Endpoints, discovery.Endpoint{
					Addresses:  []string{ep.ip},
					Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
					NodeName:   pointer.String(ep.hostname),
				})
			}

			fp.OnEndpointSliceAdd(endpointSlice)
			fp.syncProxyRules()
			runPacketFlowTests(t, tc.line, nft, testNodeIPs, tc.flowTests)

			fp.OnEndpointSliceDelete(endpointSlice)
			fp.syncProxyRules()
			runPacketFlowTests(t, tc.line, nft, testNodeIPs, []packetFlowTest{
				{
					name:     "endpoints deleted",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
			})
		})
	}
}

// TestTerminatingEndpointsTrafficPolicyLocal tests that when there are local ready and
// ready + terminating endpoints, only the ready endpoints are used.
func TestTerminatingEndpointsTrafficPolicyLocal(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Spec: v1.ServiceSpec{
			ClusterIP:             "172.30.1.1",
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
			Ports: []v1.ServicePort{
				{
					Name:       "",
					TargetPort: intstr.FromInt32(80),
					Port:       80,
					Protocol:   v1.ProtocolTCP,
				},
			},
			HealthCheckNodePort: 30000,
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}

	testcases := []struct {
		name          string
		line          int
		endpointslice *discovery.EndpointSlice
		flowTests     []packetFlowTest
	}{
		{
			name: "ready endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"10.0.1.1"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since there are ready non-terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since there are ready non-terminating endpoints
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since it's not local
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80",
					masq:     false,
				},
			},
		},
		{
			name: "only terminating endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should not be used since it is both terminating and not ready.
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since it's not local
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.2:80, 10.0.1.3:80",
					masq:     false,
				},
			},
		},
		{
			name: "terminating endpoints on remote node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// this endpoint won't be used because it's not local,
						// but it will prevent a REJECT rule from being created
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.5:80",
				},
				{
					name:     "external to LB, no locally-usable endpoints",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "DROP",
				},
			},
		},
		{
			name: "no usable endpoints on any node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// Local but not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// Remote and not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP, no usable endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB, no usable endpoints",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			fp.OnServiceAdd(service)

			fp.OnEndpointSliceAdd(testcase.endpointslice)
			fp.syncProxyRules()
			runPacketFlowTests(t, testcase.line, nft, testNodeIPs, testcase.flowTests)

			fp.OnEndpointSliceDelete(testcase.endpointslice)
			fp.syncProxyRules()
			runPacketFlowTests(t, testcase.line, nft, testNodeIPs, []packetFlowTest{
				{
					name:     "pod to clusterIP after endpoints deleted",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB after endpoints deleted",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			})
		})
	}
}

// TestTerminatingEndpointsTrafficPolicyCluster tests that when there are cluster-wide
// ready and ready + terminating endpoints, only the ready endpoints are used.
func TestTerminatingEndpointsTrafficPolicyCluster(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Spec: v1.ServiceSpec{
			ClusterIP:             "172.30.1.1",
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
			Ports: []v1.ServicePort{
				{
					Name:       "",
					TargetPort: intstr.FromInt32(80),
					Port:       80,
					Protocol:   v1.ProtocolTCP,
				},
			},
			HealthCheckNodePort: 30000,
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}

	testcases := []struct {
		name          string
		line          int
		endpointslice *discovery.EndpointSlice
		flowTests     []packetFlowTest
	}{
		{
			name: "ready endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"10.0.1.1"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored since there are ready non-terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
					{
						// this endpoint should be ignored since it is not "serving"
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
					{
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String("another-host"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.5:80",
					masq:     true,
				},
			},
		},
		{
			name: "only terminating endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should not be used since it is both terminating and not ready.
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.2:80, 10.0.1.3:80, 10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.2:80, 10.0.1.3:80, 10.0.1.5:80",
					masq:     true,
				},
			},
		},
		{
			name: "terminating endpoints on remote node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.5:80",
					masq:     true,
				},
			},
		},
		{
			name: "no usable endpoints on any node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// Local, not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// Remote, not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {

			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			fp.OnServiceAdd(service)

			fp.OnEndpointSliceAdd(testcase.endpointslice)
			fp.syncProxyRules()
			runPacketFlowTests(t, testcase.line, nft, testNodeIPs, testcase.flowTests)

			fp.OnEndpointSliceDelete(testcase.endpointslice)
			fp.syncProxyRules()
			runPacketFlowTests(t, testcase.line, nft, testNodeIPs, []packetFlowTest{
				{
					name:     "pod to clusterIP after endpoints deleted",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB after endpoints deleted",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			})
		})
	}
}

func TestInternalExternalMasquerade(t *testing.T) {
	// (Put the test setup code in an internal function so we can have it here at the
	// top, before the test cases that will be run against it.)
	setupTest := func(fp *Proxier) {
		local := v1.ServiceInternalTrafficPolicyLocal

		makeServiceMap(fp,
			makeTestService("ns1", "svc1", func(svc *v1.Service) {
				svc.Spec.Type = "LoadBalancer"
				svc.Spec.ClusterIP = "172.30.0.41"
				svc.Spec.Ports = []v1.ServicePort{{
					Name:     "p80",
					Port:     80,
					Protocol: v1.ProtocolTCP,
					NodePort: int32(3001),
				}}
				svc.Spec.HealthCheckNodePort = 30001
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
					IP: "1.2.3.4",
				}}
			}),
			makeTestService("ns2", "svc2", func(svc *v1.Service) {
				svc.Spec.Type = "LoadBalancer"
				svc.Spec.ClusterIP = "172.30.0.42"
				svc.Spec.Ports = []v1.ServicePort{{
					Name:     "p80",
					Port:     80,
					Protocol: v1.ProtocolTCP,
					NodePort: int32(3002),
				}}
				svc.Spec.HealthCheckNodePort = 30002
				svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
					IP: "5.6.7.8",
				}}
			}),
			makeTestService("ns3", "svc3", func(svc *v1.Service) {
				svc.Spec.Type = "LoadBalancer"
				svc.Spec.ClusterIP = "172.30.0.43"
				svc.Spec.Ports = []v1.ServicePort{{
					Name:     "p80",
					Port:     80,
					Protocol: v1.ProtocolTCP,
					NodePort: int32(3003),
				}}
				svc.Spec.HealthCheckNodePort = 30003
				svc.Spec.InternalTrafficPolicy = &local
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
					IP: "9.10.11.12",
				}}
			}),
		)

		populateEndpointSlices(fp,
			makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{
					{
						Addresses: []string{"10.180.0.1"},
						NodeName:  pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.180.1.1"},
						NodeName:  pointer.String("remote"),
					},
				}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}}
			}),
			makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{
					{
						Addresses: []string{"10.180.0.2"},
						NodeName:  pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.180.1.2"},
						NodeName:  pointer.String("remote"),
					},
				}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}}
			}),
			makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{
					{
						Addresses: []string{"10.180.0.3"},
						NodeName:  pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.180.1.3"},
						NodeName:  pointer.String("remote"),
					},
				}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}}
			}),
		)

		fp.syncProxyRules()
	}

	// We use the same flowTests for all of the testCases. The "output" and "masq"
	// values here represent the normal case (working localDetector, no masqueradeAll)
	flowTests := []packetFlowTest{
		{
			name:     "pod to ClusterIP",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     false,
		},
		{
			name:     "pod to NodePort",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "pod to LB",
			sourceIP: "10.0.0.2",
			destIP:   "1.2.3.4",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "node to ClusterIP",
			sourceIP: testNodeIP,
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "node to NodePort",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "node to LB",
			sourceIP: testNodeIP,
			destIP:   "1.2.3.4",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "external to ClusterIP",
			sourceIP: testExternalClient,
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "external to NodePort",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "external to LB",
			sourceIP: testExternalClient,
			destIP:   "1.2.3.4",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "pod to ClusterIP with eTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.42",
			destPort: 80,

			// externalTrafficPolicy does not apply to ClusterIP traffic, so same
			// as "Pod to ClusterIP"
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   false,
		},
		{
			name:     "pod to NodePort with eTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: 3002,

			// See the comment below in the "pod to LB with eTP:Local" case.
			// It doesn't actually make sense to short-circuit here, since if
			// you connect directly to a NodePort from outside the cluster,
			// you only get the local endpoints. But it's simpler for us and
			// slightly more convenient for users to have this case get
			// short-circuited too.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   false,
		},
		{
			name:     "pod to LB with eTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "5.6.7.8",
			destPort: 80,

			// The short-circuit rule is supposed to make this behave the same
			// way it would if the packet actually went out to the LB and then
			// came back into the cluster. So it gets routed to all endpoints,
			// not just local ones. In reality, if the packet actually left
			// the cluster, it would have to get masqueraded, but since we can
			// avoid doing that in the short-circuit case, and not masquerading
			// is more useful, we avoid masquerading.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   false,
		},
		{
			name:     "node to ClusterIP with eTP:Local",
			sourceIP: testNodeIP,
			destIP:   "172.30.0.42",
			destPort: 80,

			// externalTrafficPolicy does not apply to ClusterIP traffic, so same
			// as "node to ClusterIP"
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "node to NodePort with eTP:Local",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 3001,

			// The traffic gets short-circuited, ignoring externalTrafficPolicy, so
			// same as "node to NodePort" above.
			output: "10.180.0.1:80, 10.180.1.1:80",
			masq:   true,
		},
		{
			name:     "node to LB with eTP:Local",
			sourceIP: testNodeIP,
			destIP:   "5.6.7.8",
			destPort: 80,

			// The traffic gets short-circuited, ignoring externalTrafficPolicy, so
			// same as "node to LB" above.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "external to ClusterIP with eTP:Local",
			sourceIP: testExternalClient,
			destIP:   "172.30.0.42",
			destPort: 80,

			// externalTrafficPolicy does not apply to ClusterIP traffic, so same
			// as "external to ClusterIP" above.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "external to NodePort with eTP:Local",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: 3002,

			// externalTrafficPolicy applies; only the local endpoint is
			// selected, and we don't masquerade.
			output: "10.180.0.2:80",
			masq:   false,
		},
		{
			name:     "external to LB with eTP:Local",
			sourceIP: testExternalClient,
			destIP:   "5.6.7.8",
			destPort: 80,

			// externalTrafficPolicy applies; only the local endpoint is
			// selected, and we don't masquerade.
			output: "10.180.0.2:80",
			masq:   false,
		},
		{
			name:     "pod to ClusterIP with iTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.43",
			destPort: 80,

			// internalTrafficPolicy applies; only the local endpoint is
			// selected.
			output: "10.180.0.3:80",
			masq:   false,
		},
		{
			name:     "pod to NodePort with iTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "pod to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "pod to LB with iTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "9.10.11.12",
			destPort: 80,

			// internalTrafficPolicy does not apply to LoadBalancer traffic, so
			// same as "pod to LB" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "node to ClusterIP with iTP:Local",
			sourceIP: testNodeIP,
			destIP:   "172.30.0.43",
			destPort: 80,

			// internalTrafficPolicy applies; only the local endpoint is selected.
			// Traffic is masqueraded as in the "node to ClusterIP" case because
			// internalTrafficPolicy does not affect masquerading.
			output: "10.180.0.3:80",
			masq:   true,
		},
		{
			name:     "node to NodePort with iTP:Local",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "node to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "node to LB with iTP:Local",
			sourceIP: testNodeIP,
			destIP:   "9.10.11.12",
			destPort: 80,

			// internalTrafficPolicy does not apply to LoadBalancer traffic, so
			// same as "node to LB" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "external to ClusterIP with iTP:Local",
			sourceIP: testExternalClient,
			destIP:   "172.30.0.43",
			destPort: 80,

			// internalTrafficPolicy applies; only the local endpoint is selected.
			// Traffic is masqueraded as in the "external to ClusterIP" case
			// because internalTrafficPolicy does not affect masquerading.
			output: "10.180.0.3:80",
			masq:   true,
		},
		{
			name:     "external to NodePort with iTP:Local",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "external to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "external to LB with iTP:Local",
			sourceIP: testExternalClient,
			destIP:   "9.10.11.12",
			destPort: 80,

			// internalTrafficPolicy does not apply to LoadBalancer traffic, so
			// same as "external to LB" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
	}

	type packetFlowTestOverride struct {
		output *string
		masq   *bool
	}

	testCases := []struct {
		name          string
		line          int
		masqueradeAll bool
		localDetector bool
		overrides     map[string]packetFlowTestOverride
	}{
		{
			name:          "base",
			line:          getLine(),
			masqueradeAll: false,
			localDetector: true,
			overrides:     nil,
		},
		{
			name:          "no LocalTrafficDetector",
			line:          getLine(),
			masqueradeAll: false,
			localDetector: false,
			overrides: map[string]packetFlowTestOverride{
				// With no LocalTrafficDetector, all traffic to a
				// ClusterIP is assumed to be from a pod, and thus to not
				// require masquerading.
				"node to ClusterIP": {
					masq: pointer.Bool(false),
				},
				"node to ClusterIP with eTP:Local": {
					masq: pointer.Bool(false),
				},
				"node to ClusterIP with iTP:Local": {
					masq: pointer.Bool(false),
				},
				"external to ClusterIP": {
					masq: pointer.Bool(false),
				},
				"external to ClusterIP with eTP:Local": {
					masq: pointer.Bool(false),
				},
				"external to ClusterIP with iTP:Local": {
					masq: pointer.Bool(false),
				},

				// And there's no eTP:Local short-circuit for pod traffic,
				// so pods get only the local endpoints.
				"pod to NodePort with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
				"pod to LB with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
			},
		},
		{
			name:          "masqueradeAll",
			line:          getLine(),
			masqueradeAll: true,
			localDetector: true,
			overrides: map[string]packetFlowTestOverride{
				// All "to ClusterIP" traffic gets masqueraded when using
				// --masquerade-all.
				"pod to ClusterIP": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with eTP:Local": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with iTP:Local": {
					masq: pointer.Bool(true),
				},
			},
		},
		{
			name:          "masqueradeAll, no LocalTrafficDetector",
			line:          getLine(),
			masqueradeAll: true,
			localDetector: false,
			overrides: map[string]packetFlowTestOverride{
				// As in "masqueradeAll"
				"pod to ClusterIP": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with eTP:Local": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with iTP:Local": {
					masq: pointer.Bool(true),
				},

				// As in "no LocalTrafficDetector"
				"pod to NodePort with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
				"pod to LB with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.masqueradeAll = tc.masqueradeAll
			if !tc.localDetector {
				fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
			}
			setupTest(fp)

			// Merge base flowTests with per-test-case overrides
			tcFlowTests := make([]packetFlowTest, len(flowTests))
			overridesApplied := 0
			for i := range flowTests {
				tcFlowTests[i] = flowTests[i]
				if overrides, set := tc.overrides[flowTests[i].name]; set {
					overridesApplied++
					if overrides.masq != nil {
						if tcFlowTests[i].masq == *overrides.masq {
							t.Errorf("%q override value for masq is same as base value", flowTests[i].name)
						}
						tcFlowTests[i].masq = *overrides.masq
					}
					if overrides.output != nil {
						if tcFlowTests[i].output == *overrides.output {
							t.Errorf("%q override value for output is same as base value", flowTests[i].name)
						}
						tcFlowTests[i].output = *overrides.output
					}
				}
			}
			if overridesApplied != len(tc.overrides) {
				t.Errorf("%d overrides did not match any test case name!", len(tc.overrides)-overridesApplied)
			}
			runPacketFlowTests(t, tc.line, nft, testNodeIPs, tcFlowTests)
		})
	}
}

// Test calling syncProxyRules() multiple times with various changes
func TestSyncProxyRulesRepeated(t *testing.T) {
	nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
	fp := NewFakeProxier(nft, v1.IPv4Protocol)

	baseRules := dedent.Dedent(`
		add table ip kube-proxy { comment "rules for kube-proxy" ; }

		add chain ip kube-proxy endpoints-check
		add chain ip kube-proxy filter-forward { type filter hook forward priority -101 ; }
		add chain ip kube-proxy filter-input { type filter hook input priority -101 ; }
		add chain ip kube-proxy filter-output { type filter hook output priority -101 ; }
		add chain ip kube-proxy firewall-allow-check
		add chain ip kube-proxy firewall-check
		add chain ip kube-proxy forward
		add chain ip kube-proxy mark-for-masquerade
		add chain ip kube-proxy masquerading
		add chain ip kube-proxy nat-output { type nat hook output priority -100 ; }
		add chain ip kube-proxy nat-postrouting { type nat hook postrouting priority 100 ; }
		add chain ip kube-proxy nat-prerouting { type nat hook prerouting priority -100 ; }
		add chain ip kube-proxy reject-chain { comment "helper for @no-endpoint-services / @no-endpoint-nodeports" ; }
		add chain ip kube-proxy services

		add rule ip kube-proxy endpoints-check ip daddr . ip protocol . th dport vmap @no-endpoint-services
		add rule ip kube-proxy endpoints-check fib daddr type local fib oif != "lo" ip protocol . th dport vmap @no-endpoint-nodeports
		add rule ip kube-proxy filter-forward ct state new jump endpoints-check
		add rule ip kube-proxy filter-forward jump forward
		add rule ip kube-proxy filter-forward ct state new jump firewall-check
		add rule ip kube-proxy filter-input ct state new jump endpoints-check
		add rule ip kube-proxy filter-input ct state new jump firewall-check
		add rule ip kube-proxy filter-output ct state new jump endpoints-check
		add rule ip kube-proxy filter-output ct state new jump firewall-check
		add rule ip kube-proxy firewall-allow-check ip daddr . ip protocol . th dport . ip saddr @firewall-allow return
		add rule ip kube-proxy firewall-allow-check drop
		add rule ip kube-proxy firewall-check ip daddr . ip protocol . th dport @firewall jump firewall-allow-check
		add rule ip kube-proxy forward ct state invalid drop
		add rule ip kube-proxy mark-for-masquerade mark set mark or 0x4000
		add rule ip kube-proxy masquerading mark and 0x4000 == 0 return
		add rule ip kube-proxy masquerading mark set mark xor 0x4000
		add rule ip kube-proxy masquerading masquerade fully-random
		add rule ip kube-proxy nat-output jump services
		add rule ip kube-proxy nat-postrouting jump masquerading
		add rule ip kube-proxy nat-prerouting jump services
		add rule ip kube-proxy reject-chain reject
		add rule ip kube-proxy services ip daddr . ip protocol . th dport vmap @service-ips
		add rule ip kube-proxy services fib daddr type local fib oif != "lo" ip protocol . th dport vmap @service-nodeports

		add set ip kube-proxy firewall { type ipv4_addr . inet_proto . inet_service ; comment "destinations that are subject to LoadBalancerSourceRanges" ; }
		add set ip kube-proxy firewall-allow { type ipv4_addr . inet_proto . inet_service . ipv4_addr ; flags interval ; comment "destinations+sources that are allowed by LoadBalancerSourceRanges" ; }
		add map ip kube-proxy no-endpoint-nodeports { type inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to service nodeports with no endpoints" ; }
		add map ip kube-proxy no-endpoint-services { type ipv4_addr . inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to services with no endpoints" ; }
		add map ip kube-proxy service-ips { type ipv4_addr . inet_proto . inet_service : verdict ; comment "ClusterIP, ExternalIP and LoadBalancer IP traffic" ; }
		add map ip kube-proxy service-nodeports { type inet_proto . inet_service : verdict ; comment "NodePort traffic" ; }
		`)

	// Create initial state
	var svc2 *v1.Service

	makeServiceMap(fp,
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc2 = svc
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p8080",
				Port:     8080,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.1.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.2.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p8080"),
				Port:     pointer.Int32(8080),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	expected := baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.42 . tcp . 8080 : goto service-MHHHYRWA-ns2/svc2/tcp/p8080 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-MHHHYRWA-ns2/svc2/tcp/p8080
		add rule ip kube-proxy service-MHHHYRWA-ns2/svc2/tcp/p8080 ip daddr 172.30.0.42 tcp dport 8080 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-MHHHYRWA-ns2/svc2/tcp/p8080 numgen random mod 1 vmap { 0 : goto endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080 }
		add chain ip kube-proxy endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080
		add rule ip kube-proxy endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080 ip saddr 10.0.2.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080 ip protocol tcp dnat to 10.0.2.1:8080
                `)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	// Add a new service and its endpoints
	makeServiceMap(fp,
		makeTestService("ns3", "svc3", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.43"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)
	var eps3 *discovery.EndpointSlice
	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
			eps3 = eps
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.3.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
	)
	fp.syncProxyRules()

	expected = baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.42 . tcp . 8080 : goto service-MHHHYRWA-ns2/svc2/tcp/p8080 }
		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-MHHHYRWA-ns2/svc2/tcp/p8080
		add rule ip kube-proxy service-MHHHYRWA-ns2/svc2/tcp/p8080 ip daddr 172.30.0.42 tcp dport 8080 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-MHHHYRWA-ns2/svc2/tcp/p8080 numgen random mod 1 vmap { 0 : goto endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080 }
		add chain ip kube-proxy endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080
		add rule ip kube-proxy endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080 ip saddr 10.0.2.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-7RVP4LUQ-ns2/svc2/tcp/p8080__10.0.2.1/8080 ip protocol tcp dnat to 10.0.2.1:8080

		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 }
		add chain ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip saddr 10.0.3.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip protocol tcp dnat to 10.0.3.1:80
		`)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	// Delete a service.
	fp.OnServiceDelete(svc2)
	fp.syncProxyRules()

	expected = baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 }
		add chain ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip saddr 10.0.3.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip protocol tcp dnat to 10.0.3.1:80
		`)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	// Add a service, sync, then add its endpoints.
	makeServiceMap(fp,
		makeTestService("ns4", "svc4", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.44"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)
	fp.syncProxyRules()
	expected = baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 }
		add chain ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip saddr 10.0.3.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip protocol tcp dnat to 10.0.3.1:80

		add element ip kube-proxy no-endpoint-services { 172.30.0.44 . tcp . 80 comment "ns4/svc4:p80" : goto reject-chain }
		`)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns4", "svc4", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.4.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
	)
	fp.syncProxyRules()
	expected = baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.44 . tcp . 80 : goto service-LAUZTJTB-ns4/svc4/tcp/p80 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 }
		add chain ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip saddr 10.0.3.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-2OCDJSZQ-ns3/svc3/tcp/p80__10.0.3.1/80 ip protocol tcp dnat to 10.0.3.1:80

		add chain ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 ip daddr 172.30.0.44 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 }
		add chain ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80
		add rule ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 ip saddr 10.0.4.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 ip protocol tcp dnat to 10.0.4.1:80
		`)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	// Change an endpoint of an existing service.
	eps3update := eps3.DeepCopy()
	eps3update.Endpoints[0].Addresses[0] = "10.0.3.2"
	fp.OnEndpointSliceUpdate(eps3, eps3update)
	fp.syncProxyRules()

	expected = baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.44 . tcp . 80 : goto service-LAUZTJTB-ns4/svc4/tcp/p80 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80 }
		add chain ip kube-proxy endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80
		add rule ip kube-proxy endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80 ip saddr 10.0.3.2 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80 ip protocol tcp dnat to 10.0.3.2:80

		add chain ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 ip daddr 172.30.0.44 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 }
		add chain ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80
		add rule ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 ip saddr 10.0.4.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 ip protocol tcp dnat to 10.0.4.1:80
		`)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	// Add an endpoint to a service.
	eps3update2 := eps3update.DeepCopy()
	eps3update2.Endpoints = append(eps3update2.Endpoints, discovery.Endpoint{Addresses: []string{"10.0.3.3"}})
	fp.OnEndpointSliceUpdate(eps3update, eps3update2)
	fp.syncProxyRules()

	expected = baseRules + dedent.Dedent(`
		add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }
		add element ip kube-proxy service-ips { 172.30.0.44 . tcp . 80 : goto service-LAUZTJTB-ns4/svc4/tcp/p80 }

		add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 }
		add chain ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip saddr 10.0.1.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-5TPGNJF2-ns1/svc1/tcp/p80__10.0.1.1/80 ip protocol tcp dnat to 10.0.1.1:80

		add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 2 vmap { 0 : goto endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80 , 1 : goto endpoint-TQ2QKHCZ-ns3/svc3/tcp/p80__10.0.3.3/80 }
		add chain ip kube-proxy endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80
		add rule ip kube-proxy endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80 ip saddr 10.0.3.2 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-SWWHDC7X-ns3/svc3/tcp/p80__10.0.3.2/80 ip protocol tcp dnat to 10.0.3.2:80
		add chain ip kube-proxy endpoint-TQ2QKHCZ-ns3/svc3/tcp/p80__10.0.3.3/80
		add rule ip kube-proxy endpoint-TQ2QKHCZ-ns3/svc3/tcp/p80__10.0.3.3/80 ip saddr 10.0.3.3 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-TQ2QKHCZ-ns3/svc3/tcp/p80__10.0.3.3/80 ip protocol tcp dnat to 10.0.3.3:80

		add chain ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 ip daddr 172.30.0.44 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
		add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 }
		add chain ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80
		add rule ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 ip saddr 10.0.4.1 jump mark-for-masquerade
		add rule ip kube-proxy endpoint-WAHRBT2B-ns4/svc4/tcp/p80__10.0.4.1/80 ip protocol tcp dnat to 10.0.4.1:80
		`)
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())

	// Sync with no new changes, so same expected rules as last time
	fp.syncProxyRules()
	assertNFTablesTransactionEqual(t, getLine(), expected, nft.Dump())
}

func TestNoEndpointsMetric(t *testing.T) {
	type endpoint struct {
		ip       string
		hostname string
	}

	internalTrafficPolicyLocal := v1.ServiceInternalTrafficPolicyLocal
	externalTrafficPolicyLocal := v1.ServiceExternalTrafficPolicyLocal

	metrics.RegisterMetrics()
	testCases := []struct {
		name                                                string
		internalTrafficPolicy                               *v1.ServiceInternalTrafficPolicy
		externalTrafficPolicy                               v1.ServiceExternalTrafficPolicy
		endpoints                                           []endpoint
		expectedSyncProxyRulesNoLocalEndpointsTotalInternal int
		expectedSyncProxyRulesNoLocalEndpointsTotalExternal int
	}{
		{
			name:                  "internalTrafficPolicy is set and there are local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
		},
		{
			name:                  "externalTrafficPolicy is set and there are local endpoints",
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
		},
		{
			name:                  "both policies are set and there are local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
		},
		{
			name:                  "internalTrafficPolicy is set and there are no local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectedSyncProxyRulesNoLocalEndpointsTotalInternal: 1,
		},
		{
			name:                  "externalTrafficPolicy is set and there are no local endpoints",
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectedSyncProxyRulesNoLocalEndpointsTotalExternal: 1,
		},
		{
			name:                  "both policies are set and there are no local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectedSyncProxyRulesNoLocalEndpointsTotalInternal: 1,
			expectedSyncProxyRulesNoLocalEndpointsTotalExternal: 1,
		},
		{
			name:                  "both policies are set and there are no endpoints at all",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints:             []endpoint{},
			expectedSyncProxyRulesNoLocalEndpointsTotalInternal: 0,
			expectedSyncProxyRulesNoLocalEndpointsTotalExternal: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			serviceName := "svc1"
			namespaceName := "ns1"

			svc := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespaceName},
				Spec: v1.ServiceSpec{
					ClusterIP: "172.30.1.1",
					Selector:  map[string]string{"foo": "bar"},
					Ports:     []v1.ServicePort{{Name: "", Port: 80, Protocol: v1.ProtocolTCP, NodePort: 123}},
				},
			}
			if tc.internalTrafficPolicy != nil {
				svc.Spec.InternalTrafficPolicy = tc.internalTrafficPolicy
			}
			if tc.externalTrafficPolicy != "" {
				svc.Spec.Type = v1.ServiceTypeNodePort
				svc.Spec.ExternalTrafficPolicy = tc.externalTrafficPolicy
			}

			fp.OnServiceAdd(svc)

			endpointSlice := &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", serviceName),
					Namespace: namespaceName,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
			}
			for _, ep := range tc.endpoints {
				endpointSlice.Endpoints = append(endpointSlice.Endpoints, discovery.Endpoint{
					Addresses:  []string{ep.ip},
					Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
					NodeName:   pointer.String(ep.hostname),
				})
			}

			fp.OnEndpointSliceAdd(endpointSlice)
			fp.syncProxyRules()
			syncProxyRulesNoLocalEndpointsTotalInternal, err := testutil.GetGaugeMetricValue(metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("internal"))
			if err != nil {
				t.Errorf("failed to get %s value, err: %v", metrics.SyncProxyRulesNoLocalEndpointsTotal.Name, err)
			}

			if tc.expectedSyncProxyRulesNoLocalEndpointsTotalInternal != int(syncProxyRulesNoLocalEndpointsTotalInternal) {
				t.Errorf("sync_proxy_rules_no_endpoints_total metric mismatch(internal): got=%d, expected %d", int(syncProxyRulesNoLocalEndpointsTotalInternal), tc.expectedSyncProxyRulesNoLocalEndpointsTotalInternal)
			}

			syncProxyRulesNoLocalEndpointsTotalExternal, err := testutil.GetGaugeMetricValue(metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("external"))
			if err != nil {
				t.Errorf("failed to get %s value(external), err: %v", metrics.SyncProxyRulesNoLocalEndpointsTotal.Name, err)
			}

			if tc.expectedSyncProxyRulesNoLocalEndpointsTotalExternal != int(syncProxyRulesNoLocalEndpointsTotalExternal) {
				t.Errorf("sync_proxy_rules_no_endpoints_total metric mismatch(internal): got=%d, expected %d", int(syncProxyRulesNoLocalEndpointsTotalExternal), tc.expectedSyncProxyRulesNoLocalEndpointsTotalExternal)
			}
		})
	}
}

func TestLoadBalancerIngressRouteTypeProxy(t *testing.T) {
	ipModeProxy := v1.LoadBalancerIPModeProxy
	ipModeVIP := v1.LoadBalancerIPModeVIP

	testCases := []struct {
		name          string
		ipModeEnabled bool
		svcIP         string
		svcLBIP       string
		ipMode        *v1.LoadBalancerIPMode
		expectedRule  bool
	}{
		/* LoadBalancerIPMode disabled */
		{
			name:          "LoadBalancerIPMode disabled, ipMode Proxy",
			ipModeEnabled: false,
			svcIP:         "10.20.30.41",
			svcLBIP:       "1.2.3.4",
			ipMode:        &ipModeProxy,
			expectedRule:  true,
		},
		{
			name:          "LoadBalancerIPMode disabled, ipMode VIP",
			ipModeEnabled: false,
			svcIP:         "10.20.30.42",
			svcLBIP:       "1.2.3.5",
			ipMode:        &ipModeVIP,
			expectedRule:  true,
		},
		{
			name:          "LoadBalancerIPMode disabled, ipMode nil",
			ipModeEnabled: false,
			svcIP:         "10.20.30.43",
			svcLBIP:       "1.2.3.6",
			ipMode:        nil,
			expectedRule:  true,
		},
		/* LoadBalancerIPMode enabled */
		{
			name:          "LoadBalancerIPMode enabled, ipMode Proxy",
			ipModeEnabled: true,
			svcIP:         "10.20.30.41",
			svcLBIP:       "1.2.3.4",
			ipMode:        &ipModeProxy,
			expectedRule:  false,
		},
		{
			name:          "LoadBalancerIPMode enabled, ipMode VIP",
			ipModeEnabled: true,
			svcIP:         "10.20.30.42",
			svcLBIP:       "1.2.3.5",
			ipMode:        &ipModeVIP,
			expectedRule:  true,
		},
		{
			name:          "LoadBalancerIPMode enabled, ipMode nil",
			ipModeEnabled: true,
			svcIP:         "10.20.30.43",
			svcLBIP:       "1.2.3.6",
			ipMode:        nil,
			expectedRule:  true,
		},
	}

	svcPort := 80
	svcNodePort := 3001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.LoadBalancerIPMode, testCase.ipModeEnabled)()
			nft := nftables.NewFake(nftables.IPv4Family, kubeProxyTable)
			fp := NewFakeProxier(nft, v1.IPv4Protocol)
			makeServiceMap(fp,
				makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
					svc.Spec.Type = "LoadBalancer"
					svc.Spec.ClusterIP = testCase.svcIP
					svc.Spec.Ports = []v1.ServicePort{{
						Name:     svcPortName.Port,
						Port:     int32(svcPort),
						Protocol: v1.ProtocolTCP,
						NodePort: int32(svcNodePort),
					}}
					svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
						IP:     testCase.svcLBIP,
						IPMode: testCase.ipMode,
					}}
				}),
			)

			tcpProtocol := v1.ProtocolTCP
			populateEndpointSlices(fp,
				makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
					eps.AddressType = discovery.AddressTypeIPv4
					eps.Endpoints = []discovery.Endpoint{{
						Addresses: []string{"10.180.0.1"},
					}}
					eps.Ports = []discovery.EndpointPort{{
						Name:     pointer.String("p80"),
						Port:     pointer.Int32(80),
						Protocol: &tcpProtocol,
					}}
				}),
			)

			fp.syncProxyRules()

			element := nft.Table.Maps["service-ips"].FindElement(testCase.svcLBIP, "tcp", "80")
			ruleExists := element != nil
			if ruleExists != testCase.expectedRule {
				t.Errorf("unexpected rule for %s", testCase.svcLBIP)
			}
		})
	}
}

func Test_servicePortChainNameBase(t *testing.T) {
	testCases := []struct {
		name     string
		spn      proxy.ServicePortName
		protocol string
		expected string
	}{
		{
			name: "simple",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "testing",
					Name:      "service",
				},
				Port: "http",
			},
			protocol: "tcp",
			expected: "P4ZYZVCF-testing/service/tcp/http",
		},
		{
			name: "different port, different hash",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "testing",
					Name:      "service",
				},
				Port: "https",
			},
			protocol: "tcp",
			expected: "LZBRENCP-testing/service/tcp/https",
		},
		{
			name: "max length without truncation",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "this-is-a-very-long-namespace-name",
					Name:      "this-is-an-even-longer-name-which-is-not-a-best-practice",
				},
				Port: "port80",
			},
			protocol: "tcp",
			expected: "IPAPHA5C-this-is-a-very-long-namespace-name/this-is-an-even-longer-name-which-is-not-a-best-practice/tcp/port80",
		},
		{
			name: "truncated, 1",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "this-is-a-very-long-namespace-name",
					Name:      "and-this-is-an-even-longer-name-which-is-not-a-best-practice",
				},
				Port: "port80",
			},
			protocol: "tcp",
			expected: "7PLLR4AZ-this-is-a-very-long-namespace-name/and-this-is-an-even-longer-name-which-is-not-a-best-practice/tcp...",
		},
		{
			name: "truncated, 2 (different port, which is not visible in result)",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "this-is-a-very-long-namespace-name",
					Name:      "and-this-is-an-even-longer-name-which-is-not-a-best-practice",
				},
				Port: "port81",
			},
			protocol: "tcp",
			expected: "BWLQNBPK-this-is-a-very-long-namespace-name/and-this-is-an-even-longer-name-which-is-not-a-best-practice/tcp...",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name := servicePortChainNameBase(&tc.spn, tc.protocol)
			if name != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, name)
			}
		})
	}
}

func Test_servicePortEndpointChainNameBase(t *testing.T) {
	testCases := []struct {
		name     string
		spn      proxy.ServicePortName
		protocol string
		endpoint string
		expected string
	}{
		{
			name: "simple",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "testing",
					Name:      "service",
				},
				Port: "http",
			},
			protocol: "tcp",
			endpoint: "10.180.0.1:80",
			expected: "JO2XBXZR-testing/service/tcp/http__10.180.0.1/80",
		},
		{
			name: "different endpoint, different hash",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "testing",
					Name:      "service",
				},
				Port: "http",
			},
			protocol: "tcp",
			endpoint: "10.180.0.2:80",
			expected: "5S6H3H22-testing/service/tcp/http__10.180.0.2/80",
		},
		{
			name: "ipv6",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "testing",
					Name:      "service",
				},
				Port: "http",
			},
			protocol: "tcp",
			endpoint: "[fd80:abcd:12::a1b2:c3d4:e5f6:9999]:80",
			expected: "U7E2ET36-testing/service/tcp/http__fd80.abcd.12..a1b2.c3d4.e5f6.9999/80",
		},
		{
			name: "max length without truncation",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "this-is-a-very-long-namespace-name",
					Name:      "and-now-this-is-an-even-longer-service-name",
				},
				Port: "http",
			},
			protocol: "tcp",
			endpoint: "10.180.0.1:80",
			expected: "UXJ6P64G-this-is-a-very-long-namespace-name/and-now-this-is-an-even-longer-service-name/tcp/http__10.180.0.1/80",
		},
		{
			name: "truncated, 1",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "this-is-a-very-long-namespace-name",
					Name:      "and-this-here-is-a-much-too-long-name-for-a-service",
				},
				Port: "http",
			},
			protocol: "tcp",
			endpoint: "10.180.0.1:80",
			expected: "NNWFU3QN-this-is-a-very-long-namespace-name/and-this-here-is-a-much-too-long-name-for-a-service/tcp/http__10...",
		},
		{
			name: "truncated, 2 (different IP, which is not visible in the result)",
			spn: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "this-is-a-very-long-namespace-name",
					Name:      "and-this-here-is-a-much-too-long-name-for-a-service",
				},
				Port: "http",
			},
			protocol: "tcp",
			endpoint: "10.180.0.2:80",
			expected: "ASBH4DUC-this-is-a-very-long-namespace-name/and-this-here-is-a-much-too-long-name-for-a-service/tcp/http__10...",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name := servicePortEndpointChainNameBase(&tc.spn, tc.protocol, tc.endpoint)
			if name != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, name)
			}
		})
	}
}
