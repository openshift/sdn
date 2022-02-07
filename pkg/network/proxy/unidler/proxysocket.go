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

package unidler

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
)

// Abstraction over TCP/UDP sockets which are proxied.
type ProxySocket interface {
	// Addr gets the net.Addr for a ProxySocket.
	Addr() net.Addr
	// Close stops the ProxySocket from accepting incoming connections.
	// Each implementation should comment on the impact of calling Close
	// while sessions are active.
	Close() error
	// ProxyLoop proxies incoming connections for the specified service to the service endpoints.
	ProxyLoop(service proxy.ServicePortName, info *ServiceInfo, loadBalancer *LoadBalancerRR)
	// ListenPort returns the host port that the ProxySocket is listening on
	ListenPort() int
}

// How long we wait for a connection to a backend in seconds
var EndpointDialTimeouts = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second}

// TryConnectEndpoints attempts to connect to the next available endpoint for the given service, cycling
// through until it is able to successfully connect, or it has tried with all timeouts in EndpointDialTimeouts.
func TryConnectEndpoints(service proxy.ServicePortName, srcAddr net.Addr, protocol string, loadBalancer *LoadBalancerRR) (out net.Conn, err error) {
	sessionAffinityReset := false
	for _, dialTimeout := range EndpointDialTimeouts {
		endpoint, err := loadBalancer.NextEndpoint(service, srcAddr, sessionAffinityReset)
		if err != nil {
			klog.Errorf("Couldn't find an endpoint for %s: %v", service, err)
			return nil, err
		}
		klog.V(3).Infof("Mapped service %q to endpoint %s", service, endpoint)
		// TODO: This could spin up a new goroutine to make the outbound connection,
		// and keep accepting inbound traffic.
		outConn, err := net.DialTimeout(protocol, endpoint, dialTimeout)
		if err != nil {
			if isTooManyFDsError(err) {
				panic("Dial failed: " + err.Error())
			}
			klog.Errorf("Dial failed: %v", err)
			sessionAffinityReset = true
			continue
		}
		return outConn, nil
	}
	return nil, fmt.Errorf("failed to connect to an endpoint.")
}

// ProxyTCP proxies data bi-directionally between in and out.
func ProxyTCP(in, out *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	klog.V(4).Infof("Creating proxy between %v <-> %v <-> %v <-> %v",
		in.RemoteAddr(), in.LocalAddr(), out.LocalAddr(), out.RemoteAddr())
	go copyBytes("from backend", in, out, &wg)
	go copyBytes("to backend", out, in, &wg)
	wg.Wait()
}

func copyBytes(direction string, dest, src *net.TCPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	klog.V(4).Infof("Copying %s: %s -> %s", direction, src.RemoteAddr(), dest.RemoteAddr())
	n, err := io.Copy(dest, src)
	if err != nil {
		if !isClosedError(err) {
			klog.Errorf("I/O error: %v", err)
		}
	}
	klog.V(4).Infof("Copied %d bytes %s: %s -> %s", n, direction, src.RemoteAddr(), dest.RemoteAddr())
	dest.Close()
	src.Close()
}
