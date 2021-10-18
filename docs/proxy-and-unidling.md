# Proxying and Unidling in OpenShift SDN

## Overall Proxy Architecture

The `openshift-sdn-node` process runs kube-proxy inside of itself. CNO
passes a kube-proxy configuration file to openshift-sdn via a
ConfigMap and a command-line flag pointing to it. The node process
then reads in that configuration and sets up kube-proxy based on that.
([`./pkg/cmd/openshift-sdn-node/proxy.go`](../pkg/cmd/openshift-sdn-node/proxy.go)
has the code to read the config; it then calls out to functions in
[`./pkg/cmd/openshift-sdn-node/kube_proxy.go`](../pkg/cmd/openshift-sdn-node/kube_proxy.go)
to do most of the actual setup; the latter file is kept closely in
sync with the upstream kube-proxy startup code, for ease of updating
later.

(The process of parsing the config file depends on a function added by
one of our `<carry>` patches:
[`./vendor/k8s.io/kubernetes/cmd/kube-proxy/app/server_openshift.go`](../vendor/k8s.io/kubernetes/cmd/kube-proxy/app/server_openshift.go).)

The biggest difference in how we run kube-proxy, relative to
standalone kube-proxy, is in the function `wrapProxy` in `proxy.go`.
There we check if unidling was enabled (it is by default), and if so,
create an unidling proxy (described below). Then, the iptables proxy
and (possibly) the unidling proxy are combined together with a call to
`sdn.OsdnProxy.SetBaseProxies()`, and we then set `sdn.OsdnProxy` as
the actual proxy.

## The OsdnProxy Wrapper and Egress Firewall Handling

`OsdnProxy` (defined in
[`./pkg/network/proxy/proxy.go`](../pkg/network/proxy/proxy.go) is a
kube-proxy implementation that works as a wrapper around another
kube-proxy implementation. Its primary purpose is to filter the
Endpoints that it passes on to its base proxy, to ensure that the
egress firewall feature (aka `EgressNetworkPolicy`) is not subverted. Any
time a service's endpoints change, `OsdnProxy` checks those endpoints
against the egress firewall for that namespace. If it finds any
endpoints that are supposed to be blocked by the firewall, then it
ignores the entire Endpoints/EndpointSlice object; otherwise it passes
the Endpoints/EndpointSlice down to its base proxy.

The reason this is needed is because egress firewall rules are
per-namespace, but we only know the identity of the source namespace
of the packet while the packet is still on `br0`, but we only know the
destination IP address after the packet has gone through kube-proxy's
iptables rules, which necessarily happens after the packet leaves
`br0`. So the OVS-based egress firewall rules on `br0` won't catch
pod-to-Service-IP-to-forbidden-endpoint, and we can't write
post-kube-proxy iptables rules to catch them either since we don't
know what namespace the packet came from at that point so we don't
know what destinations to forbid. So instead, we just filter out the
"bad" endpoints so kube-proxy never sees them.

(We previously considered trying to do the filtering on the other end,
by having the code that writes out the egress firewall OVS flows also
check the endpoints of each service, and if it finds a service with
illegal endpoints, it would add a rule blocking connections to that
service. But this is racy; if the node code and the proxy code don't
make their changes exactly in sync, then after you added an illegal
endpoint to a service, there might be a period where the node code
still thinks it's acceptable to let the packets through, but the proxy
code has already been updated to use the illegal endpoint.)

(Note that ovn-kubernetes does not need to have special handling for
egress firewall like this, because it implements service proxying
itself, so it's able to rewrite the packet from the service IP to the
endpoint IP first, and then check the egress firewall ACLs after that,
while still knowing where the packet originally came from.)

## Unidling

### Theory of Idling / Unidling

From an end-user perspective, the idea of idling/unidling is this: if
you have lots of services in a cluster that are not receiving traffic,
you may want to reclaim the CPU/RAM/etc used by that service's pods,
until that service is needed again. OpenShift lets you do this by
running `oc idle SERVICENAME` (and there are some external projects
that try to automatically identify services to be idled). After doing
that, the service's pods will be killed, but the service IP will
continue to accept connections. The next time someone connects to the
service (either from inside the cluster or via a load balancer, etc),
OpenShift will "pause" the incoming connection and launch new endpoint
pods for the service. Once the pods are running, OpenShift will let
the connection through. The only thing the client should notice is
that the initial connection took longer than normal to establish.

### Backend Details

When a service is idled, `oc` finds a Deployment,
ReplicationController, etc, associated with the Service, and scales it
down to 0. Then it annotates the service with the
`"idling.alpha.openshift.io/idled-at"` annotation, indicating that it
is idled (and when it happened).

The network plugin / service proxy is expected to notice the idle
annotation, and treat the service specially, so that even though it
has no endpoints, it will still accept connections to its service IP.

Later, when the network plugin / service proxy detects an incoming
connection to the service IP, it emits an Event with the Reason
`"NeedPods"` and a reference to the service in question.

This Event is then noticed by `openshift-controller-manager`, which
will create the necessary pods, and remove the `idled-at` annotation
from the pod. The network plugin, after emitting the event, waits for
the service's endpoints to be updated, rewrites the service proxying
rules to point to the new pods, and arranges for any pending
connections to go through.

#### Legacy Idling Note

Originally `oc` annotated the `Endpoints` object with the `idled-at`
annotation, not the `Service`, but as we started porting things to use
`EndpointSlice` rather than `Endpoints`, this became awkward, since
you don't want to have to watch both `Endpoints` and `EndpointSlice`.
So a few releases ago, `oc` was changed to annotate both the
`Endpoints` (for backward compatibility) and the `Service` (for use by
newer code), and the proxy was updated to watch for the `Service`
annotation rather than the `Endpoints` annotation, and likewise
openshift-controller-manager removes both of them.

However, this can lead to problems if someone tries to idle a service
using a very old `oc` binary against a new cluster: `oc idle` will
still scale down the service, but openshift-sdn won't see any
annotation on the Service, and so won't realize that the service is
supposed to be idled.

## Unidling in OpenShift SDN

OpenShift SDN's implementation of unidling is... quirky. Basically, we
run the iptables kube-proxy to handle non-idle services, but we _also_
run a modified version of the userspace kube-proxy in parallel, to
handle idled services. This is implemented by two additional proxy
implementations, the unidling proxy (a variant of the userspace
proxy that implements unidling) and the hybrid proxy (a wrapper proxy
which handles the details of moving services between the iptables and
unidling proxies as needed).

So, when `oc` marks a service as idled, the hybrid proxy will see this
and:

  - It will tell the iptables proxy that the service has been deleted,
    causing the iptables proxy to remove its rules for that service.

  - It will tell the unidling proxy that the service has been created,
    causing the unidling proxy to create rules for that service.

The ordinary behavior of the userspace proxy for proxying a service is
that it creates a listening socket on a random port, and then
redirects traffic from the Service IP to that listening port. When it
receives a connection on that port, it makes an outbound connection to
one of the service endpoints, and then manually moves data back and
forth between the two sockets, until one of them is closed, at which
point it also closes the other.

The unidling proxy modifies this behavior slightly; when accepting a
connection, instead of just trying to proxy to the connection's
endpoints right away, it instead emits the `"NeedPods"` event, and
then waits for endpoints to appear, and _then_ starts proxying to
one of them.

After the event is emitted, `openshift-controller-manager` should
eventually launch new endpoint pods and mark the service as not idled.
The hybrid proxier will notice this and:

  - It will tell the unidling proxy that the service has been deleted.
    This causes the unidling proxy to delete its iptables rule for the
    Service IP, and close its listening socket for the service, but it
    does not affect any previously-accepted connections; it will
    continue to proxy packets back and forth for those connections
    until they are closed.

  - It will tell the iptables proxy that the service has been created,
    causing it to create rules for that service.

Endpoints/EndpointSlice events are normally sent only to the iptables
proxy (since the unidling proxy only deals with services that have no
endpoints). However, during the unidling process, the unidling proxy
needs to know about the service's endpoints so that it knows where to
redirect the traffic to. Thus, the hybrid proxier will send
Endpoints/EndpointSlice events to the unidling proxy for a short time
after unidling a service.

Note that one side effect of this implementation is that the initial
connection that causes unidling does not get checked against
NetworkPolicy, because from OVS's point of view, the connection came
from the node itself (because it's coming from the unidling proxy code
in the openshift-sdn-node process). This is considered a bug but we
never got around to fixing it. `oc idle` warns users about this.

### HybridProxier Synchronization

The hybrid proxier does one other thing: it goes out of its way to
keep the iptables and unidling proxies in sync, by forcing them to use
the same `BoundedFrequencyRunner`, such that they will always both run
their rule-updating threads at the same time. (Without this, they
might update out of sync, and there could be a gap of a few seconds
where neither proxy was accepting connections for a service.) This is
implemented by adding some additional methods to the iptables and
userspace proxiers via another carry patch in our branches of
`openshift/kubernetes`.

