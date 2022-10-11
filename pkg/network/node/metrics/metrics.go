package metrics

import (
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"
)

const (
	hostLocalDataDir = "/var/lib/cni/networks"
	SDNNamespace     = "openshift"
	SDNSubsystem     = "sdn"

	OVSFlowsKey                 = "ovs_flows"
	OVSOperationsKey            = "ovs_operations"
	ARPCacheAvailableEntriesKey = "arp_cache_entries"
	PodIPsKey                   = "pod_ips"
	PodOperationsErrorsKey      = "pod_operations_errors"
	PodOperationsLatencyKey     = "pod_operations_latency"
	VnidNotFoundErrorsKey       = "vnid_not_found_errors"
	AssignedEgressIPKey         = "assigned_egressip"
	EgressIPCapacityKey         = "egressip_capacity"

	// OVS Operation result type
	OVSOperationSuccess = "success"
	OVSOperationFailure = "failure"
	// Pod Operation types
	PodOperationSetup    = "setup"
	PodOperationTeardown = "teardown"
)

var (
	OVSFlows = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      OVSFlowsKey,
			Help:      "Number of Open vSwitch flows",
		},
	)
	OVSOperationsResult = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      OVSOperationsKey,
			Help:      "Cumulative number of OVS operations by result type",
		},
		[]string{"result_type"},
	)

	ARPCacheAvailableEntries = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      ARPCacheAvailableEntriesKey,
			Help:      "Number of available entries in the ARP cache",
		},
	)

	PodIPs = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      PodIPsKey,
			Help:      "Number of allocated pod IPs",
		},
	)

	PodOperationsErrors = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      PodOperationsErrorsKey,
			Help:      "Cumulative number of SDN operation errors by operation type",
		},
		[]string{"operation_type"},
	)

	PodOperationsLatency = metrics.NewSummaryVec(
		&metrics.SummaryOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      PodOperationsLatencyKey,
			Help:      "Latency in microseconds of SDN operations by operation type",
		},
		[]string{"operation_type"},
	)

	VnidNotFoundErrors = metrics.NewCounter(
		&metrics.CounterOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      VnidNotFoundErrorsKey,
			Help:      "Number of VNID-not-found errors",
		},
	)

	AssignedEgressIP = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      AssignedEgressIPKey,
			Help:      "Number of assigned Egress IPs on the node",
		},
	)

	EgressIPCapacity = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace: SDNNamespace,
			Subsystem: SDNSubsystem,
			Name:      EgressIPCapacityKey,
			Help:      "Egress IP capacity of the node",
		},
	)

	// num stale OVS flows (flows that reference non-existent ports)
	// num vnids (in the master)
	// num netnamespaces (in the master)
	// iptables call time (in upstream kube)
	// iptables call failures (in upstream kube)
	// iptables num rules (in upstream kube)
)

var registerMetrics sync.Once

// Register all node metrics.
func RegisterMetrics() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(OVSFlows)
		legacyregistry.MustRegister(OVSOperationsResult)
		legacyregistry.MustRegister(ARPCacheAvailableEntries)
		legacyregistry.MustRegister(PodIPs)
		legacyregistry.MustRegister(PodOperationsErrors)
		legacyregistry.MustRegister(PodOperationsLatency)
		legacyregistry.MustRegister(VnidNotFoundErrors)
		legacyregistry.MustRegister(AssignedEgressIP)
		legacyregistry.MustRegister(EgressIPCapacity)
	})
}

// SinceInMicroseconds gets the time since the specified start in microseconds.
func SinceInMicroseconds(start time.Time) float64 {
	return float64(time.Since(start) / time.Microsecond)
}

// GatherPeriodicMetrics is used to periodically gather metrics.
func GatherPeriodicMetrics() {
	updateARPMetrics()
	updatePodIPMetrics()
}

func updateARPMetrics() {
	var used int
	data, err := ioutil.ReadFile("/proc/net/arp")
	if err != nil {
		klog.Errorf("Failed to read ARP entries for metrics: %v", err)
		return
	}
	lines := strings.Split(string(data), "\n")
	// Skip the header line
	used = len(lines) - 1

	// gc_thresh2 isn't the absolute max, but it's the level at which
	// garbage collection (and thus problems) could start.
	data, err = ioutil.ReadFile("/proc/sys/net/ipv4/neigh/default/gc_thresh2")
	if err != nil && os.IsNotExist(err) {
		// gc_thresh* may not exist in some cases; don't log an error
		return
	} else if err != nil {
		klog.Errorf("Failed to read max ARP entries for metrics: %T %v", err, err)
		return
	}

	max, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err == nil {
		available := max - used
		if available < 0 {
			available = 0
		}
		ARPCacheAvailableEntries.Set(float64(available))
	} else {
		klog.Errorf("Failed to parse max ARP entries %q for metrics: %T %v", data, err, err)
	}
}

func updatePodIPMetrics() {
	numAddrs := 0
	items, err := ioutil.ReadDir(hostLocalDataDir + "/openshift-sdn/")
	if err != nil && os.IsNotExist(err) {
		// Don't log an error if the directory doesn't exist (eg, no pods started yet)
		return
	} else if err != nil {
		klog.Errorf("Failed to read pod IPs for metrics: %v", err)
	}

	for _, i := range items {
		if net.ParseIP(i.Name()) != nil {
			numAddrs++
		}
	}
	PodIPs.Set(float64(numAddrs))
}
