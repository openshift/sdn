package metrics

// contains all controller/master metric definitions and registration

import "github.com/prometheus/client_golang/prometheus"

const (
	metricSDNNamespace           = "sdn"
	metricSDNSubsystemController = "controller"
)

var metricEgressIPCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricSDNNamespace,
	Subsystem: metricSDNSubsystemController,
	Name:      "num_egress_ips",
	Help:      "The number of egress IP addresses assigned to nodes",
})

// represents kind EgressNetworkPolicy egress rules from API version network.openshift.io/v1
var metricEgressFirewallRuleCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricSDNNamespace,
	Subsystem: metricSDNSubsystemController,
	Name:      "num_egress_firewall_rules",
	Help:      "The number of egress firewall rules defined"},
)

// represents kind EgressNetworkPolicy from API version network.openshift.io/v1
var metricEgressFirewallCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricSDNNamespace,
	Subsystem: metricSDNSubsystemController,
	Name:      "num_egress_firewalls",
	Help:      "The number of egress firewall policies",
})

var registry = prometheus.NewRegistry()

func Register() {
	registry.MustRegister(metricEgressIPCount)
	registry.MustRegister(metricEgressFirewallRuleCount)
	registry.MustRegister(metricEgressFirewallCount)
}
