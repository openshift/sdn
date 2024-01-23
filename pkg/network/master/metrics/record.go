package metrics

// contains all controller/master metric data updates

// RecordEgressFirewallCount records the number of kind EgressNetworkPolicy
func RecordEgressFirewallCount(count float64) {
	metricEgressFirewallCount.Set(count)
}

// RecordEgressFirewallRuleCount records the number of Egress firewall rules.
// Represents the sum of all egress rules for kind EgressNetworkPolicy.
func RecordEgressFirewallRuleCount(count float64) {
	metricEgressFirewallRuleCount.Set(count)
}

// RecordEgressIPCount records the number of active Egress IPs.
// This may include multiple Egress IPs for kind EgressIP.
func RecordEgressIPCount(count float64) {
	metricEgressIPCount.Set(count)
}

// RecordMulticastEnabledNamespaceCount records the number of namespaces with multicast enabled.
func RecordMulticastEnabledNamespaceCount(count float64) {
	metricMulticastEnabledNamespaceCount.Set(count)
}
