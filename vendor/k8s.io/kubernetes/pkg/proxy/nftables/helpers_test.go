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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/danwinship/nftables"
	"github.com/google/go-cmp/cmp"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	netutils "k8s.io/utils/net"
)

// getLine returns the line number of the caller, if possible.  This is useful in
// tests with a large number of cases - when something goes wrong you can find
// which case more easily.
func getLine() int {
	_, _, line, ok := runtime.Caller(1)
	if ok {
		return line
	}
	return 0
}

// objectOrder defines the order we sort different types into (higher = earlier); while
// not necessarily just for comparison purposes, it's more intuitive in the Diff output to
// see rules/sets/maps before chains/elements.
var objectOrder = map[string]int{
	"table":   10,
	"chain":   9,
	"rule":    8,
	"set":     7,
	"map":     6,
	"element": 5,
	// anything else: 0
}

// sortNFTablesTransaction sorts an nftables transaction into a standard order for comparison
func sortNFTablesTransaction(tx string) string {
	lines := strings.Split(tx, "\n")

	// strip blank lines and comments
	for i := 0; i < len(lines); {
		if lines[i] == "" || lines[i][0] == '#' {
			lines = append(lines[:i], lines[i+1:]...)
		} else {
			i++
		}
	}

	// sort remaining lines
	sort.SliceStable(lines, func(i, j int) bool {
		li := lines[i]
		wi := strings.Split(li, " ")
		lj := lines[j]
		wj := strings.Split(lj, " ")

		// All lines will start with "add OBJECTTYPE ip kube-proxy". Everything
		// except "add table" will have an object name after the table name, and
		// "add table" will have a comment after the table name. So every line
		// should have at least 5 words.
		if len(wi) < 5 || len(wj) < 5 {
			return false
		}

		// Sort by object type first.
		if wi[1] != wj[1] {
			return objectOrder[wi[1]] >= objectOrder[wj[1]]
		}

		// Sort by object name when object type is identical.
		if wi[4] != wj[4] {
			return wi[4] < wj[4]
		}

		// Leave rules in the order they were originally added.
		if wi[1] == "rule" {
			return false
		}

		// Sort by the whole line when object type and name is identical. (e.g.,
		// individual "add rule" and "add element" lines in a chain/set/map.)
		return li < lj
	})
	return strings.Join(lines, "\n")
}

// assertNFTablesTransactionEqual asserts that expected and result are equal, ignoring
// irrelevant differences.
func assertNFTablesTransactionEqual(t *testing.T, line int, expected, result string) {
	expected = sortNFTablesTransaction(expected)
	result = sortNFTablesTransaction(result)

	diff := cmp.Diff(expected, result)
	if diff != "" {
		lineStr := ""
		if line != 0 {
			lineStr = fmt.Sprintf(" (from line %d)", line)
		}
		t.Errorf("tables do not match%s:\ndiff:\n%s\nfull result: %+v", lineStr, diff, result)
	}
}

// assertNFTablesChainEqual asserts that the indicated chain in nft's table contains
// exactly the rules in expected (in that order).
func assertNFTablesChainEqual(t *testing.T, line int, nft *nftables.Fake, chain, expected string) {
	expected = strings.TrimSpace(expected)
	result := ""
	if ch := nft.Table.Chains[chain]; ch != nil {
		for i, rule := range ch.Rules {
			if i > 0 {
				result += "\n"
			}
			result += rule.Rule
		}
	}

	lineStr := ""
	if line != 0 {
		lineStr = fmt.Sprintf(" (from line %d)", line)
	}
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("rules do not match%s:\ndiff:\n%s\nfull result:\n```\n%s```", lineStr, diff, result)
	}
}

// nftablesTracer holds data used while virtually tracing a packet through a set of
// iptables rules
type nftablesTracer struct {
	nft     *nftables.Fake
	nodeIPs sets.Set[string]
	t       *testing.T

	// matches accumulates the list of rules that were matched, for debugging purposes.
	matches []string

	// outputs accumulates the list of matched terminal rule targets (endpoint
	// IP:ports, or a special target like "REJECT") and is eventually used to generate
	// the return value of tracePacket.
	outputs []string

	// markMasq tracks whether the packet has been marked for masquerading
	markMasq bool
}

// newNFTablesTracer creates an nftablesTracer. nodeIPs are the IP to treat as local node
// IPs (for determining whether rules with "fib saddr type local" or "fib daddr type
// local" match).
func newNFTablesTracer(t *testing.T, nft *nftables.Fake, nodeIPs []string) *nftablesTracer {
	return &nftablesTracer{
		nft:     nft,
		nodeIPs: sets.New(nodeIPs...),
		t:       t,
	}
}

func (tracer *nftablesTracer) addressMatches(ipStr, not, ruleAddress string) bool {
	ip := netutils.ParseIPSloppy(ipStr)
	if ip == nil {
		tracer.t.Fatalf("Bad IP in test case: %s", ipStr)
	}

	var match bool
	if strings.Contains(ruleAddress, "/") {
		_, cidr, err := netutils.ParseCIDRSloppy(ruleAddress)
		if err != nil {
			tracer.t.Errorf("Bad CIDR in kube-proxy output: %v", err)
		}
		match = cidr.Contains(ip)
	} else {
		ip2 := netutils.ParseIPSloppy(ruleAddress)
		if ip2 == nil {
			tracer.t.Errorf("Bad IP/CIDR in kube-proxy output: %s", ruleAddress)
		}
		match = ip.Equal(ip2)
	}

	if not == "!= " {
		return !match
	} else {
		return match
	}
}

// matchDestIPOnly checks an "ip daddr" against a set/map, and returns the matching
// Element, if found.
func (tracer *nftablesTracer) matchDestIPOnly(elements []*nftables.Element, destIP string) *nftables.Element {
	for _, element := range elements {
		if element.Key[0] == destIP {
			return element
		}
	}
	return nil
}

// matchDest checks an "ip daddr . ip protocol . th dport" against a set/map, and returns
// the matching Element, if found.
func (tracer *nftablesTracer) matchDest(elements []*nftables.Element, destIP, protocol, destPort string) *nftables.Element {
	for _, element := range elements {
		if element.Key[0] == destIP && element.Key[1] == protocol && element.Key[2] == destPort {
			return element
		}
	}
	return nil
}

// matchDestAndSource checks an "ip daddr . ip protocol . th dport . ip saddr" against a
// set/map, where the source is allowed to be a CIDR, and returns the matching Element, if
// found.
func (tracer *nftablesTracer) matchDestAndSource(elements []*nftables.Element, destIP, protocol, destPort, sourceIP string) *nftables.Element {
	for _, element := range elements {
		if element.Key[0] == destIP && element.Key[1] == protocol && element.Key[2] == destPort && tracer.addressMatches(sourceIP, "", element.Key[3]) {
			return element
		}
	}
	return nil
}

// matchDestPort checks an "ip protocol . th dport" against a set/map, and returns the
// matching Element, if found.
func (tracer *nftablesTracer) matchDestPort(elements []*nftables.Element, protocol, destPort string) *nftables.Element {
	for _, element := range elements {
		if element.Key[0] == protocol && element.Key[1] == destPort {
			return element
		}
	}
	return nil
}

var commentRegexp = regexp.MustCompile(` *comment.*$`)

var ignoredRuleRegexp = regexp.MustCompile(`(^ct state invalid drop$|^continue$|@KUBE-AFF)`)

var masqueradeRegexp = regexp.MustCompile(`^jump ` + kubeMarkMasqChain + `$`)
var jumpRegexp = regexp.MustCompile(`^(jump|goto) (\S+)$`)
var verdictRegexp = regexp.MustCompile(`^(drop|reject)$`)
var returnRegexp = regexp.MustCompile(`^return$`)

var destAddrRegexp = regexp.MustCompile(`^ip6* daddr (!= )?(\S+)`)
var destAddrLocalRegexp = regexp.MustCompile(`^fib daddr type local`)
var destNonLocalInterfaceRegexp = regexp.MustCompile(`fib oif != "lo"`)
var destPortRegexp = regexp.MustCompile(`^(tcp|udp|sctp) dport (\d+)`)

var sourceAddrRegexp = regexp.MustCompile(`^ip6* saddr (!= )?(\S+)`)
var sourceAddrLocalRegexp = regexp.MustCompile(`^fib saddr type local`)

var dnatRegexp = regexp.MustCompile(`^ip6* protocol (tcp|udp|sctp) dnat to (\S+)$`)

var endpointVMAPRegexp = regexp.MustCompile(`^numgen random mod \d+ vmap \{(.*)\}$`)
var endpointVMapEntryRegexp = regexp.MustCompile(`\d+ : goto (\S+)`)

var destIPOnlyLookupRegexp = regexp.MustCompile(`^ip6* daddr @(\S+)`)
var destLookupRegexp = regexp.MustCompile(`^ip6* daddr \. ip6* protocol \. th dport @(\S+)`)
var destSourceLookupRegexp = regexp.MustCompile(`^ip6* daddr \. ip6* protocol \. th dport \. ip6* saddr @(\S+)`)
var destPortLookupRegexp = regexp.MustCompile(`^ip6* protocol \. th dport @(\S+)`)

var destDispatchRegexp = regexp.MustCompile(`^ip6* daddr \. ip6* protocol \. th dport vmap @(\S+)$`)
var destPortDispatchRegexp = regexp.MustCompile(`^ip6* protocol \. th dport vmap @(\S+)$`)

// runChain runs the given packet through the rules in the given table and chain, updating
// tracer's internal state accordingly. It returns true if it hits a terminal action.
func (tracer *nftablesTracer) runChain(chname, sourceIP, protocol, destIP, destPort string) bool {
	ch := tracer.nft.Table.Chains[chname]
	if ch == nil {
		tracer.t.Errorf("unknown chain %q", chname)
		return true
	}

	for _, ruleObj := range ch.Rules {
		rule := ruleObj.Rule

		// Ignore comments
		rule = commentRegexp.ReplaceAllLiteralString(rule, "")

		// The trace tests only check new connections, so this is a no-op
		rule = strings.TrimPrefix(rule, "ct state new ")

		if ignoredRuleRegexp.MatchString(rule) {
			continue
		}

		for rule != "" {
			rule = strings.TrimLeft(rule, " ")

			switch {
			case destIPOnlyLookupRegexp.MatchString(rule):
				// `^ip6* daddr @(\S+)`
				match := destIPOnlyLookupRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				set := match[1]
				if tracer.matchDestIPOnly(tracer.nft.Table.Sets[set].Elements, destIP) == nil {
					rule = ""
					break
				}

			case destSourceLookupRegexp.MatchString(rule):
				// `^ip6* daddr . ip6* protocol . th dport . ip6* saddr @(\S+)`
				match := destSourceLookupRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				set := match[1]
				if tracer.matchDestAndSource(tracer.nft.Table.Sets[set].Elements, destIP, protocol, destPort, sourceIP) == nil {
					rule = ""
					break
				}

			case destLookupRegexp.MatchString(rule):
				// `^ip6* daddr . ip6* protocol . th dport @(\S+)`
				match := destLookupRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				set := match[1]
				if tracer.matchDest(tracer.nft.Table.Sets[set].Elements, destIP, protocol, destPort) == nil {
					rule = ""
					break
				}

			case destPortLookupRegexp.MatchString(rule):
				// `^ip6* protocol . th dport @(\S+)`
				match := destPortLookupRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				set := match[1]
				if tracer.matchDestPort(tracer.nft.Table.Sets[set].Elements, protocol, destPort) == nil {
					rule = ""
					break
				}

			case destDispatchRegexp.MatchString(rule):
				// `^ip6* daddr \. ip6* protocol \. th dport vmap @(\S+)$`
				match := destDispatchRegexp.FindStringSubmatch(rule)
				mapName := match[1]
				element := tracer.matchDest(tracer.nft.Table.Maps[mapName].Elements, destIP, protocol, destPort)
				if element == nil {
					rule = ""
					break
				} else {
					rule = element.Value[0]
				}

			case destPortDispatchRegexp.MatchString(rule):
				// `^ip6* protocol \. th dport vmap @(\S+)$`
				match := destPortDispatchRegexp.FindStringSubmatch(rule)
				mapName := match[1]
				element := tracer.matchDestPort(tracer.nft.Table.Maps[mapName].Elements, protocol, destPort)
				if element == nil {
					rule = ""
					break
				} else {
					rule = element.Value[0]
				}

			case destAddrRegexp.MatchString(rule):
				// `^ip6* daddr (!= )?(\S+)`
				match := destAddrRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				not, ip := match[1], match[2]
				if !tracer.addressMatches(destIP, not, ip) {
					rule = ""
					break
				}

			case destAddrLocalRegexp.MatchString(rule):
				// `^fib daddr type local`
				match := destAddrLocalRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				if !tracer.nodeIPs.Has(destIP) {
					rule = ""
					break
				}

			case destNonLocalInterfaceRegexp.MatchString(rule):
				// `^fib oif != "lo"`
				match := destNonLocalInterfaceRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				if destIP == "127.0.0.1" || destIP == "::1" {
					rule = ""
					break
				}

			case destPortRegexp.MatchString(rule):
				// `^(tcp|udp|sctp) dport (\d+)`
				match := destPortRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				proto, port := match[1], match[2]
				if protocol != proto || destPort != port {
					rule = ""
					break
				}

			case sourceAddrRegexp.MatchString(rule):
				// `^ip6* saddr (!= )?(\S+)`
				match := sourceAddrRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				not, ip := match[1], match[2]
				if !tracer.addressMatches(sourceIP, not, ip) {
					rule = ""
					break
				}

			case sourceAddrLocalRegexp.MatchString(rule):
				// `^fib saddr type local`
				match := sourceAddrLocalRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				if !tracer.nodeIPs.Has(sourceIP) {
					rule = ""
					break
				}

			case masqueradeRegexp.MatchString(rule):
				// `^jump KUBE-MARK-MASQ$`
				match := jumpRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])

				tracer.matches = append(tracer.matches, ruleObj.Rule)
				tracer.markMasq = true

			case jumpRegexp.MatchString(rule):
				// `^(jump|goto) (\S+)$`
				match := jumpRegexp.FindStringSubmatch(rule)
				rule = strings.TrimPrefix(rule, match[0])
				action, destChain := match[1], match[2]

				tracer.matches = append(tracer.matches, ruleObj.Rule)
				terminated := tracer.runChain(destChain, sourceIP, protocol, destIP, destPort)
				if terminated {
					return true
				} else if action == "goto" {
					return false
				}

			case verdictRegexp.MatchString(rule):
				// `^(drop|reject)$`
				match := verdictRegexp.FindStringSubmatch(rule)
				verdict := match[1]

				tracer.matches = append(tracer.matches, ruleObj.Rule)
				tracer.outputs = append(tracer.outputs, strings.ToUpper(verdict))
				return true

			case returnRegexp.MatchString(rule):
				// `^return$`
				tracer.matches = append(tracer.matches, ruleObj.Rule)
				return false

			case dnatRegexp.MatchString(rule):
				// `ip6* protocol (tcp|udp|sctp) dnat to (\S+)`
				match := dnatRegexp.FindStringSubmatch(rule)
				destChain := match[2]

				tracer.matches = append(tracer.matches, ruleObj.Rule)
				tracer.outputs = append(tracer.outputs, destChain)
				return true

			case endpointVMAPRegexp.MatchString(rule):
				// `^numgen random mod \d+ vmap \{(.*)\}$`
				match := endpointVMAPRegexp.FindStringSubmatch(rule)
				elements := match[1]

				for _, match = range endpointVMapEntryRegexp.FindAllStringSubmatch(elements, -1) {
					// `\d+ : goto (\S+)`
					destChain := match[1]

					tracer.matches = append(tracer.matches, ruleObj.Rule)
					tracer.runChain(destChain, sourceIP, protocol, destIP, destPort)
				}
				return true

			default:
				tracer.t.Errorf("unmatched rule: %s", ruleObj.Rule)
				rule = ""
			}
		}
	}

	return false
}

// tracePacket determines what would happen to a packet with the given sourceIP, destIP,
// and destPort, given the indicated iptables ruleData. nodeIPs are the local node IPs (for
// rules matching "local"). (The protocol value should be lowercase as in nftables
// rules, not uppercase as in corev1.)
//
// The return values are: an array of matched rules (for debugging), the final packet
// destinations (a comma-separated list of IPs, or one of the special targets "ACCEPT",
// "DROP", or "REJECT"), and whether the packet would be masqueraded.
func tracePacket(t *testing.T, nft *nftables.Fake, sourceIP, protocol, destIP, destPort string, nodeIPs []string) ([]string, string, bool) {
	tracer := newNFTablesTracer(t, nft, nodeIPs)

	// Collect "base chains" (ie, the chains that are run by netfilter directly rather
	// than only being run when they are jumped to). Skip postrouting because it only
	// does masquerading and we handle that separately.
	var baseChains []string
	for chname, ch := range nft.Table.Chains {
		if ch.Priority != nil && chname != "nat-postrouting" {
			baseChains = append(baseChains, chname)
		}
	}

	// Sort by priority
	sort.Slice(baseChains, func(i, j int) bool {
		// FIXME: IPv4 vs IPv6 doesn't actually matter here
		iprio, _ := nftables.ParsePriority(nftables.IPv4Family, string(*nft.Table.Chains[baseChains[i]].Priority))
		jprio, _ := nftables.ParsePriority(nftables.IPv4Family, string(*nft.Table.Chains[baseChains[j]].Priority))
		return iprio < jprio
	})

	for _, chname := range baseChains {
		terminated := tracer.runChain(chname, sourceIP, protocol, destIP, destPort)
		if terminated {
			break
		}
	}

	return tracer.matches, strings.Join(tracer.outputs, ", "), tracer.markMasq
}

type packetFlowTest struct {
	name     string
	sourceIP string
	protocol v1.Protocol
	destIP   string
	destPort int
	output   string
	masq     bool
}

func runPacketFlowTests(t *testing.T, line int, nft *nftables.Fake, nodeIPs []string, testCases []packetFlowTest) {
	lineStr := ""
	if line != 0 {
		lineStr = fmt.Sprintf(" (from line %d)", line)
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			protocol := strings.ToLower(string(tc.protocol))
			if protocol == "" {
				protocol = "tcp"
			}
			matches, output, masq := tracePacket(t, nft, tc.sourceIP, protocol, tc.destIP, fmt.Sprintf("%d", tc.destPort), nodeIPs)
			var errors []string
			if output != tc.output {
				errors = append(errors, fmt.Sprintf("wrong output: expected %q got %q", tc.output, output))
			}
			if masq != tc.masq {
				errors = append(errors, fmt.Sprintf("wrong masq: expected %v got %v", tc.masq, masq))
			}
			if errors != nil {
				t.Errorf("Test %q of a packet from %s to %s:%d%s got result:\n%s\n\nBy matching:\n%s\n\n",
					tc.name, tc.sourceIP, tc.destIP, tc.destPort, lineStr, strings.Join(errors, "\n"), strings.Join(matches, "\n"))
			}
		})
	}
}
