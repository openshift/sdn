package testing

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/kubernetes/pkg/util/iptables"
)

// NodeFakeIPTables is no-op implementation of iptables Interface.
type NodeFakeIPTables struct {
	protocol iptables.Protocol
	mutex    sync.Mutex
	rules    map[string]string
	chains   map[string]interface{}
}

// NodeFakeIPTablesInterface extends iptables.Interface
type NodeFakeIPTablesInterface interface {
	iptables.Interface
	// IsPresent checks if the given rule is present in the iptables or not. If the rule existed, return true.
	IsPresent(position iptables.RulePosition, table iptables.Table, chain iptables.Chain, args ...string) bool
}

// NewFake returns a no-op iptables.Interface
func NewFake() NodeFakeIPTablesInterface {
	return &NodeFakeIPTables{protocol: iptables.ProtocolIPv4,
		rules:  make(map[string]string),
		chains: make(map[string]interface{})}
}

// NewIPv6Fake returns a no-op iptables.Interface with IsIPv6() == true
func NewIPv6Fake() NodeFakeIPTablesInterface {
	return &NodeFakeIPTables{protocol: iptables.ProtocolIPv6,
		rules:  make(map[string]string),
		chains: make(map[string]interface{})}
}

// EnsureChain is part of iptables.Interface
func (f *NodeFakeIPTables) EnsureChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	key := fmt.Sprintf("%v,%v", table, chain)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if _, ok := f.chains[key]; ok {
		return true, nil
	}
	f.chains[key] = nil
	return false, nil
}

// FlushChain is part of iptables.Interface
func (f *NodeFakeIPTables) FlushChain(table iptables.Table, chain iptables.Chain) error {
	return f.DeleteChain(table, chain)
}

// DeleteChain is part of iptables.Interface
func (f *NodeFakeIPTables) DeleteChain(table iptables.Table, chain iptables.Chain) error {
	key := fmt.Sprintf("%v,%v", table, chain)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if _, ok := f.chains[key]; !ok {
		return errors.New("chain doesn't exist")
	}
	delete(f.chains, key)
	return nil
}

// ChainExists is part of iptables.Interface
func (f *NodeFakeIPTables) ChainExists(table iptables.Table, chain iptables.Chain) (bool, error) {
	key := fmt.Sprintf("%v,%v", table, chain)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if _, ok := f.chains[key]; ok {
		return true, nil
	}
	return false, nil
}

// EnsureRule is part of iptables.Interface
func (f *NodeFakeIPTables) EnsureRule(position iptables.RulePosition, table iptables.Table, chain iptables.Chain, args ...string) (bool, error) {
	key := getRuleKey(table, chain)
	value := getRule(args...)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if rule, ok := f.rules[key]; ok && rule == value {
		return true, nil
	}
	f.rules[key] = value
	return false, nil
}

// IsPresent is part of NodeFakeIPTablesInterface
func (f *NodeFakeIPTables) IsPresent(position iptables.RulePosition, table iptables.Table, chain iptables.Chain, args ...string) bool {
	key := getRuleKey(table, chain)
	value := getRule(args...)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if rule, ok := f.rules[key]; ok && rule == value {
		return true
	}
	return false
}

// DeleteRule is part of iptables.Interface
func (f *NodeFakeIPTables) DeleteRule(table iptables.Table, chain iptables.Chain, args ...string) error {
	key := getRuleKey(table, chain)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if _, ok := f.rules[key]; ok {
		delete(f.rules, key)
	}
	return nil
}

func getRuleKey(table iptables.Table, chain iptables.Chain) string {
	return fmt.Sprintf("%v,%v", table, chain)
}

func getRule(args ...string) string {
	return strings.Join(args, ",")
}

// IsIPv6 is part of iptables.Interface
func (f *NodeFakeIPTables) IsIPv6() bool {
	return f.protocol == iptables.ProtocolIPv6
}

// Protocol is part of iptables.Interface
func (f *NodeFakeIPTables) Protocol() iptables.Protocol {
	return f.protocol
}

// SaveInto is part of iptables.Interface
func (f *NodeFakeIPTables) SaveInto(table iptables.Table, buffer *bytes.Buffer) error {
	return nil
}

// Restore is part of iptables.Interface
func (*NodeFakeIPTables) Restore(table iptables.Table, data []byte, flush iptables.FlushFlag, counters iptables.RestoreCountersFlag) error {
	return nil
}

// RestoreAll is part of iptables.Interface
func (f *NodeFakeIPTables) RestoreAll(data []byte, flush iptables.FlushFlag, counters iptables.RestoreCountersFlag) error {
	return nil
}

// Monitor is part of iptables.Interface
func (f *NodeFakeIPTables) Monitor(canary iptables.Chain, tables []iptables.Table, reloadFunc func(), interval time.Duration, stopCh <-chan struct{}) {
}

// HasRandomFully is part of iptables.Interface
func (f *NodeFakeIPTables) HasRandomFully() bool {
	return false
}

func (f *NodeFakeIPTables) Present() bool {
	return true
}
