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
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utiliptablestesting "k8s.io/kubernetes/pkg/util/iptables/testing"
)

// Table represents an nftables Table
type Table struct {
	Comment *string
	Chains  map[string]*Chain
	Sets    map[string]*Set
	Maps    map[string]*Map
}

// Chain represents an nftables Chain
type Chain struct {
	Comment     *string
	Type        *string
	Hook        *string
	Priority    *string
	NumPriority *int

	Rules []string
}

// Set represents an nftables Set
type Set struct {
	Comment *string
	Type    string
	Flags   []string
	Timeout *string

	Elements sets.Set[string]
}

// Map represents an nftables Map
type Map struct {
	Comment *string
	Type    string
	Flags   []string

	Elements map[string]string
}

// Fake is a fake implementation of Interface
type Fake struct {
	ipt utiliptables.Interface

	// Tables contains the defined tables, keyed by family+" "+name
	Tables map[string]*Table
}

func NewFake() *Fake {
	return &Fake{
		ipt:    utiliptablestesting.NewFake(),
		Tables: make(map[string]*Table),
	}
}

var _ Interface = &Fake{}

// Present is part of Interface.
func (fake *Fake) Present() bool {
	return true
}

// List is part of Interface.
func (fake *Fake) List(family Family, table, objType string) (map[string]int, error) {
	return nil, nil
}

// NewTransaction is part of Interface
func (fake *Fake) NewTransaction() *Transaction {
	return &Transaction{
		defines: map[string]string{},
	}
}

// wordRegex matches a single word, a quoted string, or a semicolon
var wordRegex = regexp.MustCompile(`("[^"]*"|[^ ";]+|;)`)

// Split a command into "words" (where a quoted string is a single word).
func splitCommand(cmd string) []string {
	var words []string
	for _, match := range wordRegex.FindAllStringSubmatch(cmd, -1) {
		words = append(words, match[1])
	}
	return words
}

// Run is part of Interface
func (fake *Fake) Run(tx *Transaction) error {
	str := string(tx.b.Bytes())
	for name, value := range tx.defines {
		str = strings.ReplaceAll(str, "$"+name, value)
	}

	// Run the commands
	for _, cmd := range strings.Split(str, "\n") {
		if cmd == "" || cmd[0] == '#' {
			continue
		}

		words := splitCommand(cmd)
		nw := len(words)
		action := words[0] + " " + words[1]
		tableName := words[2] + " " + words[3]
		table := fake.Tables[tableName]
		if table == nil && action != "add table" {
			return fmt.Errorf("no such table %q", tableName)
		}

		switch action {
		case "add table":
			if table != nil {
				continue
			}
			table = &Table{
				Chains: make(map[string]*Chain),
				Sets:   make(map[string]*Set),
				Maps:   make(map[string]*Map),
			}
			if nw == 9 && words[4] == "{" && words[5] == "comment" && words[7] == ";" && words[8] == "}" {
				unquoted := strings.Trim(words[6], `"`)
				table.Comment = &unquoted
			}
			fake.Tables[tableName] = table
			continue
		case "delete table":
			delete(fake.Tables, tableName)
			continue
		}

		objName := words[4]
		switch action {
		case "add chain":
			if table.Chains[objName] != nil {
				continue
			}
			ch := &Chain{
				Rules: []string{},
			}
			if nw > 8 && words[5] == "{" {
				numBaseChainParams := 0
				for w := 6; w < nw-3; {
					switch words[w] {
					case "}":
						break
					case ";":
						w += 1
					case "comment":
						unquoted := strings.Trim(words[w+1], `"`)
						ch.Comment = &unquoted
						w += 2
					case "type":
						ch.Type = &words[w+1]
						w += 2
						numBaseChainParams++
					case "hook":
						ch.Hook = &words[w+1]
						w += 2
						numBaseChainParams++
					case "priority":
						ch.Priority = &words[w+1]
						priority, err := parsePriority(words[2], *ch.Priority)
						if err != nil {
							return err
						}
						ch.NumPriority = &priority
						w += 2
						numBaseChainParams++
					default:
						return fmt.Errorf("unrecognized chain parameter %q", words[w])
					}
				}
				if numBaseChainParams > 0 && numBaseChainParams != 3 {
					return fmt.Errorf("base chain must specify type, hook, and priority")
				}
			}
			table.Chains[objName] = ch
		case "flush chain":
			ch := table.Chains[objName]
			if ch == nil {
				return fmt.Errorf("no such chain %q", objName)
			}
			ch.Rules = []string{}

		case "add rule":
			ch := table.Chains[objName]
			if ch == nil {
				return fmt.Errorf("no such chain %q", objName)
			}
			ch.Rules = append(ch.Rules, strings.Join(words[5:], " "))

		case "add set":
			if table.Sets[objName] != nil {
				continue
			}
			s := &Set{
				Elements: sets.New[string](),
			}
			if nw > 8 && words[5] == "{" {
				var semi int
				for w := 6; w < nw-3; w = semi+1 {
					for semi = w; semi < nw; semi++ {
						if words[semi] == ";" {
							break
						}
					}
					if semi == nw {
						return fmt.Errorf("missing ; in set declaration");
					}
					switch words[w] {
					case "}":
						break
					case "comment":
						unquoted := strings.Trim(words[w+1], `"`)
						s.Comment = &unquoted
					case "type":
						s.Type = strings.Join(words[w+1:semi], " ")
					case "flags":
						s.Flags = strings.Split(strings.Join(words[w+1:semi], ""), ",")
					case "timeout":
						timeout := strings.Join(words[w+1:semi], " ")
						s.Timeout = &timeout
					default:
						return fmt.Errorf("unrecognized set parameter %q", words[w])
					}
				}
			}
			table.Sets[objName] = s
		case "flush set":
			s := table.Sets[objName]
			if s == nil {
				return fmt.Errorf("no such set %q", objName)
			}
			s.Elements = sets.New[string]()
		case "delete set":
			s := table.Sets[objName]
			if s == nil {
				return fmt.Errorf("no such set %q", objName)
			}
			delete(table.Sets, objName)

		case "add map":
			if table.Maps[objName] != nil {
				continue
			}
			m := &Map{
				Elements: make(map[string]string),
			}
			if nw > 8 && words[5] == "{" {
				var semi int
				for w := 6; w < nw-3; w = semi+1 {
					for semi = w; semi < nw; semi++ {
						if words[semi] == ";" {
							break
						}
					}
					if semi == nw {
						return fmt.Errorf("missing ; in map declaration");
					}
					switch words[w] {
					case "}":
						break
					case "comment":
						unquoted := strings.Trim(words[w+1], `"`)
						m.Comment = &unquoted
					case "type":
						m.Type = strings.Join(words[w+1:semi], " ")
					case "flags":
						m.Flags = strings.Split(strings.Join(words[w+1:semi], ""), ",")
					default:
						return fmt.Errorf("unrecognized map parameter %q", words[w])
					}
				}
			}
			table.Maps[objName] = m
		case "flush map":
			m := table.Maps[objName]
			if m == nil {
				return fmt.Errorf("no such map %q", objName)
			}
			m.Elements = make(map[string]string)
		case "delete map":
			m := table.Maps[objName]
			if m == nil {
				return fmt.Errorf("no such map %q", objName)
			}
			delete(table.Maps, objName)

		case "add element":
			if words[5] != "{" || words[nw-1] != "}" {
				return fmt.Errorf("bad add element syntax (braces)")
			}
			if s := table.Sets[objName]; s != nil {
				s.Elements.Insert(strings.Join(words[6:nw-1], " "))
			} else if m := table.Maps[objName]; m != nil {
				var colon int
				for i, word := range words {
					if word == ":" {
						colon = i
						break
					}
				}
				if colon == 0 {
					return fmt.Errorf("bad add element syntax (colon)")
				}
				m.Elements[strings.Join(words[6:colon], " ")] = strings.Join(words[colon+1:nw-1], " ")
			} else {
				return fmt.Errorf("no such set or map %q", objName)
			}
		default:
			return fmt.Errorf("unrecognized nft command %q", cmd)
		}
	}

	return nil
}

var namedPriorities = map[string]int{
	"raw":      -300,
	"mangle":   -150,
	"dstnat":   -100,
	"filter":   0,
	"security": 50,
	"srcnat":   100,
}

var bridgeNamedPriorities = map[string]int{
	"dstnat": -300,
	"filter": -200,
	"out":    100,
	"srcnat": 300,
}

// FIXME: support "dstnat-1" etc
func parsePriority(family, priority string) (int, error) {
	num, err := strconv.Atoi(priority)
	if err == nil {
		return num, err
	}

	var found bool
	if family == "bridge" {
		num, found = bridgeNamedPriorities[priority]
	} else {
		num, found = namedPriorities[priority]
	}
	if found {
		return num, nil
	}
	return 0, fmt.Errorf("unrecognized priority name %q for family %q", priority, family)
}

// Dump dumps the current contents of fake, in a way that looks like an nft transaction,
// but not actually guaranteed to be usable as such. (e.g., chains may be referenced
// before they are created, etc)
func (fake *Fake) Dump() string {
	buf := &strings.Builder{}

	for _, tname := range sets.List(sets.KeySet(fake.Tables)) {
		table := fake.Tables[tname]
		fmt.Fprintf(buf, "add table %s", tname)
		if table.Comment != nil {
			fmt.Fprintf(buf, " { comment %q ; }", *table.Comment)
		}
		fmt.Fprintf(buf, "\n")

		for _, cname := range sets.List(sets.KeySet(table.Chains)) {
			ch := table.Chains[cname]
			fmt.Fprintf(buf, "add chain %s %s", tname, cname)
			if ch.Type != nil || ch.Comment != nil {
				fmt.Fprintf(buf, " { ")
				if ch.Type != nil {
					fmt.Fprintf(buf, "type %s hook %s priority %s ;",
						*ch.Type, *ch.Hook, *ch.Priority)
					if ch.Comment != nil {
						fmt.Fprintf(buf, " ")
					}
				}
				if ch.Comment != nil {
					fmt.Fprintf(buf, "comment %q ;", *ch.Comment)
				}
				fmt.Fprintf(buf, " }")
			}
			fmt.Fprintf(buf, "\n")

			for _, rule := range ch.Rules {
				fmt.Fprintf(buf, "add rule %s %s %s\n", tname, cname, rule)
			}
		}

		for _, sname := range sets.List(sets.KeySet(table.Sets)) {
			s := table.Sets[sname]
			fmt.Fprintf(buf, "add set %s %s { type %s ;", tname, sname, s.Type)
			if len(s.Flags) != 0 {
				fmt.Fprintf(buf, " flags %s ;", strings.Join(s.Flags, ","))
			}
			if s.Comment != nil {
				fmt.Fprintf(buf, " comment %q ;", *s.Comment)
			}
			fmt.Fprintf(buf, " }\n")

			for element := range s.Elements {
				fmt.Fprintf(buf, "add element %s %s { %s }\n", tname, sname, element)
			}
		}
		for _, mname := range sets.List(sets.KeySet(table.Maps)) {
			m := table.Maps[mname]
			fmt.Fprintf(buf, "add map %s %s { type %s ;", tname, mname, m.Type)
			if len(m.Flags) != 0 {
				fmt.Fprintf(buf, " flags %s ;", strings.Join(m.Flags, ","))
			}
			if m.Comment != nil {
				fmt.Fprintf(buf, " comment %q ;", *m.Comment)
			}
			fmt.Fprintf(buf, " }\n")


			for key, val := range m.Elements {
				fmt.Fprintf(buf, "add element %s %s { %s : %s }\n", tname, mname, key, val)
			}
		}
	}

	return buf.String()
}

// legacy utiliptables.Interface stuff

// EnsureChain is part of utiliptables.Interface
func (fake *Fake) EnsureChain(table utiliptables.Table, chain utiliptables.Chain) (bool, error) {
	return fake.ipt.EnsureChain(table, chain)
}

// EnsureRule is part of utiliptables.Interface
func (fake *Fake) EnsureRule(position utiliptables.RulePosition, table utiliptables.Table, chain utiliptables.Chain, args ...string) (bool, error) {
	return fake.ipt.EnsureRule(position, table, chain, args...)
}

// DeleteRule is part of utiliptables.Interface
func (fake *Fake) DeleteRule(table utiliptables.Table, chain utiliptables.Chain, args ...string) error {
	return fake.ipt.DeleteRule(table, chain, args...)
}

// SaveInto is part of utiliptables.Interface
func (fake *Fake) SaveInto(table utiliptables.Table, buffer *bytes.Buffer) error {
	return fake.ipt.SaveInto(table, buffer)
}

// Restore is part of utiliptables.Interface
func (fake *Fake) Restore(table utiliptables.Table, data []byte, flush utiliptables.FlushFlag, counters utiliptables.RestoreCountersFlag) error {
	return fake.ipt.Restore(table, data, flush, counters)
}

// RestoreAll is part of utiliptables.Interface
func (fake *Fake) RestoreAll(data []byte, flush utiliptables.FlushFlag, counters utiliptables.RestoreCountersFlag) error {
	return fake.ipt.RestoreAll(data, flush, counters)
}
