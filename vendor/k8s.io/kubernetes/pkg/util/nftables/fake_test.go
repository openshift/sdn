/*
Copyright 2023 The Kubernetes Authors.

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
	"strings"
	"testing"

	"github.com/lithammer/dedent"
)

func TestFakeRun(t *testing.T) {
	fake := NewFake()
	tx := fake.NewTransaction()

	tx.Define("FAMILY", "ip")
	tx.Define("TABLE", "kube-proxy")
	tx.Define("IP", "ip")

	tx.Write("add table $FAMILY $TABLE")
	tx.Write("add", "chain", "$FAMILY", "$TABLE", "chain", "{", "comment", `"foo"`, ";", "}")
	tx.Write("add rule",
		"$FAMILY $TABLE chain",
		"$IP daddr 10.0.0.0/8",
		"drop",
	)

	tx.Write("# This is a comment")
	tx.Write("add chain $FAMILY $TABLE anotherchain")
	tx.Write("add rule $FAMILY $TABLE anotherchain ip saddr 1.2.3.4 drop")
	tx.Write("add rule $FAMILY $TABLE anotherchain ip daddr 5.6.7.8 reject")

	err := fake.Run(tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	table := fake.Tables["ip kube-proxy"]
	if table == nil || len(fake.Tables) != 1 {
		t.Fatalf("unexpected contents of fake.Tables: %+v", fake.Tables)
	}

	chain := table.Chains["chain"]
	if chain == nil || len(table.Chains) != 2 {
		t.Fatalf("unexpected contents of table.Chains: %+v", table.Chains)
	}

	if len(chain.Rules) != 1 || chain.Rules[0] != "ip daddr 10.0.0.0/8 drop" {
		t.Fatalf("unexpected contents of chain.Rules: %+v", chain.Rules)
	}

	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy anotherchain
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		`), "\n")
	dump := fake.Dump()
	if dump != expected {
		t.Errorf("unexpected Dump content:\nexpected\n%s\n\ngot\n%s", expected, dump)
	}
}
