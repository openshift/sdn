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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lithammer/dedent"

	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
)

func TestListBad(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nftOutput string
		nftError  string
		listError string
	}{
		{
			name:      "empty",
			nftOutput: ``,
			listError: "could not parse nft output",
		},
		{
			name:      "nft failure",
			nftOutput: ``,
			nftError:  "blah blah blah",
			listError: "failed to run nft: blah blah blah",
		},
		{
			name:      "bad format",
			nftOutput: `{"foo": "bar"}`,
			listError: "could not parse nft output",
		},
		{
			name:      "no result",
			nftOutput: `{"foo": []}`,
			listError: "could not find result",
		},
		{
			name:      "no result (2)",
			nftOutput: `{"nftables":[]}`,
			listError: "could not find result",
		},
		{
			name:      "no metadata",
			nftOutput: `{"nftables":[{"foo":{}}]}`,
			listError: "could not find metadata",
		},
		{
			name:      "no schema info",
			nftOutput: `{"nftables":[{"metainfo":{}}]}`,
			listError: "could not find supported json_schema_version",
		},
		{
			name:      "bad version",
			nftOutput: `{"nftables":[{"metainfo":{"json_schema_version":2}}]}`,
			listError: "could not find supported json_schema_version",
		},
		{
			name:      "bad version (2)",
			nftOutput: `{"nftables":[{"metainfo":{"json_schema_version":"one"}}]}`,
			listError: "could not find supported json_schema_version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var nftErr error
			if tc.nftError != "" {
				nftErr = fmt.Errorf("dummy")
			}
			fcmd := fakeexec.FakeCmd{
				RunScript: []fakeexec.FakeAction{
					func() ([]byte, []byte, error) { return []byte(tc.nftOutput), []byte(tc.nftError), nftErr },
				},
			}
			fexec := &fakeexec.FakeExec{
				CommandScript: []fakeexec.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return fakeexec.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			nft := New(fexec)
			result, err := nft.List(IPv4Family, "testing", "chains")
			if result != nil {
				t.Errorf("unexpected non-nil result: %v", result)
			}
			if !strings.Contains(err.Error(), tc.listError) {
				t.Errorf("unexpected error: wanted %q got %q", tc.listError, err.Error())
			}
		})
	}
}

func TestList(t *testing.T) {
	for _, tc := range []struct {
		name       string
		objType    string
		nftOutput  string
		listOutput map[string]int
	}{
		{
			name:       "empty list",
			objType:    "chains",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}]}`,
			listOutput: map[string]int{},
		},
		{
			name:      "singular objType",
			objType:   "chain",
			nftOutput: `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "testing", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "output", "handle": 3, "type": "nat", "hook": "output", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "postrouting", "handle": 7, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "KUBE-SERVICES", "handle": 11}}, {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "FOO", "handle": 3}}]}`,
			listOutput: map[string]int{
				"prerouting":    1,
				"output":        3,
				"postrouting":   7,
				"KUBE-SERVICES": 11,
			},
		},
		{
			name:      "plural objType",
			objType:   "chains",
			nftOutput: `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "testing", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "output", "handle": 3, "type": "nat", "hook": "output", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "postrouting", "handle": 7, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "KUBE-SERVICES", "handle": 11}}, {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "FOO", "handle": 3}}]}`,
			listOutput: map[string]int{
				"prerouting":    1,
				"output":        3,
				"postrouting":   7,
				"KUBE-SERVICES": 11,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fcmd := fakeexec.FakeCmd{
				RunScript: []fakeexec.FakeAction{
					func() ([]byte, []byte, error) { return []byte(tc.nftOutput), []byte{}, nil },
				},
			}
			fexec := &fakeexec.FakeExec{
				CommandScript: []fakeexec.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return fakeexec.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			nft := New(fexec)
			result, err := nft.List(IPv4Family, "testing", tc.objType)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result, tc.listOutput) {
				t.Errorf("unexpected result: wanted %v got %v", tc.listOutput, result)
			}
		})
	}
}

func TestRun(t *testing.T) {
	fcmd := fakeexec.FakeCmd{
		CombinedOutputScript: []fakeexec.FakeAction{
			func() ([]byte, []byte, error) { return []byte{}, []byte{}, nil },
		},
	}
	fexec := &fakeexec.FakeExec{
		CommandScript: []fakeexec.FakeCommandAction{
			func(cmd string, args ...string) exec.Cmd { return fakeexec.InitFakeCmd(&fcmd, cmd, args...) },
		},
	}

	nft := New(fexec)
	tx := nft.NewTransaction()
	tx2 := nft.NewTransaction()
	if tx == tx2 {
		t.Errorf("NewTransaction returned the same value twice")
	}

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

	out := string(tx.b.Bytes())

	err := nft.Run(tx)
	if err != nil {
		t.Errorf("unexpected error from Run: %v", err)
	}

	// We see what gets passed to nft, which means the defines won't be expanded.
	// Compare TestFakeRun.
	expected := strings.TrimPrefix(dedent.Dedent(`
		add table $FAMILY $TABLE
		add chain $FAMILY $TABLE chain { comment "foo" ; }
		add rule $FAMILY $TABLE chain $IP daddr 10.0.0.0/8 drop
		`), "\n")
	if out != expected {
		t.Errorf("unexpected nft stdin: expected %q got %q", expected, out)
	}

	tx3 := nft.NewTransaction()
	if tx3 != tx {
		t.Errorf("NewTransaction failed to return previous transaction")
	}
	if tx.b.Len() != 0 || len(tx.defines) != 0 {
		t.Errorf("NewTransaction returned non-empty transaction: %+v", tx)
	}
	tx2 = nft.NewTransaction()
	if tx == tx2 {
		t.Errorf("NewTransaction returned the same value twice")
	}
}
