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
	"encoding/json"
	"fmt"

	utilexec "k8s.io/utils/exec"
)

// Family is an nftables family
type Family string

const (
	IPv4Family Family = "ip"
	IPv6Family Family = "ip6"
)

// Transaction builds up an nftables transaction
type Transaction struct {
	defines map[string]string
	b       bytes.Buffer
}

// Define adds a define ("nft -D") to the Transaction which can then be referenced as
// `$name` in the transaction body.
func (tx *Transaction) Define(name, value string) {
	tx.defines[name] = value
}

// Write takes a list of arguments, each a string or []string, joins all the
// individual strings with spaces, terminates with newline, and writes to tx.
// Any other argument type will panic.
func (tx *Transaction) Write(args ...interface{}) {
	for i, arg := range args {
		if i > 0 {
			tx.b.WriteByte(' ')
		}
		switch x := arg.(type) {
		case string:
			tx.b.WriteString(x)
		case Family:
			tx.b.WriteString(string(x))
		case []string:
			for j, s := range x {
				if j > 0 {
					tx.b.WriteByte(' ')
				}
				tx.b.WriteString(s)
			}
		default:
			panic(fmt.Sprintf("unknown argument type: %T", x))
		}
	}
	tx.b.WriteByte('\n')
}

// WriteBytes writes bytes to buffer, and terminates with newline.
func (tx *Transaction) WriteBytes(bytes []byte) {
	tx.b.Write(bytes)
	tx.b.WriteByte('\n')
}

// Bytes returns the contents of buffer, for debug purposes
func (tx *Transaction) Bytes() []byte {
	return tx.b.Bytes()
}

// Interface is an injectable interface for running nftables commands.
type Interface interface {
	// NewTransaction starts a new transaction
	NewTransaction() *Transaction

	// Run runs `nft` on the context of tx (which should not be used again afterward)
	Run(tx *Transaction) error

	// List returns a map from name to handle for all of the objects of a given type
	// (eg, "chains", "sets") that currently exist in the given table of the given
	// family
	List(family Family, table, objType string) (map[string]int, error)

	// Present checks if nftables is available
	Present() bool
}

// runner is an implementation of Interface
type runner struct {
	exec utilexec.Interface

	lastTransaction *Transaction
}

func New(exec utilexec.Interface) Interface {
	return &runner{
		exec: exec,
	}
}

// Present is part of Interface.
func (nftables *runner) Present() bool {
	cmd := nftables.exec.Command("nft", "--check", "add", "table", "testing")
	_, err := cmd.CombinedOutput()
	return err == nil
}

// NewTransaction is part of Interface
func (runner *runner) NewTransaction() *Transaction {
	var tx *Transaction
	if runner.lastTransaction != nil {
		tx = runner.lastTransaction
		runner.lastTransaction = nil
	} else {
		tx = &Transaction{
			defines: map[string]string{},
		}
	}
	return tx
}

// Run is part of Interface
func (runner *runner) Run(tx *Transaction) error {
	var args []string
	for name, value := range tx.defines {
		args = append(args, "-D", fmt.Sprintf("%s=%s", name, value))
	}
	args = append(args, "-f", "-")
	cmd := runner.exec.Command("nft", args...)
	cmd.SetStdin(&tx.b)
	b, err := cmd.CombinedOutput()

	tx.b.Reset()
	tx.defines = map[string]string{}
	runner.lastTransaction = tx

	if err != nil {
		return fmt.Errorf("failed to run nft: %s", string(b))
	}
	return nil
}

func jsonVal[T any](json map[string]interface{}, key string) (T, bool) {
	if ifVal, exists := json[key]; exists {
		tVal, ok := ifVal.(T)
		return tVal, ok
	} else {
		var zero T
		return zero, false
	}
}

// List is part of Interface.
func (runner *runner) List(family Family, table, objType string) (map[string]int, error) {
	// All currently-existing nftables object types have plural forms that are just
	// the singular form plus 's'.
	var typeSingular, typePlural string
	if objType[len(objType)-1] == 's' {
		typePlural = objType
		typeSingular = objType[:len(objType)-1]
	} else {
		typeSingular = objType
		typePlural = objType + "s"
	}

	// run and return
	cmd := runner.exec.Command("nft", "-j", "list", typePlural, string(family))
	outBuf := bytes.NewBuffer(nil)
	cmd.SetStdout(outBuf)
	errBuf := bytes.NewBuffer(nil)
	cmd.SetStderr(errBuf)

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run nft: %s", string(errBuf.Bytes()))
	}

	// outBuf contains JSON looking like:
	// {
	//   "nftables": [
	//     {
	//       "metainfo": {
	//         "json_schema_version": 1
	//         ...
	//       }
	//     },
	//     {
	//       "chain": {
	//         "family": "ip",
	//         "table": "kube_proxy",
	//         "name": "KUBE-SERVICES",
	//         "handle": 3,
	//         ...
	//       }
	//     },
	//     ...
	//   ]
	// }

	jsonResult := map[string][]map[string]map[string]interface{}{}
	if err := json.Unmarshal(outBuf.Bytes(), &jsonResult); err != nil {
		return nil, fmt.Errorf("could not parse nft output: %v", err)
	}

	nftablesResult := jsonResult["nftables"]
	if nftablesResult == nil || len(nftablesResult) == 0 {
		return nil, fmt.Errorf("could not find result in nft output %q", outBuf.Bytes())
	}
	metainfo := nftablesResult[0]["metainfo"]
	if metainfo == nil {
		return nil, fmt.Errorf("could not find metadata in nft output %q", outBuf.Bytes())
	}
	if version, ok := jsonVal[float64](metainfo, "json_schema_version"); !ok || version != 1.0 {
		return nil, fmt.Errorf("could not find supported json_schema_version in nft output %q", outBuf.Bytes())
	}

	result := make(map[string]int)
	for _, objContainer := range nftablesResult {
		obj := objContainer[typeSingular]
		if obj == nil {
			continue
		}
		objTable, _ := jsonVal[string](obj, "table")
		if objTable != table {
			continue
		}

		name, nameOK := jsonVal[string](obj, "name")
		handle, handleOK := jsonVal[float64](obj, "handle")
		if nameOK && handleOK {
			result[name] = int(handle)
		}
	}

	return result, nil
}
