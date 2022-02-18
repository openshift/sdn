package main

import (
	"os"

	"k8s.io/component-base/cli"

	"github.com/openshift/sdn/pkg/cmd/openshift-sdn-node"
)

func main() {
	cmd := openshift_sdn_node.NewOpenShiftSDNCommand("openshift-sdn-node", os.Stderr)
	code := cli.Run(cmd)
	os.Exit(code)
}
