package main

import (
	goflag "flag"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/pflag"

	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"

	"github.com/openshift/sdn/pkg/cmd/openshift-sdn-node"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	rand.Seed(time.Now().UTC().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	cmd := openshift_sdn_node.NewOpenShiftSDNCommand("openshift-sdn-node", os.Stderr)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
