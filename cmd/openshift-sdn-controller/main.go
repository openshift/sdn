package main

import (
	goflag "flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/pflag"

	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"

	"github.com/openshift/sdn/pkg/cmd/openshift-sdn-controller"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	rand.Seed(time.Now().UTC().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	cmd := openshift_sdn_controller.NewOpenShiftNetworkControllerCommand("openshift-sdn-controller", os.Stdout, os.Stderr)

	if err := cmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
