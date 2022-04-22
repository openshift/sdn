package main

import (
	"os"

	"k8s.io/component-base/cli"

	"github.com/openshift/sdn/pkg/cmd/openshift-sdn-controller"
)

func main() {
	cmd := openshift_sdn_controller.NewOpenShiftNetworkControllerCommand("openshift-sdn-controller")
	code := cli.Run(cmd)
	os.Exit(code)
}
