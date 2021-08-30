package openshift_sdn_controller

import (
	"github.com/coreos/go-systemd/daemon"
	"github.com/spf13/cobra"

	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/serviceability"
)

type OpenShiftNetworkController struct {
}

func NewOpenShiftNetworkControllerCommand(name string) *cobra.Command {
	options := &OpenShiftNetworkController{}

	cmd := &cobra.Command{
		Use:   name,
		Short: "Start the OpenShift SDN controller",
		Long:  "Start the OpenShift SDN controller",
		Run: func(c *cobra.Command, args []string) {
			err := options.Validate()
			if err != nil {
				klog.Fatal(err)
			}

			serviceability.StartProfiler()

			if err := options.StartNetworkController(); err != nil {
				klog.Fatal(err)
			}
		},
	}

	return cmd
}

func (o *OpenShiftNetworkController) Validate() error {
	return nil
}

// StartNetworkController calls RunOpenShiftNetworkController and then waits forever
func (o *OpenShiftNetworkController) StartNetworkController() error {
	if err := RunOpenShiftNetworkController(); err != nil {
		return err
	}

	go daemon.SdNotify(false, "READY=1")
	select {}
}
