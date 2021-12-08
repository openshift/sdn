package openshift_sdn_controller

import (
	"github.com/spf13/cobra"

	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/serviceability"
)

type OpenShiftNetworkController struct {
	platformType string
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
	flags := cmd.Flags()
	flags.StringVar(&options.platformType, "platform-type", "", "The cloud provider platform type openshift-sdn is deployed on")
	return cmd
}

func (o *OpenShiftNetworkController) Validate() error {
	return nil
}

// StartNetworkController calls RunOpenShiftNetworkController and then waits forever
func (o *OpenShiftNetworkController) StartNetworkController() error {
	if err := RunOpenShiftNetworkController(o.platformType); err != nil {
		return err
	}

	select {}
}
