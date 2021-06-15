package node

import (
	"fmt"
	"os"
	"time"

	"github.com/openshift/sdn/pkg/network/node/ovs/ovsclient"
	"k8s.io/klog/v2"
)

const (
	ovsDialDefaultNetwork = "unix"
	ovsDialDefaultAddress = "/var/run/openvswitch/db.sock"
)

func healthCheckOVS() error {
	klog.Infof("Starting OVS health check")
	c, err := ovsclient.DialTimeout(ovsDialDefaultNetwork, ovsDialDefaultAddress, time.Minute)
	if err != nil {
		return fmt.Errorf("Error connecting to OVS: %v", err)
	}
	if err := c.Ping(); err != nil {
		if cErr := c.Close(); cErr != nil {
			return fmt.Errorf("Error pinging OVS, err: %v, and closing the connection, err: %v", err, cErr)
		}
		return fmt.Errorf("Error pinging OVS, err: %v", err)
	}
	go func() {
		klog.Infof("Starting SDN-OVS disconnection go-routine")
		c.WaitForDisconnect()
		klog.Errorf("Detected OVS server change, restarting")
		os.Exit(1)
	}()
	return nil
}
