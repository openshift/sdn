package node

import (
	"fmt"
	"os"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/openshift/sdn/pkg/network/node/ovs/ovsclient"
)

const (
	ovsDialTimeout        = 5 * time.Second
	ovsDialDefaultNetwork = "unix"
	ovsDialDefaultAddress = "/var/run/openvswitch/db.sock"
)

// dialAndPing connects to OVS once and pings the server. It returns
// the dial error (if any) or the ping error (if any), or neither.
func dialAndPing(network, addr string) (error, error) {
	c, err := ovsclient.DialTimeout(network, addr, ovsDialTimeout)
	if err != nil {
		return err, nil
	}
	defer c.Close()
	if err := c.Ping(); err != nil {
		return nil, err
	}
	return nil, nil
}

// waitForOVS polls until the OVS server responds to a connection and an 'echo'
// command.
func waitForOVS(network, addr string) error {
	return utilwait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
		dialErr, pingErr := dialAndPing(network, addr)
		if dialErr != nil {
			klog.Warningf("waiting for OVS to start: %v", dialErr)
			return false, nil
		} else if pingErr != nil {
			klog.Warningf("waiting for OVS to start, ping failed: %v", pingErr)
			return false, nil
		}
		return true, nil
	})
}

// runOVSHealthCheck runs one background loop - one that waits for disconnection
// from the OVS server
func runOVSHealthCheck(network, addr string) {
	klog.Infof("[SDN healthcheck] starting SDN-OVS disconnection go-routine")
	go utilwait.Until(func() {
		c, err := ovsclient.DialTimeout(network, addr, ovsDialTimeout)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("[SDN healthcheck] SDN healthcheck unable to connect to OVS server: %v", err))
			return
		}
		defer c.Close()

		_ = c.WaitForDisconnect()

		klog.Errorf("[SDN healthcheck] detected OVS server change, restarting")
		os.Exit(1)
	}, ovsDialTimeout, utilwait.NeverStop)
}
