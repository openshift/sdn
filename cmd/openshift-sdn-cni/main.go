package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/openshift/sdn/pkg/cmd/openshift-sdn-cni"
	"github.com/openshift/sdn/pkg/network/common/cniserver"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	hostNS, err := ns.GetCurrentNS()
	if err != nil {
		panic(fmt.Sprintf("could not get current kernel netns: %v", err))
	}
	defer hostNS.Close()

	p := openshift_sdn_cni.NewCNIPlugin(cniserver.CNIServerSocketPath, hostNS)
	skel.PluginMain(p.CmdAdd, p.CmdDel, version.All)
}
