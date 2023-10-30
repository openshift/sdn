// Copyright 2016 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"
)

func getHwAddr(linkname string) string {
	veth, err := netlink.LinkByName(linkname)
	Expect(err).NotTo(HaveOccurred())
	return fmt.Sprintf("%s", veth.Attrs().HardwareAddr)
}

var _ = Describe("Link", func() {
	const (
		ifaceFormatString string = "i%d"
		mtu               int    = 1400
		ip4onehwaddr             = "0a:58:01:01:01:01"
	)
	var (
		hostNetNS         ns.NetNS
		containerNetNS    ns.NetNS
		ifaceCounter      int = 0
		containerVeth     net.Interface
		containerVethName string

		ip4one             = net.ParseIP("1.1.1.1")
		ip4two             = net.ParseIP("1.1.1.2")
		originalRandReader = rand.Reader
	)

	BeforeEach(func() {
		var err error

		hostNetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		containerNetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		fakeBytes := make([]byte, 20)
		//to be reset in AfterEach block
		rand.Reader = bytes.NewReader(fakeBytes)

		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, containerVeth, err = ip.SetupVeth(fmt.Sprintf(ifaceFormatString, ifaceCounter), mtu, "", hostNetNS)
			if err != nil {
				return err
			}
			Expect(err).NotTo(HaveOccurred())

			containerVethName = containerVeth.Name

			return nil
		})
	})

	AfterEach(func() {
		Expect(containerNetNS.Close()).To(Succeed())
		Expect(hostNetNS.Close()).To(Succeed())
		ifaceCounter++
		rand.Reader = originalRandReader
	})

	It("SetHWAddrByIP must change the interface hwaddr and be predictable", func() {

		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			var err error
			hwaddrBefore := getHwAddr(containerVethName)

			err = SetHWAddrByIP(containerVethName, ip4one, nil)
			Expect(err).NotTo(HaveOccurred())
			hwaddrAfter1 := getHwAddr(containerVethName)

			Expect(hwaddrBefore).NotTo(Equal(hwaddrAfter1))
			Expect(hwaddrAfter1).To(Equal(ip4onehwaddr))

			return nil
		})
	})

	It("SetHWAddrByIP must be injective", func() {

		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := SetHWAddrByIP(containerVethName, ip4one, nil)
			Expect(err).NotTo(HaveOccurred())
			hwaddrAfter1 := getHwAddr(containerVethName)

			err = SetHWAddrByIP(containerVethName, ip4two, nil)
			Expect(err).NotTo(HaveOccurred())
			hwaddrAfter2 := getHwAddr(containerVethName)

			Expect(hwaddrAfter1).NotTo(Equal(hwaddrAfter2))
			return nil
		})
	})
})
