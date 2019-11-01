package master

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

var ErrSubnetAllocatorFull = fmt.Errorf("no subnets available.")

type SubnetAllocator struct {
	sync.Mutex

	ranges []*subnetAllocatorRange
}

func NewSubnetAllocator() *SubnetAllocator {
	return &SubnetAllocator{}
}

func (sna *SubnetAllocator) AddNetworkRange(network string, hostBits uint32) error {
	sna.Lock()
	defer sna.Unlock()

	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}
	snr, err := newSubnetAllocatorRange(ipnet, hostBits)
	if err != nil {
		return err
	}
	sna.ranges = append(sna.ranges, snr)
	return nil
}

func (sna *SubnetAllocator) MarkAllocatedNetwork(subnet string) error {
	sna.Lock()
	defer sna.Unlock()

	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}
	for _, snr := range sna.ranges {
		if snr.markAllocatedNetwork(ipnet) {
			return nil
		}
	}
	return fmt.Errorf("network %s does not belong to any known range", subnet)
}

func (sna *SubnetAllocator) AllocateNetwork() (string, error) {
	sna.Lock()
	defer sna.Unlock()

	for _, snr := range sna.ranges {
		sn := snr.allocateNetwork()
		if sn != nil {
			return sn.String(), nil
		}
	}
	return "", ErrSubnetAllocatorFull
}

func (sna *SubnetAllocator) ReleaseNetwork(subnet string) error {
	sna.Lock()
	defer sna.Unlock()

	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}
	for _, snr := range sna.ranges {
		if snr.releaseNetwork(ipnet) {
			return nil
		}
	}
	return fmt.Errorf("network %s does not belong to any known range", subnet)
}

// subnetAllocatorRange handles allocating subnets out of a single CIDR
type subnetAllocatorRange struct {
	network    *net.IPNet
	hostBits   uint32
	leftShift  uint32
	leftMask   uint32
	rightShift uint32
	rightMask  uint32
	next       uint32
	allocMap   map[string]bool
}

func newSubnetAllocatorRange(network *net.IPNet, hostBits uint32) (*subnetAllocatorRange, error) {
	netMaskSize, _ := network.Mask.Size()
	if hostBits == 0 {
		return nil, fmt.Errorf("host capacity cannot be zero.")
	} else if hostBits > (32 - uint32(netMaskSize)) {
		return nil, fmt.Errorf("subnet capacity cannot be larger than number of networks available.")
	}
	subnetBits := 32 - uint32(netMaskSize) - hostBits

	// In the simple case, the subnet part of the 32-bit IP address is just the subnet
	// number shifted hostBits to the left. However, if hostBits isn't a multiple of
	// 8, then it can be difficult to distinguish the subnet part and the host part
	// visually. (Eg, given network="10.1.0.0/16" and hostBits=6, then "10.1.0.50" and
	// "10.1.0.70" are on different networks.)
	//
	// To try to avoid this confusion, if the subnet extends into the next higher
	// octet, we rotate the bits of the subnet number so that we use the subnets with
	// all 0s in the shared octet first. So again given network="10.1.0.0/16",
	// hostBits=6, we first allocate 10.1.0.0/26, 10.1.1.0/26, etc, through
	// 10.1.255.0/26 (just like we would with /24s in the hostBits=8 case), and only
	// if we use up all of those subnets do we start allocating 10.1.0.64/26,
	// 10.1.1.64/26, etc.
	var leftShift, rightShift uint32
	var leftMask, rightMask uint32
	if hostBits%8 != 0 && ((hostBits-1)/8 != (hostBits+subnetBits-1)/8) {
		leftShift = 8 - (hostBits % 8)
		leftMask = uint32(1)<<(32-uint32(netMaskSize)) - 1
		rightShift = subnetBits - leftShift
		rightMask = (uint32(1)<<leftShift - 1) << hostBits
	} else {
		leftShift = 0
		leftMask = 0xFFFFFFFF
		rightShift = 0
		rightMask = 0
	}

	return &subnetAllocatorRange{
		network:    network,
		hostBits:   hostBits,
		leftShift:  leftShift,
		leftMask:   leftMask,
		rightShift: rightShift,
		rightMask:  rightMask,
		next:       0,
		allocMap:   make(map[string]bool),
	}, nil
}

// markAllocatedNetwork marks network as being in use, if it is part of snr's range.
// It returns whether the network was in snr's range.
func (snr *subnetAllocatorRange) markAllocatedNetwork(network *net.IPNet) bool {
	str := network.String()
	if snr.network.Contains(network.IP) {
		snr.allocMap[str] = true
	}
	return snr.allocMap[str]
}

// allocateNetwork returns a new subnet, or nil if the range is full
func (snr *subnetAllocatorRange) allocateNetwork() *net.IPNet {
	var (
		numSubnets    uint32
		numSubnetBits uint32
	)

	baseipu := IPToUint32(snr.network.IP)
	netMaskSize, _ := snr.network.Mask.Size()
	numSubnetBits = 32 - uint32(netMaskSize) - snr.hostBits
	numSubnets = 1 << numSubnetBits

	var i uint32
	for i = 0; i < numSubnets; i++ {
		n := (i + snr.next) % numSubnets
		shifted := n << snr.hostBits
		ipu := baseipu | ((shifted << snr.leftShift) & snr.leftMask) | ((shifted >> snr.rightShift) & snr.rightMask)
		genIp := Uint32ToIP(ipu)
		genSubnet := &net.IPNet{IP: genIp, Mask: net.CIDRMask(int(numSubnetBits)+netMaskSize, 32)}
		if !snr.allocMap[genSubnet.String()] {
			snr.allocMap[genSubnet.String()] = true
			snr.next = n + 1
			return genSubnet
		}
	}

	snr.next = 0
	return nil
}

// releaseNetwork marks network as being not in use, if it is part of snr's range.
// It returns whether the network was in snr's range.
func (snr *subnetAllocatorRange) releaseNetwork(network *net.IPNet) bool {
	if !snr.network.Contains(network.IP) {
		return false
	}

	snr.allocMap[network.String()] = false
	return true
}

func IPToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func Uint32ToIP(u uint32) net.IP {
	ip := make([]byte, 4)
	binary.BigEndian.PutUint32(ip, u)
	return net.IPv4(ip[0], ip[1], ip[2], ip[3])
}
