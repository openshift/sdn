package ranges

import (
	"encoding/binary"
	"fmt"
	"net"

	networkingv1 "k8s.io/api/networking/v1"
)

// IPBlockToCIDRs returns an array of CIDRs corresponding to ipBlock.
//
// To match a NetworkPolicy IPBlock with an "Except", we need to generate the OpenFlow
// equivalent of "nw_src=${CIDR} && nw_src!=${Except}". OVS has conjunctive matches to get
// the effect of "&&", but there's no way to say "!="... The only way to make this work is
// to rewrite
//
//    nw_src=[A-H] && nw_src!=B && nw_src!=E
//
// as
//
//    nw_src=A || nw_src=[C-D] || nw_src=[F-H]
//
// except that it's more complicated than that because CIDRs can only express ranges
// whose lengths are powers of 2. So, we call rangesForIPBlock() to generate the list
// "[[A-A], [C-D], [F-H]]", and then call .toRangeMasks() on each of those ranges to turn
// them into an equivalent list of VALUE/MASK values.
func IPBlockToCIDRs(ipBlock *networkingv1.IPBlock) []string {
	if len(ipBlock.Except) == 0 {
		return []string{ipBlock.CIDR}
	}
	cidrs := []string{}
	for _, r := range rangesForIPBlock(ipBlock) {
		for _, rangeMask := range r.toRangeMasks() {
			cidr := &net.IPNet{
				IP:   uint32ToBytes(rangeMask.start),
				Mask: uint32ToBytes(rangeMask.mask),
			}
			cidrs = append(cidrs, cidr.String())
		}
	}
	return cidrs
}

func uint32ToBytes(u uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, u)
	return bytes
}

func bytesToUint32(bytes []byte) uint32 {
	if len(bytes) == 16 {
		to4 := net.IP(bytes).To4()
		if to4 != nil {
			bytes = to4
		}
	}
	return binary.BigEndian.Uint32(bytes)
}

// rangeForCIDR takes a net.IPNet and returns an intRange
func rangeForCIDR(cidr *net.IPNet) intRange {
	rangeMask := intRangeMask{
		start: bytesToUint32(cidr.IP),
		mask:  bytesToUint32(cidr.Mask),
	}
	return rangeMask.toRange()
}

// rangesForIPBlock returns an array of ipRanges corresponding to ipBlock
func rangesForIPBlock(ipBlock *networkingv1.IPBlock) []intRange {
	_, baseCIDR, _ := net.ParseCIDR(ipBlock.CIDR)
	if baseCIDR == nil {
		// can't happen
		return nil
	}
	ranges := []intRange{rangeForCIDR(baseCIDR)}

	for _, except := range ipBlock.Except {
		_, exceptCIDR, _ := net.ParseCIDR(except)
		if exceptCIDR == nil {
			// can't happen
			return nil
		}

		newRanges := make([]intRange, 0, len(ranges)+2)
		for _, r := range ranges {
			newRanges = append(newRanges, r.except(rangeForCIDR(exceptCIDR))...)
		}
		ranges = newRanges
	}

	return ranges
}

// PortRangeToPortMasks returns an array of port/mask strings corresponding to the given
// start and end values.
//
// Here the problem is that we need ">=" and "<=", which OpenFlow doesn't have. So we have
// to figure out how to express "tp_dst >= ${START} && tp_dst <= ${END}" as a series of
// "tp_dst=${VALUE}/${MASK}" matches.
//
// (The naive implementation of port range matching would be to just check tp_dst against
// each value from start to end, for a total of (end-start+1) rules. PortRangeToPortMasks
// generates the same number of rules as the naive implementation when start==end or when
// start is odd and end==start+1, but in all other cases it generates fewer total rules.)
func PortRangeToPortMasks(start, end int) []string {
	portRange := intRange{uint32(start), uint32(end)}
	rangeMasks := portRange.toRangeMasks()
	masks := make([]string, len(rangeMasks))
	for i, rm := range rangeMasks {
		masks[i] = fmt.Sprintf("0x%04x/0x%04x", uint16(rm.start), uint16(rm.mask))
	}
	return masks
}
