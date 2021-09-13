package ranges

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

func mustParseCIDR(cidrString string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(cidrString)
	if err != nil {
		panic(err.Error())
	}
	return cidr
}

func Test_rangeForCIDR(t *testing.T) {
	var cidr *net.IPNet
	var r intRange
	var expectStart, expectEnd uint32

	cidr = mustParseCIDR("10.0.0.0/8")
	r = rangeForCIDR(cidr)
	expectStart = 10 * 256 * 256 * 256
	expectEnd = 11*256*256*256 - 1
	if r.start != expectStart {
		t.Fatalf("bad start %d != %d", r.start, expectStart)
	}
	if r.end != expectEnd {
		t.Fatalf("bad end %d != %d", r.end, expectEnd)
	}

	cidr = mustParseCIDR("192.168.0.0/24")
	r = rangeForCIDR(cidr)
	expectStart = 192*256*256*256 + 168*256*256
	expectEnd = 192*256*256*256 + 168*256*256 + 255
	if r.start != expectStart {
		t.Fatalf("bad start %d != %d", r.start, expectStart)
	}
	if r.end != expectEnd {
		t.Fatalf("bad end %d != %d", r.end, expectEnd)
	}
}

func parseRange(start, end string) intRange {
	r := intRange{
		start: bytesToUint32(net.ParseIP(start)),
		end:   bytesToUint32(net.ParseIP(end)),
	}
	return r
}

func Test_rangesForIPBlock(t *testing.T) {
	for i, tc := range []struct {
		ipBlock networkingv1.IPBlock
		result  []intRange
	}{
		{
			ipBlock: networkingv1.IPBlock{
				CIDR:   "10.0.0.0/8",
				Except: []string{"10.0.1.0/24"},
			},
			result: []intRange{
				parseRange("10.0.0.0", "10.0.0.255"),
				parseRange("10.0.2.0", "10.255.255.255"),
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.0.0/16",
				Except: []string{
					"192.168.2.0/24",
					"192.168.3.6/32",
				},
			},
			result: []intRange{
				parseRange("192.168.0.0", "192.168.1.255"),
				parseRange("192.168.3.0", "192.168.3.5"),
				parseRange("192.168.3.7", "192.168.255.255"),
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.1.0/24",
				Except: []string{
					"192.168.1.0/32",
					"192.168.1.9/32",
					"192.168.1.255/32",
				},
			},
			result: []intRange{
				parseRange("192.168.1.1", "192.168.1.8"),
				parseRange("192.168.1.10", "192.168.1.254"),
			},
		},
	} {
		ranges := rangesForIPBlock(&tc.ipBlock)

		if !reflect.DeepEqual(tc.result, ranges) {
			t.Fatalf("bad result for %d\nexpected %v\ngot      %v", i, tc.result, ranges)
		}
	}
}

func TestIPBlockToCIDRs(t *testing.T) {
	for i, tc := range []struct {
		ipBlock networkingv1.IPBlock
		result  []string
	}{
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "10.0.0.0/8",
				Except: []string{
					"10.0.1.0/24",
				},
			},
			result: []string{
				"10.0.0.0/24",   // 10.0.0.0 - 10.0.0.255
				"10.0.2.0/23",   // 10.0.2.0 - 10.0.3.255
				"10.0.4.0/22",   // 10.0.4.0 - 10.0.7.255
				"10.0.8.0/21",   // 10.0.8.0 - 10.0.15.255
				"10.0.16.0/20",  // 10.0.16.0 - 10.0.31.255
				"10.0.32.0/19",  // 10.0.32.0 - 10.0.63.255
				"10.0.64.0/18",  // 10.0.64.0 - 10.0.127.255
				"10.0.128.0/17", // 10.0.128.0 - 10.0.255.255
				"10.1.0.0/16",   // 10.1.0.0 - 10.1.255.255
				"10.2.0.0/15",   // 10.2.0.0 - 10.3.255.255
				"10.4.0.0/14",   // 10.4.0.0 - 10.7.255.255
				"10.8.0.0/13",   // 10.8.0.0 - 10.15.255.255
				"10.16.0.0/12",  // 10.16.0.0 - 10.31.255.255
				"10.32.0.0/11",  // 10.32.0.0 - 10.63.255.255
				"10.64.0.0/10",  // 10.64.0.0 - 10.127.255.255
				"10.128.0.0/9",  // 10.128.0.0 - 10.255.255.255
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.0.0/16",
				Except: []string{
					"192.168.2.0/24",
					"192.168.3.6/32",
				},
			},
			result: []string{
				"192.168.0.0/23",   // 192.168.0.0 - 192.168.1.255
				"192.168.3.0/30",   // 192.168.3.0 - 192.168.3.3
				"192.168.3.4/31",   // 192.168.3.4 - 192.168.3.5
				"192.168.3.7/32",   // 192.168.3.7 - 192.168.3.7
				"192.168.3.8/29",   // 192.168.3.8 - 192.168.3.15
				"192.168.3.16/28",  // 192.168.3.16 - 192.168.3.31
				"192.168.3.32/27",  // 192.168.3.32 - 192.168.3.63
				"192.168.3.64/26",  // 192.168.3.64 - 192.168.3.127
				"192.168.3.128/25", // 192.168.3.128 - 192.168.3.255
				"192.168.4.0/22",   // 192.168.4.0 - 192.168.7.255
				"192.168.8.0/21",   // 192.168.8.0 - 192.168.15.255
				"192.168.16.0/20",  // 192.168.16.0 - 192.168.31.255
				"192.168.32.0/19",  // 192.168.32.0 - 192.168.63.255
				"192.168.64.0/18",  // 192.168.64.0 - 192.168.127.255
				"192.168.128.0/17", // 192.168.128.0 - 192.168.255.255
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.1.0/24",
				Except: []string{
					"192.168.1.0/32",
					"192.168.1.9/32",
					"192.168.1.255/32",
				},
			},
			result: []string{
				"192.168.1.1/32",   // 192.168.1.1 - 192.168.1.1
				"192.168.1.2/31",   // 192.168.1.2 - 192.168.1.3
				"192.168.1.4/30",   // 192.168.1.4 - 192.168.1.7
				"192.168.1.8/32",   // 192.168.1.8 - 192.168.1.8
				"192.168.1.10/31",  // 192.168.1.10 - 192.168.1.11
				"192.168.1.12/30",  // 192.168.1.12 - 192.168.1.15
				"192.168.1.16/28",  // 192.168.1.16 - 192.168.1.31
				"192.168.1.32/27",  // 192.168.1.32 - 192.168.1.63
				"192.168.1.64/26",  // 192.168.1.64 - 192.168.1.127
				"192.168.1.128/26", // 192.168.1.128 - 192.168.1.191
				"192.168.1.192/27", // 192.168.1.192 - 192.168.1.223
				"192.168.1.224/28", // 192.168.1.224 - 192.168.1.239
				"192.168.1.240/29", // 192.168.1.240 - 192.168.1.247
				"192.168.1.248/30", // 192.168.1.248 - 192.168.1.251
				"192.168.1.252/31", // 192.168.1.252 - 192.168.1.253
				"192.168.1.254/32", // 192.168.1.254 - 192.168.1.254
			},
		},
	} {
		cidrs := IPBlockToCIDRs(&tc.ipBlock)

		if !reflect.DeepEqual(tc.result, cidrs) {
			fmt.Printf("\t\t\tresult: []string{\n")
			for _, cidr := range cidrs {
				r := rangeForCIDR(mustParseCIDR(cidr))
				fmt.Printf("\t\t\t\t\"%s\", // %s - %s\n",
					cidr,
					net.IP(uint32ToBytes(r.start)),
					net.IP(uint32ToBytes(r.end)),
				)
			}
			fmt.Printf("\t\t\t}\n")
			t.Fatalf("bad result for %d", i)
		}
	}
}

func TestPortRangeToPortMasks(t *testing.T) {
	for i, tc := range []struct {
		start  uint16
		end    uint16
		result []string
	}{
		{
			start: 0,
			end:   0,
			result: []string{
				"0x0000/0xffff",
			},
		},
		{
			start: 0,
			end:   65535,
			result: []string{
				"0x0000/0x0000",
			},
		},
		{
			start: 0,
			end:   1023,
			result: []string{
				"0x0000/0xfc00",
			},
		},
		{
			start: 1024,
			end:   65535,
			result: []string{
				"0x0400/0xfc00",
				"0x0800/0xf800",
				"0x1000/0xf000",
				"0x2000/0xe000",
				"0x4000/0xc000",
				"0x8000/0x8000",
			},
		},
		{
			start: 6000,
			end:   6100,
			result: []string{
				"0x1770/0xfff0",
				"0x1780/0xffc0",
				"0x17c0/0xfff0",
				"0x17d0/0xfffc",
				"0x17d4/0xffff",
			},
		},
	} {
		masks := PortRangeToPortMasks(int(tc.start), int(tc.end))
		if !reflect.DeepEqual(masks, tc.result) {
			fmt.Printf("\t\t\tresult: []string{\n")
			for _, mask := range masks {
				fmt.Printf("\t\t\t\t%q,\n", mask)
			}
			fmt.Printf("\t\t\t},\n")
			t.Fatalf("bad result for %d\nexpected %v\ngot      %v", i, tc.result, masks)
		}
	}
}
