package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/openshift/sdn/pkg/network/node/bpf"
)

func main() {
	maps, err := bpf.InitBPF("")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	acceptMap := maps["accept_map"]

	key, ok := makeEBPFServiceKey("1.2.3.4", 80, "tcp")
	if !ok {
		fmt.Printf("error: key not ok\n")
		return
	}
	err = acceptMap.Put(key, byte(1))
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
}

func makeEBPFServiceKey(ip string, port int, protocol string) ([8]byte, bool) {
	var key [8]byte

	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		return key, false
	}
	key[0] = ipBytes[0]
	key[1] = ipBytes[1]
	key[2] = ipBytes[2]
	key[3] = ipBytes[3]

	binary.BigEndian.PutUint16(key[4:6], uint16(port))

	var proto uint8
	switch protocol {
	case "tcp":
		proto = syscall.IPPROTO_TCP
	case "udp":
		proto = syscall.IPPROTO_UDP
	case "sctp":
		proto = syscall.IPPROTO_SCTP
	default:
		return key, false
	}
	key[6] = proto

	return key, true
}
