package gateway

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Frame crafting for the L2 services (DHCP replies, router advertisements):
// these are answered before the netstack, so the frames are built by hand
// with gvisor's header package.

// craftUDP4 builds an ethernet/IPv4/UDP frame.
func craftUDP4(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.EthernetMinimumSize + header.IPv4MinimumSize + udpLen
	frame := make([]byte, totalLen)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    header.IPv4ProtocolNumber,
	})

	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + udpLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(srcIP.To4()),
		DstAddr:     tcpip.AddrFromSlice(dstIP.To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udp := header.UDP(frame[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(udp.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
		tcpip.AddrFromSlice(srcIP.To4()), tcpip.AddrFromSlice(dstIP.To4()), uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	udp.SetChecksum(^udp.CalculateChecksum(xsum))

	return frame
}

// craftUDP6 builds an ethernet/IPv6/UDP frame.
func craftUDP6(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.EthernetMinimumSize + header.IPv6MinimumSize + udpLen
	frame := make([]byte, totalLen)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    header.IPv6ProtocolNumber,
	})

	ip := header.IPv6(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(srcIP.To16()),
		DstAddr:           tcpip.AddrFromSlice(dstIP.To16()),
	})

	udp := header.UDP(frame[header.EthernetMinimumSize+header.IPv6MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(udp.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
		tcpip.AddrFromSlice(srcIP.To16()), tcpip.AddrFromSlice(dstIP.To16()), uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	udp.SetChecksum(^udp.CalculateChecksum(xsum))

	return frame
}

// craftICMP6 builds an ethernet/IPv6/ICMPv6 frame (for RA). icmpBody is the
// ICMPv6 message starting at the type byte.
func craftICMP6(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, icmpBody []byte, hopLimit uint8) []byte {
	totalLen := header.EthernetMinimumSize + header.IPv6MinimumSize + len(icmpBody)
	frame := make([]byte, totalLen)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    header.IPv6ProtocolNumber,
	})

	ip := header.IPv6(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(icmpBody)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          hopLimit,
		SrcAddr:           tcpip.AddrFromSlice(srcIP.To16()),
		DstAddr:           tcpip.AddrFromSlice(dstIP.To16()),
	})

	icmp := header.ICMPv6(frame[header.EthernetMinimumSize+header.IPv6MinimumSize:])
	copy(icmp, icmpBody)
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    tcpip.AddrFromSlice(srcIP.To16()),
		Dst:    tcpip.AddrFromSlice(dstIP.To16()),
	}))

	return frame
}

// parseIngress dissects an untagged frame far enough to dispatch DHCP and
// router solicitations. Returns ok=false for anything else.
type ingressPacket struct {
	srcMAC  net.HardwareAddr
	isUDP4  bool
	isUDP6  bool
	isICMP6 bool
	srcIP   net.IP
	dstIP   net.IP
	dstPort uint16 // UDP
	srcPort uint16 // UDP
	icmpTyp uint8  // ICMPv6
	payload []byte // UDP payload or ICMPv6 message
}

func parseIngress(frame []byte) (ingressPacket, bool) {
	var p ingressPacket
	if len(frame) < header.EthernetMinimumSize {
		return p, false
	}
	eth := header.Ethernet(frame)
	p.srcMAC = net.HardwareAddr(eth.SourceAddress())
	body := frame[header.EthernetMinimumSize:]

	switch eth.Type() {
	case header.IPv4ProtocolNumber:
		if len(body) < header.IPv4MinimumSize {
			return p, false
		}
		ip := header.IPv4(body)
		if !ip.IsValid(len(body)) || ip.TransportProtocol() != header.UDPProtocolNumber {
			return p, false
		}
		if ip.FragmentOffset() != 0 || ip.More() {
			return p, false
		}
		udp := header.UDP(body[ip.HeaderLength():])
		if len(udp) < header.UDPMinimumSize {
			return p, false
		}
		p.isUDP4 = true
		src, dst := ip.SourceAddress(), ip.DestinationAddress()
		p.srcIP = net.IP(src.AsSlice())
		p.dstIP = net.IP(dst.AsSlice())
		p.srcPort = udp.SourcePort()
		p.dstPort = udp.DestinationPort()
		p.payload = udp.Payload()
		return p, true

	case header.IPv6ProtocolNumber:
		if len(body) < header.IPv6MinimumSize {
			return p, false
		}
		ip := header.IPv6(body)
		src, dst := ip.SourceAddress(), ip.DestinationAddress()
		p.srcIP = net.IP(src.AsSlice())
		p.dstIP = net.IP(dst.AsSlice())
		rest := body[header.IPv6MinimumSize:]
		switch ip.TransportProtocol() {
		case header.UDPProtocolNumber:
			udp := header.UDP(rest)
			if len(udp) < header.UDPMinimumSize {
				return p, false
			}
			p.isUDP6 = true
			p.srcPort = udp.SourcePort()
			p.dstPort = udp.DestinationPort()
			p.payload = udp.Payload()
			return p, true
		case header.ICMPv6ProtocolNumber:
			if len(rest) < header.ICMPv6MinimumSize {
				return p, false
			}
			p.isICMP6 = true
			p.icmpTyp = uint8(header.ICMPv6(rest).Type())
			p.payload = rest
			return p, true
		}
	}
	return p, false
}
