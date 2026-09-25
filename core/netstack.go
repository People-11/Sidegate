package main

// User-space IPv4 TCP/UDP stack (gVisor) that the tunnel feeds raw IP packets into.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type vstack struct {
	s   *stack.Stack
	ep  *channel.Endpoint
	dns []netip.Addr
	rr  atomic.Uint32
}

func newStack(ip netip.Addr, dns []netip.Addr, mtu int) (*vstack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})
	sack := tcpip.TCPSACKEnabled(true) // off by default in gVisor; matters on lossy links
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(1, ep); err != nil {
		return nil, errors.New(err.String())
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}
	if err := s.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	return &vstack{s: s, ep: ep, dns: dns}, nil
}

func (v *vstack) close() {
	v.ep.Close()
	v.s.Close()
}

// read blocks for the next outbound IP packet; nil once closed or ctx is done.
func (v *vstack) read(ctx context.Context) []byte {
	pkt := v.ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	return append([]byte(nil), view.AsSlice()...)
}

// write injects an inbound IP packet from the tunnel.
func (v *vstack) write(b []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	v.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
}

func (v *vstack) dialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, v.s, fullAddr(ap), ipv4.ProtocolNumber)
}

// resolver sends every DNS query to the VPN's DNS servers (round-robin) through the tunnel.
func (v *vstack) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if len(v.dns) == 0 {
			return nil, errors.New("no VPN DNS servers")
		}
		ap := netip.AddrPortFrom(v.dns[v.rr.Add(1)%uint32(len(v.dns))], 53)
		if network == "tcp" || network == "tcp4" {
			return v.dialTCP(ctx, ap)
		}
		fa := fullAddr(ap)
		return gonet.DialUDP(v.s, nil, &fa, ipv4.ProtocolNumber)
	}}
}
