package main

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Two stacks wired back to back stand in for "us <-> tunnel <-> campus network".
func TestStackTCPAndDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srvIP, cliIP := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	srv, _ := newStack(srvIP, nil, 1400)
	cli, _ := newStack(cliIP, []netip.Addr{srvIP}, 1400)
	defer srv.close()
	defer cli.close()
	pump := func(from, to *vstack) {
		for p := from.read(ctx); p != nil; p = from.read(ctx) {
			to.write(p)
		}
	}
	go pump(cli, srv)
	go pump(srv, cli)

	// TCP echo server on the far side.
	ln, err := gonet.ListenTCP(srv.s, fullAddr(netip.AddrPortFrom(srvIP, 80)), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(c, c)
		}
	}()
	c, err := cli.dialTCP(ctx, netip.AddrPortFrom(srvIP, 80))
	if err != nil {
		t.Fatal("dial:", err)
	}
	msg := make([]byte, 100_000) // several segments
	for i := range msg {
		msg[i] = byte(i)
	}
	go c.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatal("echo mismatch:", err)
	}

	// Minimal DNS server on the far side: answers every A query with 10.9.8.7.
	fa := fullAddr(netip.AddrPortFrom(srvIP, 53))
	uc, err := gonet.DialUDP(srv.s, &fa, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := uc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			qend := 12
			for q[qend] != 0 {
				qend += int(q[qend]) + 1
			}
			qend += 5 // root label + qtype + qclass
			resp := append([]byte{}, q[:qend]...)
			binary.BigEndian.PutUint16(resp[2:], 0x8180)  // response, RD+RA, no error
			if binary.BigEndian.Uint16(q[qend-4:]) == 1 { // A
				binary.BigEndian.PutUint16(resp[6:], 1) // ANCOUNT
				resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 9, 8, 7)
			} else {
				binary.BigEndian.PutUint16(resp[6:], 0)
			}
			uc.WriteTo(resp, from)
		}
	}()
	ips, err := cli.resolver().LookupNetIP(ctx, "ip4", "intranet.example.edu")
	if err != nil || len(ips) == 0 || ips[0] != netip.MustParseAddr("10.9.8.7") {
		t.Fatalf("dns via tunnel: %v %v", ips, err)
	}
}
