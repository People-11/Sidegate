package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type router struct {
	vs       *vstack
	dns      *net.Resolver // queries the VPN's DNS servers through the tunnel
	routes   []netip.Prefix
	suffixes []string // split DNS: only these domains (and bare hostnames) go to VPN DNS
	direct   net.Dialer
}

func (r *router) internalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if len(r.suffixes) == 0 || !strings.Contains(h, ".") {
		return true
	}
	for _, s := range r.suffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

func (r *router) viaVPN(ip netip.Addr) bool {
	for _, p := range r.routes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// dial sends destinations inside the gateway's routes into the tunnel, everything else out
// the normal connection. Only internal names are resolved by VPN DNS, so the VPN operator
// doesn't see every hostname you visit.
func (r *router) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if r.internalName(host) {
			ips, _ = r.dns.LookupNetIP(lctx, "ip4", host)
		}
		if len(ips) == 0 {
			ips, _ = net.DefaultResolver.LookupNetIP(lctx, "ip", host)
		}
		cancel()
	}
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() && r.viaVPN(ip) {
			return r.vs.dialTCP(ctx, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	return r.direct.DialContext(ctx, "tcp", addr)
}

// pac builds the proxy auto-config script: internal names and route ranges go to our
// proxy (falling back to DIRECT if we're gone), everything else is DIRECT. Public hostnames
// are resolved by the browser's normal DNS, never the VPN's.
func (r *router) pac() string {
	// No trailing commas: Windows runs PAC in legacy JScript, where [a,] has an extra undefined element.
	var s, rt []string
	for _, x := range r.suffixes {
		s = append(s, fmt.Sprintf("%q", strings.ToLower(strings.Trim(x, "."))))
	}
	for _, p := range r.routes {
		if p.Addr().Is4() {
			rt = append(rt, fmt.Sprintf("[%q,%q]", p.Masked().Addr(), net.IP(net.CIDRMask(p.Bits(), 32))))
		}
	}
	return `function FindProxyForURL(url, host) {
  var P = "PROXY ` + httpAddr + `; DIRECT";
  if (isPlainHostName(host)) return P;
  var S = [` + strings.Join(s, ",") + `];
  for (var i = 0; i < S.length; i++) if (host == S[i] || dnsDomainIs(host, "." + S[i])) return P;
  var ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host : dnsResolve(host);
  if (!ip) return "DIRECT";
  var R = [` + strings.Join(rt, ",") + `];
  for (var i = 0; i < R.length; i++) if (isInNet(ip, R[i][0], R[i][1])) return P;
  return "DIRECT";
}
`
}

func pipe(a, b net.Conn) {
	go func() { io.Copy(a, b); a.Close() }()
	io.Copy(b, a)
	b.Close()
}

// SOCKS5 CONNECT only: no auth, no UDP ASSOCIATE.
func (r *router) serveSOCKS(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			if err := r.socks(c); err != nil { // not logged: it would record browsing destinations
				c.Close()
			}
		}()
	}
}

func (r *router) socks(c net.Conn) error {
	br := bufio.NewReader(c)
	h := make([]byte, 262)
	if _, err := io.ReadFull(br, h[:2]); err != nil || h[0] != 5 {
		return fmt.Errorf("not socks5")
	}
	if _, err := io.ReadFull(br, h[:h[1]]); err != nil {
		return err
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(br, h[:4]); err != nil {
		return err
	}
	if h[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported command %d", h[1])
	}
	var host string
	switch h[3] {
	case 1, 4:
		n := map[byte]int{1: 4, 4: 16}[h[3]]
		if _, err := io.ReadFull(br, h[:n]); err != nil {
			return err
		}
		host = net.IP(h[:n]).String()
	case 3:
		if _, err := io.ReadFull(br, h[:1]); err != nil {
			return err
		}
		n := int(h[0])
		if _, err := io.ReadFull(br, h[:n]); err != nil {
			return err
		}
		host = string(h[:n])
	default:
		return fmt.Errorf("bad atyp")
	}
	if _, err := io.ReadFull(br, h[:2]); err != nil {
		return err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(h[:2]))))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	up, err := r.dial(ctx, "tcp", addr)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	pipe(&bufConn{c, br}, up)
	return nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// HTTP proxy: CONNECT tunnels plus plain-HTTP forwarding.
func (r *router) httpHandler() http.Handler {
	tr := &http.Transport{DialContext: r.dial}
	pac := r.pac()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Host == "" && req.URL.Path == "/proxy.pac" { // asked of us directly, not proxied
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, pac)
			return
		}
		if req.Method == http.MethodConnect {
			up, err := r.dial(req.Context(), "tcp", req.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.WriteHeader(200)
			c, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				up.Close()
				return
			}
			pipe(&bufConn{c, buf.Reader}, up)
			return
		}
		req.RequestURI = ""
		req.Header.Del("Proxy-Connection")
		resp, err := tr.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
}
