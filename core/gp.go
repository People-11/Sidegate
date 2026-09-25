package main

// GlobalProtect gateway protocol (the portal step is skipped: the endpoint is used as the gateway).
// Same wire format as openconnect's gpst.c.

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var httpc = &http.Client{
	Timeout: 30 * time.Second,
	// Server lacks RFC 5746: OpenSSL refuses the handshake, Go allows it (renegotiation stays disabled).
	Transport: &http.Transport{},
}

func post(host, path string, form url.Values) ([]byte, error) {
	req, _ := http.NewRequest("POST", "https://"+host+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "PAN GlobalProtect")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode != 200 {
		err = &statusError{path, resp.StatusCode}
	}
	return body, err
}

type statusError struct {
	path string
	code int
}

func (e *statusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.path, e.code) }

var errNotGP = errors.New("该地址不是 GlobalProtect 网关，或未启用 SAML 登录")

func baseForm(host, computer string) url.Values {
	return url.Values{
		"clientVer": {"4100"}, "clientos": {"Windows"}, "os-version": {"Microsoft Windows 10 Pro, 64-bit"},
		"ipv6-support": {"no"}, "server": {host}, "computer": {computer},
	}
}

// prelogin returns the SAML start page: either an HTML form (POST) or a URL (REDIRECT).
func prelogin(host string) (method, payload string, err error) {
	body, err := post(host, "/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows&default-browser=1&cas-support=yes", url.Values{})
	var se *statusError
	if errors.As(err, &se) {
		return "", "", errNotGP // a web server, but not a GlobalProtect gateway
	}
	if err != nil {
		return "", "", err
	}
	doc := string(body)
	req := xmlTag(doc, "saml-request")
	if req == "" {
		return "", "", errNotGP // not GlobalProtect, or password login only
	}
	b, err := base64.StdEncoding.DecodeString(req)
	return xmlTag(doc, "saml-auth-method"), string(b), err
}

// Session is everything needed to (re)open a tunnel. Valid for the gateway's login lifetime.
type Session struct {
	Host, AuthCookie, Portal, User, Domain, Computer, PreferredIP string
}

func (s *Session) form() url.Values {
	f := baseForm(s.Host, s.Computer)
	f.Set("authcookie", s.AuthCookie)
	f.Set("portal", s.Portal)
	f.Set("user", s.User)
	f.Set("domain", s.Domain)
	f.Set("preferred-ip", s.PreferredIP)
	return f
}

func gatewayLogin(host, computer, user, preloginCookie string) (*Session, error) {
	f := baseForm(host, computer)
	for k, v := range map[string]string{"jnlpReady": "jnlpReady", "ok": "Login", "direct": "yes", "prot": "https:",
		"internal": "no", "user": user, "passwd": "", "prelogin-cookie": preloginCookie,
		"portal-userauthcookie": "", "portal-prelogonuserauthcookie": "", "inputStr": ""} {
		f.Set(k, v)
	}
	body, err := post(host, "/ssl-vpn/login.esp", f)
	if err != nil {
		return nil, err
	}
	var a []string // positional, see openconnect auth-globalprotect.c gp_login_args
	if d := xmlRaw(string(body), "application-desc"); len(d) > 0 {
		a = xmlTags(d[0], "argument")
	}
	if len(a) < 16 {
		return nil, replyErr("login.esp", body)
	}
	return &Session{Host: host, AuthCookie: a[1], Portal: a[3], User: a[4], Domain: a[7], Computer: computer, PreferredIP: a[15]}, nil
}

type TunnelConfig struct {
	IP, TunnelURL         string
	MTU                   int
	DNS, Routes, Suffixes []string
}

func getConfig(s *Session) (*TunnelConfig, error) {
	f := s.form()
	for k, v := range map[string]string{"client-type": "1", "protocol-version": "p1", "internal": "no",
		"app-version": "6.2.8-948", "hmac-algo": "sha1,md5,sha256", "enc-algo": "aes-128-cbc,aes-256-cbc"} {
		f.Set(k, v)
	}
	body, err := post(s.Host, "/ssl-vpn/getconfig.esp", f)
	if err != nil {
		return nil, err
	}
	doc := string(body)
	c := TunnelConfig{
		IP:        xmlTag(doc, "ip-address"),
		TunnelURL: xmlTag(doc, "ssl-tunnel-url"),
		DNS:       xmlMembers(doc, "dns"),
		Routes:    xmlMembers(doc, "access-routes"),
		Suffixes:  xmlMembers(doc, "dns-suffix"),
	}
	c.MTU, _ = strconv.Atoi(xmlTag(doc, "mtu"))
	if c.IP == "" {
		return nil, replyErr("getconfig", body)
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.TunnelURL == "" {
		c.TunnelURL = "/ssl-tunnel-connect.sslvpn"
	}
	return &c, nil
}

// replyErr describes a failed gateway reply without echoing the body, which can hold the
// authcookie (login.esp) or ESP keys (getconfig); errors end up in the UI and the log.
func replyErr(what string, body []byte) error {
	doc := string(body)
	msg := xmlTag(doc, "error")
	if msg == "" {
		msg = xmlTag(doc, "msg")
	}
	if msg == "" || len(msg) > 120 {
		return fmt.Errorf("%s: unexpected reply (%d bytes)", what, len(body))
	}
	return fmt.Errorf("%s: %s", what, msg)
}

var errAuth = errors.New("gateway rejected session cookie")

// openTunnel returns a raw TLS stream carrying framed IP packets.
func openTunnel(s *Session, path string) (*tls.Conn, error) {
	c, err := tls.Dial("tcp", s.Host+":443", &tls.Config{ServerName: s.Host})
	if err != nil {
		return nil, err
	}
	q := url.Values{"user": {s.User}, "authcookie": {s.AuthCookie}}
	fmt.Fprintf(c, "GET %s?%s HTTP/1.1\r\n\r\n", path, q.Encode())
	buf := make([]byte, 12)
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	if string(buf) != "START_TUNNEL" {
		c.Close()
		return nil, fmt.Errorf("%w: %q", errAuth, buf)
	}
	return c, nil
}

// Frame: magic(4) ethertype(2) len(2) 01 00 00 00 00 00 00 00, then the IP packet.
// ethertype=0,len=0 with zero trailer is a keepalive.
const hdrLen = 16

var keepalive = []byte{0x1a, 0x2b, 0x3c, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func frame(pkt []byte) []byte {
	b := make([]byte, hdrLen+len(pkt))
	binary.BigEndian.PutUint32(b, 0x1a2b3c4d)
	binary.BigEndian.PutUint16(b[4:], 0x0800) // IPv4 only: we send ipv6-support=no
	binary.BigEndian.PutUint16(b[6:], uint16(len(pkt)))
	b[8] = 1
	copy(b[hdrLen:], pkt)
	return b
}

// readFrame returns the next IP packet, or nil for a keepalive.
func readFrame(r io.Reader, hdr []byte) ([]byte, error) {
	if _, err := io.ReadFull(r, hdr[:hdrLen]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(hdr) != 0x1a2b3c4d {
		return nil, fmt.Errorf("bad frame magic % x", hdr[:hdrLen])
	}
	n := binary.BigEndian.Uint16(hdr[6:])
	if n == 0 {
		return nil, nil
	}
	pkt := make([]byte, n)
	_, err := io.ReadFull(r, pkt)
	return pkt, err
}
