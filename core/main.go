package main

// VPN core, linked into Sidegate.exe as a static library (see lib.go).
// Driven by tab-separated lines:
//   in:  "setup\t<endpoint>" | connect | disconnect | logout | quit
//   out: "<state>\t<endpoint>\t<user>\t<ip>\t<msg>", state = setup|off|checking|login|connecting|on|exited

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	socksAddr = "127.0.0.1:10808"
	httpAddr  = "127.0.0.1:10809"
)

var (
	dataDir  = filepath.Join(os.Getenv("LOCALAPPDATA"), "Sidegate")
	sessFile = filepath.Join(dataDir, "session.bin")
	confFile = filepath.Join(dataDir, "endpoint.txt")
	logFile  *os.File
)

func main() {} // required by -buildmode=c-archive; entry points are in lib.go

// serveCommands runs the command loop until "quit" or cmds closes, then emits "exited".
func serveCommands(cmds <-chan string) {
	os.MkdirAll(dataDir, 0700)
	if f, err := os.Create(filepath.Join(dataDir, "log.txt")); err == nil {
		log.SetOutput(f)
		logFile = f
	}
	clearStaleProxy()

	b := &backend{}
	defer b.emit("exited", "")
	b.ev.Endpoint = loadEndpoint()
	if s := loadSession(b.ev.Endpoint); s != nil {
		b.ev.User = s.User
	}
	b.emit(idleState(b.ev.Endpoint), "")
	for line := range cmds {
		cmd, arg, _ := strings.Cut(line, "\t")
		switch cmd {
		case "setup":
			b.setup(arg)
		case "connect":
			b.connect()
		case "disconnect":
			b.disconnect()
			b.emit(idleState(b.ev.Endpoint), "")
		case "logout":
			b.logout()
		case "quit":
			b.disconnect()
			return
		}
	}
	b.disconnect()
}

type Event struct{ State, Endpoint, User, IP, Msg string }

type backend struct {
	mu     sync.Mutex
	ev     Event
	cancel context.CancelFunc
	done   chan struct{}
}

func (b *backend) emit(state, msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ev.State, b.ev.Msg = state, msg
	if state != "on" {
		b.ev.IP = ""
	}
	clean := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace
	e := b.ev
	line := strings.Join([]string{e.State, e.Endpoint, clean(e.User), e.IP, clean(e.Msg)}, "\t")
	events <- line
	log.Print(state, " ", msg) // no user/IP/gateway: logs get attached to bug reports
}

func (b *backend) setup(endpoint string) {
	// Full-width punctuation from a CJK input method ("vpn。example。edu").
	endpoint = strings.NewReplacer("。", ".", "．", ".", "：", ":", "／", "/").Replace(strings.TrimSpace(endpoint))
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		endpoint = u.Host
	}
	endpoint = strings.Trim(endpoint, "/")
	if endpoint == "" {
		b.emit("setup", "请输入地址")
		return
	}
	os.WriteFile(confFile, []byte(endpoint), 0600)
	b.mu.Lock()
	b.ev.Endpoint = endpoint
	b.mu.Unlock()
	b.connect()
}

func (b *backend) connect() {
	b.mu.Lock()
	if b.cancel != nil || b.ev.Endpoint == "" {
		b.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.cancel, b.done = cancel, done
	host := b.ev.Endpoint
	b.mu.Unlock()

	go func() {
		defer close(done)
		err := b.run(ctx, host)
		b.mu.Lock()
		b.cancel = nil
		b.mu.Unlock()
		if ctx.Err() == nil { // not a user-initiated disconnect
			msg := ""
			if err != nil {
				msg = friendly(err)
			}
			b.emit(idleState(host), msg)
		}
	}()
}

// idleState is the page to show when not connected: with no session for the endpoint
// (never logged in, logged out, or a wrong address was just tried) the endpoint page, so it
// can be corrected; otherwise the switch page (an expired session just logs in again on connect).
func idleState(host string) string {
	if loadSession(host) == nil {
		return "setup"
	}
	return "off"
}

// friendly turns common network failures into a short message for the UI. The address itself
// is already on screen (input box / info card), so messages don't repeat it.
func friendly(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	var opErr *net.OpError
	var urlErr *url.Error
	switch {
	case errors.As(err, &dnsErr):
		return "找不到该服务器，请检查地址是否正确"
	case errors.As(err, &certErr):
		return "服务器证书无效"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "连接服务器超时"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "无法连接到服务器"
	case errors.As(err, &urlErr):
		return urlErr.Err.Error() // drop the long request URL
	}
	return err.Error()
}

// disconnect tears down the tunnel but keeps the session cookie for next time.
func (b *backend) disconnect() {
	b.mu.Lock()
	cancel, done := b.cancel, b.done
	b.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (b *backend) logout() {
	b.disconnect()
	if s := loadSession(b.ev.Endpoint); s != nil {
		post(s.Host, "/ssl-vpn/logout.esp", s.form()) // best effort: kill it server-side too
	}
	os.Remove(sessFile)
	if logFile != nil { // logging out clears the log too
		logFile.Truncate(0)
		logFile.Seek(0, 0)
	}
	b.mu.Lock()
	b.ev.User = ""
	b.mu.Unlock()
	b.emit("setup", "")
}

func (b *backend) run(ctx context.Context, host string) error {
	s := loadSession(host)
	var tc *TunnelConfig
	if s != nil {
		b.emit("connecting", "")
		var err error
		if tc, err = getConfig(s); err != nil {
			log.Printf("saved session unusable: %v", err)
			s = nil
		}
	}
	if s == nil {
		// "checking" keeps the setup page up while the address is validated, so a wrong
		// address never flashes the browser-login page.
		b.emit("checking", "")
		method, payload, err := prelogin(host)
		if err != nil {
			return err
		}
		b.emit("login", "请在浏览器中完成登录")
		user, cookie, err := browserLogin(ctx, method, payload)
		if err != nil {
			return err
		}
		b.emit("connecting", "")
		computer, _ := os.Hostname()
		if s, err = gatewayLogin(host, computer, user, cookie); err != nil {
			return err
		}
		if tc, err = getConfig(s); err != nil {
			return err
		}
		saveSession(s)
	}
	b.mu.Lock()
	b.ev.User, b.ev.IP = s.User, tc.IP
	b.mu.Unlock()
	return b.serve(ctx, s, tc)
}

// serve brings up netstack + proxies + system proxy and runs the tunnel until ctx is cancelled.
func (b *backend) serve(ctx context.Context, s *Session, tc *TunnelConfig) error {
	var dns []netip.Addr
	for _, d := range tc.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, a)
		}
	}
	ip, err := netip.ParseAddr(tc.IP)
	if err != nil {
		return err
	}
	vs, err := newStack(ip, dns, tc.MTU)
	if err != nil {
		return err
	}
	defer vs.close()
	r := &router{vs: vs, dns: vs.resolver(), suffixes: tc.Suffixes}
	// exclude-access-routes are not supported.
	for _, s := range tc.Routes {
		if p, err := netip.ParsePrefix(s); err == nil {
			r.routes = append(r.routes, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			r.routes = append(r.routes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go r.serveSOCKS(ln)
	hln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: r.httpHandler(), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(hln)
	defer hs.Close()
	restore, err := setSystemProxy()
	if err != nil {
		return err
	}
	defer restore()
	return b.runTunnel(ctx, s, tc, vs)
}

// runTunnel keeps the SSL tunnel up, reconnecting with the same cookie if it drops.
func (b *backend) runTunnel(ctx context.Context, s *Session, tc *TunnelConfig, vs *vstack) error {
	out := make(chan []byte, 256)
	go func() {
		for {
			p := vs.read(ctx)
			if p == nil {
				return // stack closed on teardown
			}
			select {
			case out <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	for ctx.Err() == nil {
		c, err := openTunnel(s, tc.TunnelURL)
		if errors.Is(err, errAuth) { // session.bin is kept: the next connect re-logs in and overwrites it
			return errors.New("会话已过期，请重新连接以登录")
		}
		if err != nil {
			log.Printf("tunnel: %v", err)
			b.emit("connecting", "重连中…")
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
			}
			continue
		}
		b.emit("on", "")
		stop := context.AfterFunc(ctx, func() { c.Close() })
		done := make(chan struct{})
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				var err error
				select {
				case p := <-out:
					_, err = c.Write(frame(p))
				case <-t.C:
					_, err = c.Write(keepalive)
				case <-done:
					return
				}
				if err != nil {
					c.Close()
					return
				}
			}
		}()
		hdr := make([]byte, hdrLen)
		for {
			c.SetReadDeadline(time.Now().Add(60 * time.Second))
			pkt, err := readFrame(c, hdr)
			if err != nil {
				log.Printf("tunnel down: %v", err)
				break
			}
			if pkt != nil {
				vs.write(pkt)
			}
		}
		close(done)
		stop()
		c.Close()
	}
	return nil
}

func loadEndpoint() string {
	b, _ := os.ReadFile(confFile)
	return strings.TrimSpace(string(b))
}

// The session cookie is a credential: encrypt it at rest with DPAPI (current Windows user only).
func dpapi(in []byte, protect bool) ([]byte, error) {
	var out windows.DataBlob
	blob := &windows.DataBlob{Size: uint32(len(in))}
	if len(in) > 0 {
		blob.Data = &in[0]
	}
	var err error
	if protect {
		err = windows.CryptProtectData(blob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(blob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// Session file: one field per line (none of them can contain a newline), DPAPI-encrypted.
func saveSession(s *Session) {
	plain := strings.Join([]string{s.Host, s.AuthCookie, s.Portal, s.User, s.Domain, s.Computer, s.PreferredIP}, "\n")
	if b, err := dpapi([]byte(plain), true); err == nil {
		os.WriteFile(sessFile, b, 0600)
	}
}

func loadSession(host string) *Session {
	b, err := os.ReadFile(sessFile)
	if err != nil {
		return nil
	}
	plain, err := dpapi(b, false)
	f := strings.Split(string(plain), "\n")
	if err != nil || len(f) != 7 || f[0] != host {
		return nil
	}
	return &Session{Host: f[0], AuthCookie: f[1], Portal: f[2], User: f[3], Domain: f[4], Computer: f[5], PreferredIP: f[6]}
}
