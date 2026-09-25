package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// After the IdP, the gateway sends the browser to globalprotectcallback:<base64 xml>
// (or, for embedded browsers, puts the same tags in HTML comments). Handle both.
func parseACS(doc string) (user, cookie string) {
	// PathUnescape, not QueryUnescape: the latter turns base64 "+" into spaces
	if u, err := url.PathUnescape(doc); err == nil {
		doc = u
	}
	if _, cb, ok := strings.Cut(doc, "globalprotectcallback:"); ok {
		end := strings.IndexFunc(cb, func(r rune) bool {
			return !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-", r)
		})
		if end >= 0 {
			cb = cb[:end]
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
			if b, err := enc.DecodeString(cb); err == nil {
				doc += string(b)
				break
			}
		}
	}
	return xmlTag(doc, "saml-username"), xmlTag(doc, "prelogin-cookie")
}

var cbPortFile = filepath.Join(dataDir, "callback.port")

const cbKey = `Software\Classes\globalprotectcallback`

// browserLogin runs SAML in the default browser. The callback URI handler is registered
// under HKCU only for the duration of the login, pointing at "Sidegate.exe --callback",
// which forwards the URL to us over loopback.
func browserLogin(ctx context.Context, host string) (user, cookie string, err error) {
	method, payload, err := prelogin(host)
	if err != nil {
		return "", "", err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	// Only whoever can read cbPortFile (this Windows user) knows the token, so web pages
	// and other users can't inject a login into the loopback server.
	tok := make([]byte, 16)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	got := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/saml": // POST binding: the browser needs a page that auto-submits the form
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, payload)
		case "/cb":
			if r.Method != http.MethodPost || subtle.ConstantTimeCompare([]byte(r.FormValue("t")), []byte(token)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			select {
			case got <- r.FormValue("u"):
			default:
			}
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	port := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	os.WriteFile(cbPortFile, []byte(port+" "+token), 0600)
	defer os.Remove(cbPortFile)
	if err := registerCallback(); err != nil {
		return "", "", err
	}
	defer unregisterCallback()

	start := "http://127.0.0.1:" + port + "/saml"
	if strings.EqualFold(method, "REDIRECT") {
		start = payload
	}
	if err := shellOpen(start); err != nil {
		return "", "", err
	}
	select {
	case u := <-got:
		if user, cookie = parseACS(u); cookie == "" {
			return "", "", errors.New("login callback had no prelogin-cookie")
		}
		return user, cookie, nil
	case <-ctx.Done():
		return "", "", ctx.Err()
	case <-time.After(10 * time.Minute):
		return "", "", errors.New("login timed out")
	}
}

// deliverCallback is what the browser launches: hand the URL to the running instance and exit.
func deliverCallback(u string) {
	b, err := os.ReadFile(cbPortFile)
	port, token, ok := strings.Cut(strings.TrimSpace(string(b)), " ")
	if err != nil || !ok {
		return
	}
	http.PostForm("http://127.0.0.1:"+port+"/cb", url.Values{"u": {u}, "t": {token}})
}

// Overwrites (and later deletes) any existing HKCU handler; the machine-wide HKLM one is untouched.
func registerCallback() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, cbKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	k.SetStringValue("", "URL:GlobalProtectCallback Protocol")
	k.SetStringValue("URL Protocol", "")
	k.Close()
	k, _, err = registry.CreateKey(registry.CURRENT_USER, cbKey+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("", `"`+exe+`" --callback "%1"`)
}

func unregisterCallback() {
	for _, sub := range []string{`\shell\open\command`, `\shell\open`, `\shell`, ``} {
		registry.DeleteKey(registry.CURRENT_USER, cbKey+sub)
	}
}

func shellOpen(target string) error {
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(target), nil, nil, windows.SW_SHOWNORMAL)
}
