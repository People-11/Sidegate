package main

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Runs our PAC through Windows' own PAC engine (WinHTTP), the one that matters in practice.
func TestPACWithWinHTTP(t *testing.T) {
	r := &router{
		suffixes: []string{"example.edu"},
		routes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/16")},
	}
	srv := httptest.NewServer(r.httpHandler())
	defer srv.Close()

	winhttp := windows.NewLazySystemDLL("winhttp.dll")
	open, getProxy, closeH := winhttp.NewProc("WinHttpOpen"), winhttp.NewProc("WinHttpGetProxyForUrl"), winhttp.NewProc("WinHttpCloseHandle")
	h, _, err := open.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("pac-test"))), 1, 0, 0, 0)
	if h == 0 {
		t.Fatal(err)
	}
	defer closeH.Call(h)

	type autoProxyOptions struct {
		flags, detect uint32
		url           *uint16
		reserved      uintptr
		reserved2     uint32
		autoLogon     int32
	}
	type proxyInfo struct {
		access        uint32
		proxy, bypass *uint16
	}
	opts := autoProxyOptions{flags: 2 /* CONFIG_URL */, url: windows.StringToUTF16Ptr(srv.URL + "/proxy.pac")}

	for url, wantProxy := range map[string]bool{
		"http://10.1.2.3/":            true,  // inside a route
		"http://172.16.9.9/":          true,  // inside a route
		"http://8.8.8.8/":             false, // public IP
		"http://intranet/":            true,  // bare hostname
		"https://www.example.edu/x":   true,  // internal suffix
		"https://example.edu/":        true,  // suffix itself
		"http://nonexistent.invalid/": false, // unresolvable public name
	} {
		var pi proxyInfo
		ok, _, err := getProxy.Call(h, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(url))), uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&pi)))
		if ok == 0 {
			t.Fatalf("%s: WinHttpGetProxyForUrl: %v", url, err)
		}
		got := pi.access == 3 && pi.proxy != nil && windows.UTF16PtrToString(pi.proxy) != ""
		if got != wantProxy {
			p := ""
			if pi.proxy != nil {
				p = windows.UTF16PtrToString(pi.proxy)
			}
			t.Errorf("%s: proxied=%v (%q), want %v", url, got, p, wantProxy)
		}
	}

	// Fail-safe: once we're dead the PAC can't be fetched, so no proxy is returned and
	// clients go DIRECT. The internet keeps working after a hard kill.
	srv.Close()
	var pi proxyInfo
	if ok, _, _ := getProxy.Call(h, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("http://8.8.8.8/"))), uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&pi))); ok != 0 && pi.access == 3 {
		t.Fatal("dead PAC server still yielded a proxy")
	}
}
