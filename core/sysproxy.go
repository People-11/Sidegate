package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	pacURL  = "http://" + httpAddr + "/proxy.pac"
)

// setSystemProxy points the system at our PAC script rather than at a fixed proxy.
// Fail-safe: if we're killed (Task Manager, crash, power loss) browsers can't fetch the PAC
// and fall back to direct, and the PAC itself says "PROXY ...; DIRECT" for VPN hosts and
// "DIRECT" for everything else. So a dead Sidegate can never cut off the internet.
// The user's own static proxy settings are left untouched.
func setSystemProxy() (restore func(), err error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	old, _, errOld := k.GetStringValue("AutoConfigURL")
	if old == pacURL { // left over from a killed run; don't "restore" to ourselves
		errOld = registry.ErrNotExist
	}
	err = k.SetStringValue("AutoConfigURL", pacURL)
	k.Close()
	if err != nil {
		return nil, err
	}
	notifyProxyChanged()

	return func() {
		k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.SET_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		if errOld == nil {
			k.SetStringValue("AutoConfigURL", old)
		} else {
			k.DeleteValue("AutoConfigURL")
		}
		notifyProxyChanged()
	}, nil
}

// clearStaleProxy undoes the setting left by a killed previous run.
func clearStaleProxy() {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if s, _, _ := k.GetStringValue("AutoConfigURL"); s == pacURL {
		k.DeleteValue("AutoConfigURL")
		notifyProxyChanged()
	}
}

var inetSetOption = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")

func notifyProxyChanged() {
	inetSetOption.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	inetSetOption.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}
