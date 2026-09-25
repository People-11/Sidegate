package main

import (
	"reflect"
	"testing"
)

// Shapes of real GlobalProtect replies.
func TestXMLExtract(t *testing.T) {
	login := `<?xml version="1.0" encoding="utf-8"?> <jnlp> <application-desc>
<argument>(null)</argument>
<argument>cafe01</argument>
<argument/>
<argument>GP-Portal</argument>
<argument>u@x&amp;y</argument>
</application-desc></jnlp>`
	if got := xmlTags(xmlRaw(login, "application-desc")[0], "argument"); !reflect.DeepEqual(got,
		[]string{"(null)", "cafe01", "", "GP-Portal", "u@x&y"}) {
		t.Errorf("arguments: %q", got)
	}

	cfg := `<response status="success"><need-tunnel>yes</need-tunnel>
<ip-address>10.20.30.40</ip-address><mtu>1400</mtu>
<dns><member>10.0.0.53</member><member>10.0.0.54</member></dns>
<dns-suffix><member>example.edu</member></dns-suffix>
<access-routes><member>10.0.0.0/8</member><member>172.16.0.0/16</member></access-routes>
<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>`
	if xmlTag(cfg, "ip-address") != "10.20.30.40" || xmlTag(cfg, "mtu") != "1400" || xmlTag(cfg, "ssl-tunnel-url") != "/ssl-tunnel-connect.sslvpn" {
		t.Error("scalar tags")
	}
	if got := xmlMembers(cfg, "dns"); !reflect.DeepEqual(got, []string{"10.0.0.53", "10.0.0.54"}) {
		t.Errorf("dns: %q", got) // must not pick up <dns-suffix>
	}
	if got := xmlMembers(cfg, "dns-suffix"); !reflect.DeepEqual(got, []string{"example.edu"}) {
		t.Errorf("suffix: %q", got)
	}
	if got := xmlMembers(cfg, "access-routes"); len(got) != 2 {
		t.Errorf("routes: %q", got)
	}
	if xmlTag(cfg, "missing") != "" || xmlMembers(cfg, "missing") != nil || xmlTag("<a", "a") != "" {
		t.Error("missing/truncated")
	}
}
