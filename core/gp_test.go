package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	pkt := []byte{0x45, 1, 2, 3}
	var buf bytes.Buffer
	buf.Write(keepalive)
	buf.Write(frame(pkt))
	hdr := make([]byte, hdrLen)
	if p, err := readFrame(&buf, hdr); err != nil || p != nil {
		t.Fatalf("keepalive: %v %v", p, err)
	}
	if p, err := readFrame(&buf, hdr); err != nil || !bytes.Equal(p, pkt) {
		t.Fatalf("data: %v %v", p, err)
	}
}

func TestParseACS(t *testing.T) {
	cb := base64.StdEncoding.EncodeToString([]byte("<saml-username>u@x</saml-username><prelogin-cookie>abc</prelogin-cookie>"))
	for _, doc := range []string{
		`<html><!-- <saml-username>u@x</saml-username><prelogin-cookie>abc</prelogin-cookie> --></html>`,
		`<meta http-equiv="refresh" content="0; URL=globalprotectcallback:` + cb + `">`,
	} {
		if u, c := parseACS(doc); u != "u@x" || c != "abc" {
			t.Fatalf("got %q %q from %s", u, c, doc)
		}
	}
}

func TestSplitDNS(t *testing.T) {
	r := &router{suffixes: []string{"example.edu"}}
	for host, want := range map[string]bool{
		"intranet": true, "example.edu": true, "myuni.Example.edu.": true,
		"google.com": false, "evil-example.edu": false,
	} {
		if r.internalName(host) != want {
			t.Errorf("%s: want %v", host, want)
		}
	}
}

func TestLogoutWipesLocalCredentials(t *testing.T) {
	d, _ := os.MkdirTemp("", "sidegate") // not t.TempDir: log.txt stays open, Windows can't delete it
	dataDir, sessFile, confFile = d, d+"/session.bin", d+"/endpoint.txt"
	saveSession(&Session{Host: "", AuthCookie: "secret", User: "u@x"}) // Host "" matches the empty endpoint
	if loadSession("") == nil {
		t.Fatal("session not saved")
	}
	cmds := make(chan string, 2)
	go serveCommands(cmds)
	<-events // initial state (logs a line with the username)
	cmds <- "logout"
	if e := <-events; !strings.HasPrefix(e, "setup\t") {
		t.Fatalf("after logout: %q", e)
	}
	cmds <- "quit"
	if e := <-events; !strings.HasPrefix(e, "exited\t") {
		t.Fatalf("after quit: %q", e)
	}
	if _, err := os.Stat(sessFile); !os.IsNotExist(err) {
		t.Fatal("session.bin still exists after logout")
	}
	if b, _ := os.ReadFile(d + "/log.txt"); bytes.Contains(b, []byte("u@x")) {
		t.Fatalf("log still has username: %s", b)
	}
}

func TestReplyErrDoesNotLeakBody(t *testing.T) {
	secret := `<jnlp><application-desc><argument>SECRETCOOKIE</argument></application-desc></jnlp>`
	if err := replyErr("login.esp", []byte(secret)); strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("leaked: %v", err)
	}
	if err := replyErr("login.esp", []byte(`<response status="error"><error>Invalid username or password</error></response>`)); !strings.Contains(err.Error(), "Invalid username") {
		t.Fatalf("lost server message: %v", err)
	}
}
