package main

import "strings"

// Minimal extraction for GlobalProtect's flat XML replies (smaller than encoding/xml).
// No CDATA, namespaces or numeric entities; the gateway doesn't send them.

var xmlUnescape = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace

// xmlRaw returns the raw inner XML of every <name ...>...</name> in doc, in order.
// A self-closing <name/> yields "" so positional lists (login.esp arguments) stay aligned.
func xmlRaw(doc, name string) []string {
	var out []string
	for {
		i := strings.Index(doc, "<"+name)
		if i < 0 {
			return out
		}
		rest := doc[i+1+len(name):]
		if rest == "" || !strings.ContainsRune(">/ \t\r\n", rune(rest[0])) {
			doc = rest // longer name sharing the prefix, e.g. <dns-suffix> when looking for <dns>
			continue
		}
		gt := strings.IndexByte(rest, '>')
		if gt < 0 {
			return out
		}
		if gt > 0 && rest[gt-1] == '/' {
			out = append(out, "")
			doc = rest[gt+1:]
			continue
		}
		body := rest[gt+1:]
		end := strings.Index(body, "</"+name+">")
		if end < 0 {
			return out
		}
		out = append(out, body[:end])
		doc = body[end+len(name)+3:]
	}
}

// xmlTags is xmlRaw with each value trimmed and entity-decoded.
func xmlTags(doc, name string) []string {
	raw := xmlRaw(doc, name)
	for i, s := range raw {
		raw[i] = xmlUnescape(strings.TrimSpace(s))
	}
	return raw
}

// xmlTag returns the decoded text of the first <name> element, or "".
func xmlTag(doc, name string) string {
	if t := xmlTags(doc, name); len(t) > 0 {
		return t[0]
	}
	return ""
}

// xmlMembers returns the <member> values inside the first <section> element.
func xmlMembers(doc, section string) []string {
	if s := xmlRaw(doc, section); len(s) > 0 {
		return xmlTags(s[0], "member")
	}
	return nil
}
