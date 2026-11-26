package tools

import (
	"strings"
	"testing"

	"github.com/mikluko/jmap"
)

func TestNormalizeKeyword(t *testing.T) {
	for in, want := range map[string]string{
		"$label:Invoices": "$label:invoices",
		"Todo":            "todo",
		"/imap/flag":      "/imap/flag",
		"$Seen":           "$seen",
	} {
		if got, err := normalizeKeyword(in); err != nil || got != want {
			t.Errorf("normalizeKeyword(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "two words", "tab\t", "a(b", "a)b", "a{b", "a]b", "50%", "a*", `a"b`, `a\b`, "é", strings.Repeat("k", 256)} {
		if _, err := normalizeKeyword(bad); err == nil {
			t.Errorf("normalizeKeyword(%q) accepted", bad)
		}
	}
}

func TestKeywordPatch(t *testing.T) {
	yes, no := true, false
	p, err := keywordPatch(updateInput{Read: &yes, Flagged: &no, AddKeywords: []string{"$label:Invoices", "a/b~c"}, RemoveKeywords: []string{"Todo"}})
	if err != nil {
		t.Fatal(err)
	}
	want := jmap.Patch{
		"keywords/$seen":           true,
		"keywords/$flagged":        nil,
		"keywords/$label:invoices": true,
		"keywords/a~1b~0c":         true,
		"keywords/todo":            nil,
	}
	if len(p) != len(want) {
		t.Fatalf("patch = %v, want %v", p, want)
	}
	for k, v := range want {
		if got, ok := p[k]; !ok || got != v {
			t.Errorf("patch[%q] = %v (present %v), want %v", k, got, ok, v)
		}
	}
	if _, ok := p["keywords"]; ok {
		t.Error("the patch must never replace the whole keywords object")
	}

	for name, in := range map[string]updateInput{
		"added and removed":       {AddKeywords: []string{"Todo"}, RemoveKeywords: []string{"todo"}},
		"read=false and add seen": {Read: &no, AddKeywords: []string{"$seen"}},
		"invalid keyword":         {AddKeywords: []string{"two words"}},
		"nothing to do":           {},
	} {
		if _, err := keywordPatch(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := keywordPatch(updateInput{Read: &yes, AddKeywords: []string{"$seen"}}); err != nil {
		t.Errorf("read=true with $seen added is consistent: %v", err)
	}
}
