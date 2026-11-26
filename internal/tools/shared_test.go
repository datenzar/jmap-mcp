package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
	"github.com/kOlapsis/jmap-mcp/internal/testenv"
)

// fakeShared serves one JMAP session per login (/<login>/session) and records the account of each Mailbox/get.
type fakeShared struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func newFakeShared(t *testing.T, sessions map[string]string) *fakeShared {
	t.Helper()
	f := &fakeShared{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if login, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/session"); ok {
			_, _ = fmt.Fprint(w, sessions[login])
			return
		}
		var req struct {
			MethodCalls [][]json.RawMessage `json:"methodCalls"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var args struct {
			AccountID string `json:"accountId"`
		}
		_ = json.Unmarshal(req.MethodCalls[0][1], &args)
		f.mu.Lock()
		f.seen = append(f.seen, args.AccountID)
		f.mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"methodResponses":[["Mailbox/get",{"accountId":%q,"state":"1","notFound":[],`+
			`"list":[{"id":"in","name":"Inbox","role":"inbox","totalEmails":1,"unreadEmails":0}]},"0"]],"sessionState":"s"}`, args.AccountID)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeShared) account(login string, def bool) *Account {
	return &Account{Email: login, Default: def, Client: &jmapc.Client{HTTP: f.srv.Client(), SessionURL: f.srv.URL + "/" + login + "/session"}}
}

func (f *fakeShared) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		return ""
	}
	return f.seen[len(f.seen)-1]
}

// session builds a session whose first account is the primary mail account; "nomail:" names an account without mail.
func session(username string, accounts ...string) string {
	accts := map[string]any{}
	for i, name := range accounts {
		caps := map[string]any{"urn:ietf:params:jmap:mail": map[string]any{}}
		if n, ok := strings.CutPrefix(name, "nomail:"); ok {
			name, caps = n, map[string]any{"urn:ietf:params:jmap:filenode": map[string]any{}}
		}
		accts[fmt.Sprintf("%s-%d", username, i)] = map[string]any{"name": name, "isPersonal": i == 0, "isReadOnly": strings.HasPrefix(name, "ro-"), "accountCapabilities": caps}
	}
	b, _ := json.Marshal(map[string]any{
		"capabilities":    map[string]any{"urn:ietf:params:jmap:core": map[string]any{}, "urn:ietf:params:jmap:mail": map[string]any{}},
		"accounts":        accts,
		"primaryAccounts": map[string]any{"urn:ietf:params:jmap:mail": username + "-0"},
		"username":        username, "apiUrl": "/api/", "state": "s",
	})
	return string(b)
}

func TestSharedAccounts(t *testing.T) {
	f := newFakeShared(t, map[string]string{
		"alice@example.test": session("alice@example.test", "alice@example.test", "team@example.test", "ro-archive@example.test", "nomail:Files"),
		"bob@example.test":   session("bob@example.test", "bob@example.test", "team@example.test"),
	})
	b := &staticBackend{accounts: []*Account{f.account("alice@example.test", false)}}
	cs := connect(t, New(Options{Backend: b, Mode: "test"}), nil)

	var list struct {
		Accounts []struct {
			Email  string
			Shared []struct {
				Name     string
				ReadOnly bool `json:"read_only"`
			}
		}
	}
	callJSON(t, cs, "list_accounts", nil, &list)
	if len(list.Accounts) != 1 || len(list.Accounts[0].Shared) != 2 ||
		list.Accounts[0].Shared[0].Name != "ro-archive@example.test" || !list.Accounts[0].Shared[0].ReadOnly ||
		list.Accounts[0].Shared[1].Name != "team@example.test" || list.Accounts[0].Shared[1].ReadOnly {
		t.Fatalf("list_accounts: %+v", list)
	}

	var mbs struct{ Account string }
	callJSON(t, cs, "list_mailboxes", map[string]any{"account": "Team@Example.test"}, &mbs)
	if mbs.Account != "team@example.test" || f.last() != "alice@example.test-1" {
		t.Fatalf("shared account: %+v, JMAP account %q", mbs, f.last())
	}
	callJSON(t, cs, "list_mailboxes", map[string]any{"account": "alice@example.test"}, &mbs)
	if mbs.Account != "alice@example.test" || f.last() != "alice@example.test-0" {
		t.Fatalf("login account: %+v, JMAP account %q", mbs, f.last())
	}
	callJSON(t, cs, "list_mailboxes", nil, &mbs)
	if f.last() != "alice@example.test-0" {
		t.Fatalf("default account: JMAP account %q", f.last())
	}
	for _, name := range []string{"Files", "nobody@example.test"} {
		if txt, isErr := call(t, cs, "list_mailboxes", map[string]any{"account": name}); !isErr || !strings.Contains(txt, "list_accounts") {
			t.Fatalf("account %q: %s", name, txt)
		}
	}

	// Two logins reach the same shared account: the default login is used, and without one the call fails.
	b.accounts = append(b.accounts, f.account("bob@example.test", false))
	if txt, isErr := call(t, cs, "list_mailboxes", map[string]any{"account": "team@example.test"}); !isErr || !strings.Contains(txt, "several connected accounts") {
		t.Fatalf("ambiguous shared account: %s", txt)
	}
	b.accounts[1].Default = true
	callJSON(t, cs, "list_mailboxes", map[string]any{"account": "team@example.test"}, &mbs)
	if f.last() != "bob@example.test-1" {
		t.Fatalf("shared account through the default login: JMAP account %q", f.last())
	}
}

// TestSharedAccountReplay runs the shared account scenario against recorded exchanges
// (refresh them with: JMAP_MCP_RECORD=$PWD/internal/tools/testdata/shared go test -tags integration -run TestStalwartSharedAccount ./internal/tools).
func TestSharedAccountReplay(t *testing.T) {
	url := testenv.Replay(t, "testdata/shared")
	sharedScenario(t, &Account{Email: "alice@example.test", Client: &jmapc.Client{HTTP: http.DefaultClient, SessionURL: url}}, "bob@example.test")
}

// sharedScenario reads and tags the inbox that owner shares with alice, through alice's login.
func sharedScenario(t *testing.T, alice *Account, owner string) {
	cs := connect(t, New(Options{Backend: &staticBackend{accounts: []*Account{alice}}, Mode: "test"}), nil)

	var list struct {
		Accounts []struct {
			Email  string
			Shared []struct{ Name string }
		}
	}
	callJSON(t, cs, "list_accounts", nil, &list)
	if len(list.Accounts) != 1 || len(list.Accounts[0].Shared) != 1 || !strings.EqualFold(list.Accounts[0].Shared[0].Name, owner) {
		t.Fatalf("list_accounts: %+v", list)
	}

	var search struct {
		Account string
		Total   int
		Emails  []mailview.Summary
	}
	callJSON(t, cs, "search_emails", nil, &search)
	if search.Account != alice.Email || search.Total != 0 {
		t.Fatalf("alice's own mailbox must be empty: %+v", search)
	}
	callJSON(t, cs, "search_emails", map[string]any{"account": owner, "subject": "Quarterly"}, &search)
	if !strings.EqualFold(search.Account, owner) || search.Total != 1 {
		t.Fatalf("search in the shared account: %+v", search)
	}
	var msg mailview.Message
	callJSON(t, cs, "get_email", map[string]any{"account": owner, "id": search.Emails[0].ID}, &msg)
	if msg.Subject != "Quarterly report" || !strings.Contains(msg.Body, "quarterly report") {
		t.Fatalf("get_email in the shared account: %+v", msg)
	}
	var upd struct{ Updated int }
	callJSON(t, cs, "update_emails", map[string]any{"account": owner, "ids": []string{msg.ID}, "add_keywords": []string{"$label:shared"}}, &upd)
	callJSON(t, cs, "search_emails", map[string]any{"account": owner, "keyword": "$label:shared"}, &search)
	if upd.Updated != 1 || search.Total != 1 || strings.Join(search.Emails[0].Keywords, ",") != "$label:shared" {
		t.Fatalf("keyword in the shared account: %+v %+v", upd, search)
	}
}
