package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

// fakeMail serves one JMAP session per API key: API_alice and API_bob open their own account,
// API_weak may not open a session (403), API_evil names an API URL on another host, and any
// other token is rejected (401). Mailbox/get returns one inbox named after the account.
type fakeMail struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func newFakeMail(t *testing.T) *fakeMail {
	t.Helper()
	f := &fakeMail{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		user := map[string]string{"Bearer API_alice": "alice@example.test", "Bearer API_bob": "bob@example.test", "Bearer API_evil": "eve@example.test"}[r.Header.Get("Authorization")]
		switch {
		case r.Header.Get("Authorization") == "Bearer API_weak":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"type":"about:blank","status":403,"detail":"You do not have enough permissions to access this resource."}`)
			return
		case user == "":
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/jmap/session" {
			api := "/jmap/"
			if user == "eve@example.test" {
				api = "https://elsewhere.example/jmap/"
			}
			_, _ = fmt.Fprintf(w, `{"capabilities":{"urn:ietf:params:jmap:core":{},"urn:ietf:params:jmap:mail":{}},`+
				`"accounts":{"a":{"name":%q,"isPersonal":true,"accountCapabilities":{"urn:ietf:params:jmap:mail":{}}}},`+
				`"primaryAccounts":{"urn:ietf:params:jmap:mail":"a"},"username":%q,"apiUrl":%q,`+
				`"downloadUrl":"/jmap/download/{accountId}/{blobId}/{name}?accept={type}","uploadUrl":"/jmap/upload/{accountId}/","state":"s"}`, user, user, api)
			return
		}
		_, _ = fmt.Fprintf(w, `{"methodResponses":[["Mailbox/get",{"accountId":"a","state":"1","notFound":[],`+
			`"list":[{"id":"in","name":%q,"role":"inbox","totalEmails":1,"unreadEmails":0}]},"0"]],"sessionState":"s"}`, "Inbox of "+user)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type testProxy struct {
	*Server
	http *httptest.Server
	now  time.Time
}

func newProxy(t *testing.T, mail *fakeMail) *testProxy {
	t.Helper()
	cfg := &config.Config{Command: "proxy", SessionURL: mail.srv.URL + "/jmap/session", Net: netguard.Options{AllowPrivate: true, InsecureTLS: true}}
	s, err := New(cfg, "test", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p := &testProxy{Server: s, now: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	s.now = func() time.Time { return p.now }
	p.http = httptest.NewServer(s.Handler())
	t.Cleanup(p.http.Close)
	return p
}

type headerTransport struct {
	header http.Header
	base   http.RoundTripper
}

func (h *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.header {
		r.Header[k] = v
	}
	return h.base.RoundTrip(r)
}

// connect opens an MCP client session that sends token as its bearer token.
func (p *testProxy) connect(t *testing.T, token string) (*mcp.ClientSession, error) {
	t.Helper()
	hc := &http.Client{Transport: &headerTransport{header: http.Header{"Authorization": {"Bearer " + token}}, base: http.DefaultTransport}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "proxy-test", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: p.http.URL + "/mcp", HTTPClient: hc, MaxRetries: -1}, nil)
	if err == nil {
		t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, err
}

// post sends a raw initialize request and returns the response.
func (p *testProxy) post(t *testing.T, header http.Header) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, p.http.URL+"/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func inbox(t *testing.T, cs *mcp.ClientSession) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_mailboxes", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list_mailboxes: %v %+v", err, res)
	}
	var out struct {
		Account   string
		Mailboxes []struct{ Path string }
	}
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out); err != nil || len(out.Mailboxes) != 1 {
		t.Fatalf("list_mailboxes result: %v %+v", err, res.Content)
	}
	return out.Account + ": " + out.Mailboxes[0].Path
}

func TestProxyServesEachKeyItsOwnAccount(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	alice, err := p.connect(t, "API_alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := p.connect(t, "API_bob")
	if err != nil {
		t.Fatal(err)
	}
	if got := inbox(t, alice); got != "alice@example.test: Inbox of alice@example.test" {
		t.Errorf("alice sees %q", got)
	}
	if got := inbox(t, bob); got != "bob@example.test: Inbox of bob@example.test" {
		t.Errorf("bob sees %q", got)
	}
	tl, err := alice.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tl.Tools {
		if tool.Name == "send_email" || tool.Name == "connect_account" {
			t.Errorf("%s must not be exposed by the proxy without --enable-send", tool.Name)
		}
	}
}

func TestProxyRejectsWithoutContactingTheMailServer(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	for name, h := range map[string]http.Header{
		"no header":         {},
		"basic credentials": {"Authorization": {"Basic YWxpY2U6c2VjcmV0"}},
		"not an API key":    {"Authorization": {"Bearer eyJhbGciOi.fake.jwt"}},
	} {
		resp := p.post(t, h)
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: HTTP %d, WWW-Authenticate %q", name, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}
	if n := mail.hits.Load(); n != 0 {
		t.Fatalf("the mail server was contacted %d times", n)
	}
}

func TestProxyCachesRejectedKeys(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	h := http.Header{"Authorization": {"Bearer API_wrong"}}
	for range 3 {
		if resp := p.post(t, h); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong key: HTTP %d", resp.StatusCode)
		}
	}
	if n := mail.hits.Load(); n != 1 {
		t.Fatalf("a rejected key must be checked once, the mail server saw %d requests", n)
	}
	p.now = p.now.Add(rejectedTTL + time.Second)
	p.post(t, h)
	if n := mail.hits.Load(); n != 2 {
		t.Fatalf("after %s the key is checked again; the mail server saw %d requests", rejectedTTL, n)
	}
}

func TestProxyLocksOutAfterFailures(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	for i := range maxFailures {
		if resp := p.post(t, http.Header{"Authorization": {fmt.Sprintf("Bearer API_guess%d", i)}}); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: HTTP %d", i, resp.StatusCode)
		}
	}
	resp := p.post(t, http.Header{"Authorization": {"Bearer API_alice"}})
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("locked out client: HTTP %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	p.now = p.now.Add(lockout + time.Second)
	if _, err := p.connect(t, "API_alice"); err != nil {
		t.Fatalf("after the lockout: %v", err)
	}
}

func TestProxyLockoutUsesTheForwardedClient(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	for i := range maxFailures {
		p.post(t, http.Header{"Authorization": {fmt.Sprintf("Bearer API_guess%d", i)}, "X-Forwarded-For": {"203.0.113.7"}})
	}
	if resp := p.post(t, http.Header{"Authorization": {"Bearer API_alice"}, "X-Forwarded-For": {"198.51.100.9"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("another client behind the reverse proxy must not be locked out: HTTP %d", resp.StatusCode)
	}
	if resp := p.post(t, http.Header{"Authorization": {"Bearer API_alice"}, "X-Forwarded-For": {"203.0.113.7"}}); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the guessing client must be locked out: HTTP %d", resp.StatusCode)
	}
}

func TestProxyKeyWithoutSignInPermission(t *testing.T) {
	p := newProxy(t, newFakeMail(t))
	if resp := p.post(t, http.Header{"Authorization": {"Bearer API_weak"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP %d, want 403", resp.StatusCode)
	}
}

func TestProxyRefusesForeignSessionURLs(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	if resp := p.post(t, http.Header{"Authorization": {"Bearer API_evil"}}); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("HTTP %d, want 502", resp.StatusCode)
	}
	pin := &pinned{origin: "https://mail.example.test", base: http.DefaultTransport}
	req, _ := http.NewRequest(http.MethodGet, "https://elsewhere.example/jmap/", nil)
	if _, err := pin.RoundTrip(req); err == nil {
		t.Fatal("a request outside the mail server's origin must be refused")
	}
}

func TestProxyRechecksKeys(t *testing.T) {
	mail := newFakeMail(t)
	p := newProxy(t, mail)
	cs, err := p.connect(t, "API_alice")
	if err != nil {
		t.Fatal(err)
	}
	inbox(t, cs)
	before := mail.hits.Load()
	inbox(t, cs)
	if n := mail.hits.Load() - before; n != 1 {
		t.Fatalf("a known key must not reopen its session: %d requests for one call", n)
	}
	p.now = p.now.Add(keyMaxAge + time.Second)
	before = mail.hits.Load()
	inbox(t, cs)
	if n := mail.hits.Load() - before; n != 2 {
		t.Fatalf("after %s the key must be checked again: %d requests for one call", keyMaxAge, n)
	}
	p.purge()
	if len(p.keys) != 1 {
		t.Fatalf("the rechecked key must stay cached: %d", len(p.keys))
	}
	p.now = p.now.Add(keyIdle + time.Second)
	p.purge()
	if len(p.keys) != 0 {
		t.Fatalf("an idle key must be forgotten: %d", len(p.keys))
	}
}

func TestProxyCrossOriginAndHealth(t *testing.T) {
	p := newProxy(t, newFakeMail(t))
	resp := p.post(t, http.Header{"Authorization": {"Bearer API_alice"}, "Sec-Fetch-Site": {"cross-site"}, "Origin": {"https://evil.example"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin browser request: HTTP %d, want 403", resp.StatusCode)
	}
	hr, err := http.Get(p.http.URL + "/healthz")
	if err != nil || hr.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", err, hr)
	}
	_ = hr.Body.Close()
}

func TestNewNeedsAValidSessionURL(t *testing.T) {
	if _, err := New(&config.Config{SessionURL: "mail.example.test"}, "test", slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a session URL without scheme must be refused")
	}
}
