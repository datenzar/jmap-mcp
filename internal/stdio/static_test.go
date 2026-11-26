package stdio

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

type noSRV struct{}

func (noSRV) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, errors.New("no SRV")
}

// sessionServer answers the session resource for "Bearer good", 403 for "Bearer weak" and 401 otherwise.
func sessionServer(t *testing.T, username string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer good":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"capabilities":{"urn:ietf:params:jmap:core":{},"urn:ietf:params:jmap:mail":{}},` +
				`"accounts":{"a":{"name":"x","isPersonal":true}},"primaryAccounts":{"urn:ietf:params:jmap:mail":"a"},` +
				`"username":"` + username + `","apiUrl":"/jmap/","state":"s1"}`))
		case "Bearer weak":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"type":"about:blank","status":403,"detail":"You do not have enough permissions to access this resource."}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func staticConfig(srv *httptest.Server, token string) *config.Config {
	return &config.Config{
		Token:      token,
		SessionURL: srv.URL + "/jmap/session",
		Net:        netguard.Options{AllowPrivate: true, InsecureTLS: true},
	}
}

func TestStaticAccountNamedAfterSessionUser(t *testing.T) {
	srv := sessionServer(t, "alice@example.test")
	acct, err := staticAccount(context.Background(), staticConfig(srv, "good"), noSRV{})
	if err != nil {
		t.Fatal(err)
	}
	if acct.Email != "alice@example.test" || !acct.Default {
		t.Fatalf("account = %+v", acct)
	}
	id, err := acct.Client.MailAccount(context.Background())
	if err != nil || id != "a" {
		t.Fatalf("MailAccount = %q, %v", id, err)
	}
	if want := srv.URL + "/jmap/"; acct.Client.HTTP == nil || mustSession(t, acct.Client).APIURL != want {
		t.Fatalf("apiUrl not resolved against the session URL, want %s", want)
	}
}

func TestStaticAccountWithoutUsername(t *testing.T) {
	acct, err := staticAccount(context.Background(), staticConfig(sessionServer(t, ""), "good"), noSRV{})
	if err != nil {
		t.Fatal(err)
	}
	if acct.Email != "token" {
		t.Fatalf("Email = %q, want token", acct.Email)
	}
}

func TestStaticAccountRejectedToken(t *testing.T) {
	srv := sessionServer(t, "alice@example.test")
	if _, err := staticAccount(context.Background(), staticConfig(srv, "wrong"), noSRV{}); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Fatalf("err = %v, want the token to be reported as rejected", err)
	}
	_, err := staticAccount(context.Background(), staticConfig(srv, "weak"), noSRV{})
	if err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("err = %v, want a hint about the sign-in permission", err)
	}
}

func TestStaticAccountRefusesPrivateAddressByDefault(t *testing.T) {
	cfg := staticConfig(sessionServer(t, "alice@example.test"), "good")
	cfg.Net = netguard.Options{}
	if _, err := staticAccount(context.Background(), cfg, noSRV{}); err == nil {
		t.Fatal("a loopback session URL must be refused without --allow-private-networks")
	}
}

func mustSession(t *testing.T, c *jmapc.Client) *jmapc.Session {
	t.Helper()
	s, err := c.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
