// Package proxy serves MCP over HTTP without holding any credential: every request carries the
// caller's own bearer token for the mail server (an API key), which is used for that caller's
// JMAP calls and sent nowhere else.
//
// This is token passthrough, which the MCP authorization specification forbids for OAuth tokens
// issued to the MCP server. It suits clients that are given a mail-server API key directly; use
// serve for clients that sign in with OAuth.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/mikluko/jmap"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
	"github.com/kOlapsis/jmap-mcp/internal/netguard"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

// Limits of the proxy. A key is checked against the mail server when first seen and again
// after keyMaxAge, so a revoked key stops working within that time.
const (
	keyIdle         = 10 * time.Minute
	keyMaxAge       = 15 * time.Minute
	rejectedTTL     = 5 * time.Minute
	failureWindow   = 10 * time.Minute
	maxFailures     = 10
	lockout         = 15 * time.Minute
	sessionTimeout  = 20 * time.Second
	defaultKeyClass = "API_"
)

// Server is the credential-less HTTP mode.
type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	version string
	origin  string
	net     netguard.Options
	now     func() time.Time
	// keyPrefix restricts the accepted tokens to one kind (Stalwart API keys by default).
	keyPrefix string

	mu       sync.Mutex
	keys     map[[32]byte]*keyEntry
	rejected map[[32]byte]time.Time
	failures map[string]*failures
}

type keyEntry struct {
	srv      *tools.Server
	user     string
	created  time.Time
	lastUsed time.Time
}

type failures struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// New checks the configuration; it opens no connection.
func New(cfg *config.Config, version string, log *slog.Logger) (*Server, error) {
	origin, err := originOf(cfg.SessionURL)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, log: log, version: version, origin: origin, net: cfg.Net, now: time.Now, keyPrefix: defaultKeyClass,
		keys: map[[32]byte]*keyEntry{}, rejected: map[[32]byte]time.Time{}, failures: map[string]*failures{}}, nil
}

func originOf(raw string) (string, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	host, _, _ := strings.Cut(rest, "/")
	if !ok || host == "" || (scheme != "https" && scheme != "http") {
		return "", fmt.Errorf("invalid session URL %q", raw)
	}
	return scheme + "://" + strings.ToLower(host), nil
}

// Handler returns the routes: /mcp and /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	// Stateless: there is no MCP session another caller could take over. The SDK's DNS-rebinding guard
	// would refuse every request a local reverse proxy forwards under the public host name; a bearer
	// token is required on every request, and browsers are held off by the cross-origin protection.
	h := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		if e, ok := r.Context().Value(entryKey{}).(*keyEntry); ok {
			return e.srv.Server
		}
		return nil
	}, &mcp.StreamableHTTPOptions{Stateless: true, Logger: s.sdkLog(), DisableLocalhostProtection: true})
	mux.Handle("/mcp", http.NewCrossOriginProtection().Handler(s.authenticate(h)))
	return mux
}

type entryKey struct{}

// authenticate finds the tool server of the caller's key, refusing missing, rejected and locked-out callers.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if until, locked := s.locked(ip); locked {
			w.Header().Set("Retry-After", fmt.Sprint(int(until.Sub(s.now()).Seconds())+1))
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		token, ok := bearer(r)
		if !ok || !strings.HasPrefix(token, s.keyPrefix) {
			s.fail(ip)
			unauthorized(w, "send the mail server's API key as a bearer token")
			return
		}
		e, status, err := s.entry(r.Context(), token)
		if err != nil {
			switch status {
			case http.StatusUnauthorized:
				s.fail(ip)
				unauthorized(w, "the mail server rejected the token")
			case http.StatusForbidden:
				http.Error(w, "the token is valid but may not open a JMAP session; give it the permission to sign in (\"authenticate\" on Stalwart)", http.StatusForbidden)
			default:
				s.log.Warn("opening the JMAP session", "err", err)
				http.Error(w, "the mail server is unavailable", http.StatusBadGateway)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), entryKey{}, e)))
	})
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	http.Error(w, msg, http.StatusUnauthorized)
}

func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != ""
}

// entry returns the tool server of a key, opening its JMAP session when the key is new or due for a check.
func (s *Server) entry(ctx context.Context, token string) (*keyEntry, int, error) {
	h := sha256.Sum256([]byte(token))
	now := s.now()
	s.mu.Lock()
	if until, ok := s.rejected[h]; ok && now.Before(until) {
		s.mu.Unlock()
		return nil, http.StatusUnauthorized, errors.New("rejected recently")
	}
	if e, ok := s.keys[h]; ok && now.Sub(e.created) < keyMaxAge {
		e.lastUsed = now
		s.mu.Unlock()
		return e, 0, nil
	}
	s.mu.Unlock()

	e, err := s.open(ctx, token)
	var he *jmapc.HTTPError
	switch {
	case errors.Is(err, jmapc.ErrUnauthorized):
		s.mu.Lock()
		s.rejected[h] = now.Add(rejectedTTL)
		delete(s.keys, h)
		s.mu.Unlock()
		return nil, http.StatusUnauthorized, err
	case errors.As(err, &he) && he.Status == http.StatusForbidden:
		return nil, http.StatusForbidden, err
	case err != nil:
		return nil, http.StatusBadGateway, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.keys[h]; ok && now.Sub(old.created) < keyMaxAge {
		old.lastUsed = now
		return old, 0, nil
	}
	s.keys[h] = e
	s.log.Info("key accepted", "key", hex.EncodeToString(h[:4]), "account", e.user)
	return e, 0, nil
}

// open checks a key by opening its JMAP session and builds the tool server of its account.
func (s *Server) open(ctx context.Context, token string) (*keyEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	hc := s.net.Client(60 * time.Second)
	hc.Transport = &pinned{origin: s.origin, base: &mailauth.BearerTransport{
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}), Base: hc.Transport,
	}}
	c := &jmapc.Client{HTTP: hc, SessionURL: s.cfg.SessionURL}
	sess, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range []string{sess.APIURL, sess.UploadURL, sess.DownloadURL} {
		if u != "" && !strings.HasPrefix(strings.ToLower(u), s.origin+"/") {
			return nil, fmt.Errorf("the session names %s outside %s; refusing to send the token there", u, s.origin)
		}
	}
	name := sess.Username
	if name == "" {
		name = "token"
	}
	acct := &tools.Account{Email: name, Client: c, Default: true}
	srv := tools.New(tools.Options{Backend: &backend{acct: acct}, SendEnabled: s.cfg.EnableSend, Mode: "proxy", Version: s.version, Logger: s.sdkLog()})
	srv.Sync(ctx)
	now := s.now()
	return &keyEntry{srv: srv, user: name, created: now, lastUsed: now}, nil
}

// pinned refuses any request outside the mail server's origin, so the token never leaves it,
// whatever URL a session document or a redirect names.
type pinned struct {
	origin string
	base   http.RoundTripper
}

func (p *pinned) RoundTrip(req *http.Request) (*http.Response, error) {
	if o := strings.ToLower(req.URL.Scheme + "://" + req.URL.Host); o != p.origin {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("%w: %s is outside %s", netguard.ErrBlocked, o, p.origin)
	}
	return p.base.RoundTrip(req)
}

func (s *Server) locked(ip string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.failures[ip]
	if !ok {
		return time.Time{}, false
	}
	return f.lockedUntil, s.now().Before(f.lockedUntil)
}

// fail counts a failed attempt of ip and locks it out after maxFailures within failureWindow.
func (s *Server) fail(ip string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.failures[ip]
	if !ok || now.Sub(f.windowStart) > failureWindow {
		f = &failures{windowStart: now}
		s.failures[ip] = f
	}
	f.count++
	if f.count >= maxFailures {
		f.lockedUntil = now.Add(lockout)
		s.log.Warn("locking out a client after failed attempts", "client", ip, "failures", f.count)
	}
}

// purge forgets idle keys, expired rejections and old failure counts.
func (s *Server) purge() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, e := range s.keys {
		if now.Sub(e.lastUsed) > keyIdle || now.Sub(e.created) > keyMaxAge {
			delete(s.keys, h)
		}
	}
	for h, until := range s.rejected {
		if now.After(until) {
			delete(s.rejected, h)
		}
	}
	for ip, f := range s.failures {
		if now.After(f.lockedUntil) && now.Sub(f.windowStart) > failureWindow {
			delete(s.failures, ip)
		}
	}
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	hs := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.purge()
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	s.log.Info("proxy listening", "addr", s.cfg.Listen, "mail_server", s.origin, "send_enabled", s.cfg.EnableSend)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// clientIP is the peer address, or the last X-Forwarded-For hop when the peer is a reverse proxy
// on a private or loopback address: a client reaching the proxy directly cannot pick its own key.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || netguard.PublicAddr(peer) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
			return ip.String()
		}
	}
	return host
}

// sdkLog keeps the SDK's warnings and errors: in stateless mode it logs every request at info level.
func (s *Server) sdkLog() *slog.Logger {
	return slog.New(minLevel{Handler: s.log.Handler(), min: slog.LevelWarn})
}

type minLevel struct {
	slog.Handler
	min slog.Level
}

func (h minLevel) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.min && h.Handler.Enabled(ctx, l)
}

func (h minLevel) WithAttrs(as []slog.Attr) slog.Handler {
	return minLevel{Handler: h.Handler.WithAttrs(as), min: h.min}
}

func (h minLevel) WithGroup(name string) slog.Handler {
	return minLevel{Handler: h.Handler.WithGroup(name), min: h.min}
}

// backend is the single account of one key.
type backend struct{ acct *tools.Account }

func (b *backend) Accounts(context.Context) ([]*tools.Account, error) {
	return []*tools.Account{b.acct}, nil
}

func (b *backend) SetDefault(_ context.Context, email string) error {
	if strings.EqualFold(email, b.acct.Email) {
		return nil
	}
	return fmt.Errorf("unknown account %q", email)
}

// AttachmentLink is not available: a link would need either stored state or the caller's key.
func (b *backend) AttachmentLink(context.Context, *mcp.CallToolRequest, *tools.Account, jmap.ID, mailview.Attachment) (string, error) {
	return "", errors.New("this attachment is too large to return inline, and the proxy mode offers no download links")
}
