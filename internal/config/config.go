// Package config parses the optional deployment settings.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

// Config holds deployment settings; every field has a working default.
type Config struct {
	Command    string
	DataDir    string
	Listen     string
	PublicURL  string
	LogLevel   slog.Level
	EnableSend bool
	Stateless  bool
	Net        netguard.Options

	Args         []string
	ClientID     string
	ClientSecret string
	ClientAuth   string

	// Token is a static bearer credential (an API key or a long-lived access token) for the
	// local mode; SessionURL is its JMAP session URL, or an email address to discover it from.
	Token      string
	SessionURL string
}

// EnvPrefix prefixes the environment variable form of every flag.
const EnvPrefix = "JMAP_MCP_"

// Parse reads flags, falling back to JMAP_MCP_* environment variables.
func Parse(args []string, stderr io.Writer) (*Config, error) {
	c := &Config{}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		c.Command, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("jmap-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var level, resolve, tokenFile, devToken, devSessionURL string
	str := func(p *string, name, def, usage string) { fs.StringVar(p, name, env(name, def), usage) }
	boolean := func(p *bool, name, usage string) {
		v, _ := strconv.ParseBool(env(name, "false"))
		fs.BoolVar(p, name, v, usage)
	}
	str(&c.DataDir, "data-dir", "", "data directory (default: $XDG_CONFIG_HOME/jmap-mcp or OS equivalent)")
	str(&c.Listen, "listen", ":8080", "HTTP listen address of serve (default :8080)")
	str(&c.PublicURL, "public-url", "", "public base URL of the bridge (default: derived from X-Forwarded-* headers)")
	str(&level, "log-level", "info", "log level: debug, info (default), warn, error")
	boolean(&c.EnableSend, "enable-send", "allow sending email (always confirmed by the user)")
	boolean(&c.Stateless, "stateless", "use stateless Streamable HTTP for MCP requests (serve)")
	boolean(&c.Net.AllowPrivate, "allow-private-networks", "allow mail servers on private or loopback addresses (disables part of the SSRF protection)")
	boolean(&c.Net.AllowHTTP, "dev-allow-http", "development only: accept plain http mail servers")
	boolean(&c.Net.InsecureTLS, "dev-insecure-tls", "development only: skip TLS certificate verification")
	str(&resolve, "dev-resolve", "", "development only: comma-separated host:port=ip:port overrides")
	str(&c.ClientID, "client-id", "", "client add: client ID declared at the authorization server")
	str(&c.ClientSecret, "client-secret", "", "client add: client secret, empty for a public client")
	str(&c.ClientAuth, "auth-method", "", "client add: none (default without secret), client_secret_basic (default with a secret) or client_secret_post")
	str(&c.SessionURL, "session-url", "", "stdio with a static token: JMAP session URL, or an email address to discover it from; proxy: the JMAP session URL")
	str(&tokenFile, "token-file", "", "stdio with a static token: file holding the bearer token (an API key); "+EnvPrefix+"TOKEN passes it directly")
	str(&devToken, "dev-token", "", "deprecated: use "+EnvPrefix+"TOKEN or --token-file")
	str(&devSessionURL, "dev-session-url", "", "deprecated: use --session-url")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: jmap-mcp [stdio|serve|proxy|client add|admin-token|healthcheck|version] [flags]\n\n  stdio         MCP server on standard input and output (default)\n  serve         MCP server over HTTP with OAuth\n  proxy         MCP server over HTTP without credentials: each client sends its own mail-server token\n  client add <email or JMAP session URL> --client-id ID\n                declare a static OAuth client for the local mode\n  admin-token   print the token of the /admin page\n  healthcheck   exit 0 when the local HTTP server answers /healthz\n\nFlags (also read from %s<FLAG_NAME>):\n", EnvPrefix)
		fs.VisitAll(func(f *flag.Flag) {
			if !strings.HasPrefix(f.Name, "dev-") {
				fmt.Fprintf(stderr, "  --%s\n    \t%s\n", f.Name, f.Usage)
			}
		})
	}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		c.Args, args = append(c.Args, fs.Arg(0)), fs.Args()[1:]
	}
	if err := c.LogLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	if resolve != "" {
		c.Net.Resolve = map[string]string{}
		for _, kv := range strings.Split(resolve, ",") {
			from, to, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok {
				return nil, fmt.Errorf("invalid --dev-resolve entry %q", kv)
			}
			c.Net.Resolve[from] = to
		}
	}
	if err := c.staticToken(tokenFile, devToken, devSessionURL); err != nil {
		return nil, err
	}
	if c.DataDir == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("no data directory: pass --data-dir (%w)", err)
		}
		c.DataDir = filepath.Join(dir, "jmap-mcp")
	}
	return c, nil
}

// staticToken settles the static credential of the local mode. The token itself is never a flag,
// so that it does not show up in the process list: it comes from JMAP_MCP_TOKEN or a file.
func (c *Config) staticToken(tokenFile, devToken, devSessionURL string) error {
	envToken, hasEnv := os.LookupEnv(EnvPrefix + "TOKEN")
	sources := 0
	for _, set := range []bool{hasEnv && envToken != "", tokenFile != "", devToken != ""} {
		if set {
			sources++
		}
	}
	if sources > 1 {
		return errors.New("give the token once: " + EnvPrefix + "TOKEN, --token-file or --dev-token")
	}
	switch {
	case tokenFile != "":
		t, err := readTokenFile(tokenFile)
		if err != nil {
			return err
		}
		c.Token = t
	case devToken != "":
		c.Token = devToken
	default:
		c.Token = strings.TrimSpace(envToken)
	}
	if devSessionURL != "" {
		if c.SessionURL != "" {
			return errors.New("--session-url and --dev-session-url are the same setting; keep --session-url")
		}
		c.SessionURL = devSessionURL
	}
	if c.Command == "proxy" {
		if c.Token != "" {
			return errors.New("proxy holds no credential: each MCP client sends its own token; unset the static token")
		}
		plainHTTP := c.Net.AllowHTTP && strings.HasPrefix(c.SessionURL, "http://")
		if !strings.HasPrefix(c.SessionURL, "https://") && !plainHTTP {
			return errors.New("proxy needs --session-url, the https URL of the JMAP session of the mail server")
		}
		return nil
	}
	if (c.Token == "") != (c.SessionURL == "") {
		return errors.New("a static token and --session-url go together")
	}
	if c.Token != "" && c.Command != "" && c.Command != "stdio" {
		return fmt.Errorf("a static token only works in the local mode (stdio), not with %q", c.Command)
	}
	return nil
}

// readTokenFile reads a token that only its owner may read, as ssh does for private keys.
func readTokenFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s is readable by others (mode %04o); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return t, nil
}

func env(flagName, def string) string {
	if v, ok := os.LookupEnv(EnvPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))); ok {
		return v
	}
	return def
}
