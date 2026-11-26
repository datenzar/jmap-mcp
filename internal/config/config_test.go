package config

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseFlagsAfterArguments(t *testing.T) {
	dir := t.TempDir()
	c, err := Parse([]string{"client", "add", "alice@example.com", "--client-id", "webui", "--data-dir", dir}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Command != "client" || !slices.Equal(c.Args, []string{"add", "alice@example.com"}) || c.ClientID != "webui" || c.DataDir != dir {
		t.Fatalf("%+v", c)
	}
}

func TestStaticToken(t *testing.T) {
	const url = "https://mail.example.test/jmap/session"
	writeToken := func(t *testing.T, mode os.FileMode, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("from the environment", func(t *testing.T) {
		t.Setenv(EnvPrefix+"TOKEN", " API_abc\n")
		c, err := Parse([]string{"stdio", "--session-url", url}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if c.Token != "API_abc" || c.SessionURL != url {
			t.Fatalf("%+v", c)
		}
	})

	t.Run("from a file", func(t *testing.T) {
		t.Setenv(EnvPrefix+"SESSION_URL", url)
		c, err := Parse([]string{"--token-file", writeToken(t, 0o600, "API_file\n")}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if c.Token != "API_file" || c.SessionURL != url {
			t.Fatalf("%+v", c)
		}
	})

	t.Run("deprecated dev flags", func(t *testing.T) {
		c, err := Parse([]string{"--dev-token", "API_dev", "--dev-session-url", url}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if c.Token != "API_dev" || c.SessionURL != url {
			t.Fatalf("%+v", c)
		}
	})

	for name, tc := range map[string]struct {
		env  string
		args []string
		want string
	}{
		"token without session url":        {env: "API_x", args: []string{"stdio"}, want: "go together"},
		"session url without token":        {args: []string{"stdio", "--session-url", url}, want: "go together"},
		"two token sources":                {env: "API_x", args: []string{"--dev-token", "API_y", "--session-url", url}, want: "once"},
		"static token with serve":          {env: "API_x", args: []string{"serve", "--session-url", url}, want: "local mode"},
		"session url given twice":          {env: "API_x", args: []string{"--session-url", url, "--dev-session-url", url}, want: "same setting"},
		"token file readable by the group": {args: []string{"--session-url", url, "--token-file", "MODE640"}, want: "readable by others"},
		"empty token file":                 {args: []string{"--session-url", url, "--token-file", "EMPTY"}, want: "empty"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv(EnvPrefix+"TOKEN", tc.env)
			}
			args := slices.Clone(tc.args)
			for i, a := range args {
				switch a {
				case "MODE640":
					args[i] = writeToken(t, 0o640, "API_z")
				case "EMPTY":
					args[i] = writeToken(t, 0o600, " \n")
				}
			}
			_, err := Parse(args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestProxyConfig(t *testing.T) {
	const url = "https://mail.example.test/jmap/session"
	c, err := Parse([]string{"proxy", "--session-url", url}, io.Discard)
	if err != nil || c.Command != "proxy" || c.SessionURL != url || c.Token != "" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, tc := range map[string]struct {
		env  string
		args []string
		want string
	}{
		"no session url":    {args: []string{"proxy"}, want: "--session-url"},
		"email instead":     {args: []string{"proxy", "--session-url", "alice@example.test"}, want: "--session-url"},
		"plain http":        {args: []string{"proxy", "--session-url", "http://mail.example.test/jmap/session"}, want: "--session-url"},
		"with static token": {env: "API_x", args: []string{"proxy", "--session-url", url}, want: "no credential"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv(EnvPrefix+"TOKEN", tc.env)
			}
			if _, err := Parse(tc.args, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestStatelessFlag(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		t.Setenv(EnvPrefix+"STATELESS", "false")
		cfg, err := Parse([]string{"serve"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Stateless {
			t.Fatal("Stateless = true, want false by default")
		}
	})

	t.Run("enabled by flag", func(t *testing.T) {
		cfg, err := Parse([]string{"serve", "--stateless"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Stateless {
			t.Fatal("Stateless = false, want true")
		}
	})

	t.Run("enabled by environment", func(t *testing.T) {
		t.Setenv(EnvPrefix+"STATELESS", "true")
		cfg, err := Parse([]string{"serve"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Stateless {
			t.Fatal("Stateless = false, want true from environment")
		}
	})
}
