package estlab

import "testing"

// clearEnvironment removes every variable the package reads, so a case states its whole
// input rather than inheriting the shell the suite happens to run in.
func clearEnvironment(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"EST_LAB_SERVER", "EST_LAB_LABEL", "EST_LAB_USERNAME",
		"EST_LAB_PASSWORD", "EST_LAB_CA_FILE", "EST_LAB_DOMAIN",
	} {
		t.Setenv(name, "")
	}
}

func TestGivenNoEnvironmentWhenReadingThenTheLocalLabIsUsed(t *testing.T) {
	// Given
	clearEnvironment(t)

	// When
	cfg := ReadConfigFromEnv()

	// Then: the lab needs no label and no credentials, so an unset environment has to be
	// enough to run the suite from a clean checkout.
	if cfg.Server != DefaultServer {
		t.Errorf("Server = %q, want %q", cfg.Server, DefaultServer)
	}
	if cfg.Domain != DefaultDomain {
		t.Errorf("Domain = %q, want %q", cfg.Domain, DefaultDomain)
	}
	if cfg.Label != "" || cfg.Username != "" || cfg.Password != "" || cfg.TrustedCAFile != "" {
		t.Errorf("expected no label, credentials or trust file, got %+v", cfg)
	}
}

func TestGivenAFullEnvironmentWhenReadingThenEveryValueIsCarried(t *testing.T) {
	// Given
	clearEnvironment(t)
	t.Setenv("EST_LAB_SERVER", "https://pki.example.com:8443")
	t.Setenv("EST_LAB_LABEL", "tlsserver")
	t.Setenv("EST_LAB_USERNAME", "est-client")
	t.Setenv("EST_LAB_PASSWORD", "secret")
	t.Setenv("EST_LAB_CA_FILE", "/etc/pki/ca.pem")
	t.Setenv("EST_LAB_DOMAIN", "pki.example.com")

	// When
	cfg := ReadConfigFromEnv()

	// Then
	want := Config{
		Server:        "https://pki.example.com:8443",
		Label:         "tlsserver",
		Username:      "est-client",
		Password:      "secret",
		TrustedCAFile: "/etc/pki/ca.pem",
		Domain:        "pki.example.com",
	}
	if cfg != want {
		t.Errorf("ReadConfigFromEnv() = %+v, want %+v", cfg, want)
	}
}

func TestGivenADomainWhenNamingThenTheNameIsBuiltUnderIt(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		label  string
		want   string
	}{
		{"the default domain", "", "renewal", "renewal.example.com"},
		{"a constrained domain", "pki.example.com", "renewal", "renewal.pki.example.com"},
		{"a trailing dot is not doubled", "example.com.", "renewal", "renewal.example.com"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given
			clearEnvironment(t)
			if testCase.domain != "" {
				t.Setenv("EST_LAB_DOMAIN", testCase.domain)
			}

			// When
			got := ReadConfigFromEnv().NameFor(testCase.label)

			// Then: a CA that constrains the names it will issue still has to be testable,
			// which it is not if the suite hard-codes example.com.
			if got != testCase.want {
				t.Errorf("NameFor(%q) = %q, want %q", testCase.label, got, testCase.want)
			}
		})
	}
}
