package jwksauth

import (
	"strings"
	"testing"
)

func TestParseIssuerDomains_EmptyDisablesEnforcement(t *testing.T) {
	out, err := ParseIssuerDomains("", []string{"https://a", "https://b"})
	if err != nil {
		t.Fatalf("ParseIssuerDomains(\"\"): %v", err)
	}
	if out != nil {
		t.Errorf("empty input should return nil map, got %v", out)
	}
}

func TestParseIssuerDomains_HappyPath(t *testing.T) {
	known := []string{"https://a", "https://b"}
	out, err := ParseIssuerDomains("https://a=oa,hwrd;https://b=swrd", known)
	if err != nil {
		t.Fatalf("ParseIssuerDomains: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d issuers, want 2", len(out))
	}
	if got := out["https://a"]; len(got) != 2 || got[0] != "oa" || got[1] != "hwrd" {
		t.Errorf("https://a domains = %v, want [oa hwrd]", got)
	}
	if got := out["https://b"]; len(got) != 1 || got[0] != "swrd" {
		t.Errorf("https://b domains = %v, want [swrd]", got)
	}
}

func TestParseIssuerDomains_LowerCases(t *testing.T) {
	out, err := ParseIssuerDomains("https://a=OA,HwRd", []string{"https://a"})
	if err != nil {
		t.Fatalf("ParseIssuerDomains: %v", err)
	}
	got := out["https://a"]
	if len(got) != 2 || got[0] != "oa" || got[1] != "hwrd" {
		t.Errorf("domains = %v, want lower-cased [oa hwrd]", got)
	}
}

func TestParseIssuerDomains_RejectsUnknownIssuer(t *testing.T) {
	_, err := ParseIssuerDomains("https://typo=oa", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "not a registered issuer") {
		t.Fatalf("error = %v, want 'not a registered issuer'", err)
	}
}

func TestParseIssuerDomains_RequiresEveryKnownIssuer(t *testing.T) {
	_, err := ParseIssuerDomains("https://a=oa", []string{"https://a", "https://b"})
	if err == nil || !strings.Contains(err.Error(), "missing from") {
		t.Fatalf("error = %v, want 'missing from'", err)
	}
}

func TestParseIssuerDomains_DistinguishesDuplicateFromOverlap(t *testing.T) {
	// Same issuer, same domain twice — typo, not cross-issuer overlap.
	_, err := ParseIssuerDomains("https://a=oa,oa", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "drop the duplicate") {
		t.Fatalf("same-issuer dup: error = %v, want 'drop the duplicate'", err)
	}

	// Different issuers, same domain — true cross-issuer overlap.
	_, err = ParseIssuerDomains("https://a=oa;https://b=oa", []string{"https://a", "https://b"})
	if err == nil || !strings.Contains(err.Error(), "multiple issuers") {
		t.Fatalf("cross-issuer overlap: error = %v, want 'multiple issuers'", err)
	}
}

func TestParseIssuerDomains_RejectsEmptyDomainList(t *testing.T) {
	_, err := ParseIssuerDomains("https://a=", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "no domains") {
		t.Fatalf("error = %v, want 'no domains'", err)
	}
}

func TestParseIssuerDomains_RejectsMalformedEntry(t *testing.T) {
	_, err := ParseIssuerDomains("https://a", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("error = %v, want 'malformed'", err)
	}
}

func TestParseIssuerDomains_DuplicateIssuerInRaw(t *testing.T) {
	_, err := ParseIssuerDomains(
		"https://a=oa;https://a=hwrd",
		[]string{"https://a"},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want 'duplicate'", err)
	}
}
