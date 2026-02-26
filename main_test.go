package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCategorizeDeterministicPriority(t *testing.T) {
	got := categorize("certificate expired on TLS1 endpoint")
	if got != "Protocol Weakness" {
		t.Fatalf("expected deterministic protocol priority, got %q", got)
	}
}

func TestIsCipherFinding(t *testing.T) {
	t.Run("id based cipher finding", func(t *testing.T) {
		f := Finding{
			ID:      "cipher-tls1_2_xc02f",
			Finding: "TLSv1.2 ... TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		}
		if !isCipherFinding(f) {
			t.Fatalf("expected cipher finding for id=%q", f.ID)
		}
	})

	t.Run("protocol finding should not be cipher", func(t *testing.T) {
		f := Finding{
			ID:      "TLS1_3",
			Finding: "offered + downgraded to weaker protocol",
		}
		if isCipherFinding(f) {
			t.Fatalf("did not expect protocol-only finding to be treated as cipher finding")
		}
	})
}

func TestFilterSecurityFindingsThresholdAndDedup(t *testing.T) {
	in := []Finding{
		{ID: "A", Severity: "HIGH", Finding: "x", Host: "h", Port: "443", SortScore: severityScore["HIGH"]},
		{ID: "A", Severity: "HIGH", Finding: "x", Host: "h", Port: "443", SortScore: severityScore["HIGH"]},
		{ID: "B", Severity: "LOW", Finding: "y", Host: "h", Port: "443", SortScore: severityScore["LOW"]},
		{ID: "C", Severity: "INFO", Finding: "z", Host: "h", Port: "443", SortScore: severityScore["INFO"]},
	}

	got := filterSecurityFindings(in, "MEDIUM")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding after dedupe + threshold, got %d", len(got))
	}
	if got[0].ID != "A" {
		t.Fatalf("expected finding A, got %q", got[0].ID)
	}
}

func TestParseFindingsNestedJSON(t *testing.T) {
	raw := []byte(`{"results":[{"id":"TLS1","severity":"LOW","finding":"offered"}]}`)
	findings, err := parseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "TLS1" {
		t.Fatalf("expected ID TLS1, got %q", findings[0].ID)
	}
}

func TestIndexHandlerRejectsOversizedRequest(t *testing.T) {
	values := url.Values{
		"minSeverity": {"MEDIUM"},
		"jsonText":    {strings.Repeat("a", int(maxRequestBytes)+1024)},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	indexHandler(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "request is too large") {
		t.Fatalf("expected size limit message, got body: %s", body)
	}
}

func TestCipherRiskTypes(t *testing.T) {
	tests := []struct {
		name string
		in   Finding
		want []string
	}{
		{
			name: "cbc sha1 and no fs",
			in: Finding{
				ID:        "cipher-tls1_2_x2f",
				Finding:   "TLSv1.2 ... TLS_RSA_WITH_AES_128_CBC_SHA",
				SortScore: severityScore["HIGH"],
			},
			want: []string{"No Forward Secrecy", "CBC Mode", "SHA-1 MAC"},
		},
		{
			name: "3des and rc4 and export",
			in: Finding{
				ID:        "cipherlist_EXPORT",
				Finding:   "supports RC4 and DES-CBC3",
				SortScore: severityScore["HIGH"],
			},
			want: []string{"CBC Mode", "3DES / SWEET32", "RC4", "Export-grade Cipher"},
		},
		{
			name: "fallback risk",
			in: Finding{
				ID:        "cipher-something",
				Finding:   "custom cipher weakness",
				SortScore: severityScore["LOW"],
			},
			want: []string{"Other Cipher Weakness"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cipherRiskTypes(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("cipherRiskTypes() mismatch\nwant=%v\ngot=%v", tc.want, got)
			}
		})
	}
}

func TestExtractCipherSuite(t *testing.T) {
	tests := []struct {
		name string
		in   Finding
		want string
	}{
		{
			name: "suite from structured finding line",
			in: Finding{
				ID:      "cipher-tls1_2_xc02f",
				Finding: "TLSv1.2   xc02f   ECDHE-RSA-AES128-GCM-SHA256   ECDH 253   AESGCM",
			},
			want: "ECDHE-RSA-AES128-GCM-SHA256",
		},
		{
			name: "fallback to id",
			in: Finding{
				ID:      "cipherlist_LOW",
				Finding: "not offered",
			},
			want: "cipherlist_LOW",
		},
		{
			name: "fallback to finding text",
			in: Finding{
				Finding: "unknown suite line",
			},
			want: "unknown suite line",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractCipherSuite(tc.in)
			if got != tc.want {
				t.Fatalf("extractCipherSuite() mismatch: want=%q got=%q", tc.want, got)
			}
		})
	}
}

func TestWeaknessTemplateFileName(t *testing.T) {
	got := weaknessTemplateFileName("3DES / SWEET32")
	if got != "3des_sweet32.md" {
		t.Fatalf("expected 3des_sweet32.md, got %q", got)
	}
}

func TestBuildCipherWeaknessReports(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cbc_mode.md"), []byte("cbc guidance"), 0o644); err != nil {
		t.Fatalf("write cbc template: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rc4.md"), []byte("rc4 guidance"), 0o644); err != nil {
		t.Fatalf("write rc4 template: %v", err)
	}

	originalDir := reportTemplatesDir
	reportTemplatesDir = dir
	t.Cleanup(func() {
		reportTemplatesDir = originalDir
	})

	rows := []WeakCipher{
		{Risks: "CBC Mode, RC4"},
		{Risks: "CBC Mode"},
	}

	got := buildCipherWeaknessReports(rows)
	if len(got) != 2 {
		t.Fatalf("expected 2 report items, got %d", len(got))
	}

	if got[0].Name != "CBC Mode" || got[0].Count != 2 || got[0].Content != "cbc guidance" {
		t.Fatalf("unexpected CBC report item: %+v", got[0])
	}
	if got[1].Name != "RC4" || got[1].Count != 1 || got[1].Content != "rc4 guidance" {
		t.Fatalf("unexpected RC4 report item: %+v", got[1])
	}
}

func TestCollectWeakRiskTypesAndAnnotateFlags(t *testing.T) {
	rows := []WeakCipher{
		{Suite: "A", RiskList: []string{"CBC Mode", "RC4"}},
		{Suite: "B", RiskList: []string{"RC4"}},
	}

	riskTypes := collectWeakRiskTypes(rows)
	wantTypes := []string{"CBC Mode", "RC4"}
	if !reflect.DeepEqual(riskTypes, wantTypes) {
		t.Fatalf("risk types mismatch\nwant=%v\ngot=%v", wantTypes, riskTypes)
	}

	annotated := annotateWeakCipherRiskFlags(rows, riskTypes)
	if len(annotated) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(annotated))
	}

	if !reflect.DeepEqual(annotated[0].RiskFlags, []bool{true, true}) {
		t.Fatalf("unexpected row 0 flags: %v", annotated[0].RiskFlags)
	}
	if !reflect.DeepEqual(annotated[1].RiskFlags, []bool{false, true}) {
		t.Fatalf("unexpected row 1 flags: %v", annotated[1].RiskFlags)
	}
}

func TestBuildWeakHostRiskRows(t *testing.T) {
	rows := []WeakCipher{
		{Host: "host-a", RiskList: []string{"CBC Mode", "RC4"}},
		{Host: "host-a", RiskList: []string{"No Forward Secrecy"}},
		{Host: "host-b", RiskList: []string{"RC4"}},
	}
	riskTypes := []string{"CBC Mode", "No Forward Secrecy", "RC4"}

	got := buildWeakHostRiskRows(rows, riskTypes)
	if len(got) != 2 {
		t.Fatalf("expected 2 host rows, got %d", len(got))
	}
	if got[0].Host != "host-a" || !reflect.DeepEqual(got[0].RiskFlags, []bool{true, true, true}) {
		t.Fatalf("unexpected host-a row: %+v", got[0])
	}
	if got[1].Host != "host-b" || !reflect.DeepEqual(got[1].RiskFlags, []bool{false, false, true}) {
		t.Fatalf("unexpected host-b row: %+v", got[1])
	}
}

func TestIsStrongCipherFinding(t *testing.T) {
	t.Run("strong tls12 aead fs", func(t *testing.T) {
		f := Finding{
			ID:      "cipher-tls1_2_xc02f",
			Finding: "TLSv1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 253 AESGCM 128 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		}
		if !isStrongCipherFinding(f) {
			t.Fatalf("expected strong cipher")
		}
	})

	t.Run("weak tls12 cbc sha1", func(t *testing.T) {
		f := Finding{
			ID:      "cipher-tls1_2_x2f",
			Finding: "TLSv1.2 x2f AES128-SHA RSA AES 128 TLS_RSA_WITH_AES_128_CBC_SHA",
		}
		if isStrongCipherFinding(f) {
			t.Fatalf("did not expect CBC/SHA1 suite to be strong")
		}
	})
}

func TestBuildRecommendedCipherRows(t *testing.T) {
	all := []Finding{
		{
			ID:      "cipher-tls1_2_xc02f",
			Host:    "example.com",
			Port:    "443",
			Finding: "TLSv1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 253 AESGCM 128 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			ID:      "cipher-tls1_2_x2f",
			Host:    "example.com",
			Port:    "443",
			Finding: "TLSv1.2 x2f AES128-SHA RSA AES 128 TLS_RSA_WITH_AES_128_CBC_SHA",
		},
		{
			ID:      "cipher-tls1_2_xc02f",
			Host:    "example.com",
			Port:    "443",
			Finding: "TLSv1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 253 AESGCM 128 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			ID:      "cipher_order",
			Host:    "example.com",
			Port:    "443",
			Finding: "server prioritizes ciphers",
		},
	}

	got := buildRecommendedCipherRows(all)
	if len(got) != 1 {
		t.Fatalf("expected 1 recommended cipher, got %d", len(got))
	}
	if got[0].Suite != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Fatalf("unexpected suite: %q", got[0].Suite)
	}
	if got[0].TLS10 || got[0].TLS11 || !got[0].TLS12 || got[0].TLS13 {
		t.Fatalf("unexpected protocol flags: tls10=%v tls11=%v tls12=%v tls13=%v", got[0].TLS10, got[0].TLS11, got[0].TLS12, got[0].TLS13)
	}
	if !strings.Contains(got[0].Reason, "AEAD") {
		t.Fatalf("expected AEAD reason, got %q", got[0].Reason)
	}
}

func TestBuildRecommendedCipherRows_DedupBySuiteAcrossHosts(t *testing.T) {
	all := []Finding{
		{
			ID:      "cipher-tls1_2_xc02f",
			Host:    "host-a",
			Port:    "443",
			Finding: "TLSv1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 253 AESGCM 128 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			ID:      "cipher-tls1_3_x1301",
			Host:    "host-b",
			Port:    "443",
			Finding: "TLSv1.3 x1301 TLS_AES_128_GCM_SHA256 ECDH 253 AESGCM 128 TLS_AES_128_GCM_SHA256",
		},
		{
			ID:      "cipher-tls1_3_x1301",
			Host:    "host-c",
			Port:    "8443",
			Finding: "TLSv1.3 x1301 TLS_AES_128_GCM_SHA256 ECDH 253 AESGCM 128 TLS_AES_128_GCM_SHA256",
		},
	}

	got := buildRecommendedCipherRows(all)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique suites, got %d", len(got))
	}

	if got[1].Suite != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected second suite: %q", got[1].Suite)
	}
	if got[1].TLS12 || !got[1].TLS13 {
		t.Fatalf("unexpected protocol flags for TLS_AES_128_GCM_SHA256: tls12=%v tls13=%v", got[1].TLS12, got[1].TLS13)
	}
}

func TestDetectCipherProtocol(t *testing.T) {
	tls10, tls11, tls12, tls13 := detectCipherProtocol(Finding{ID: "cipher-tls1_2_xc02f", Finding: "TLSv1.2 ..."})
	if tls10 || tls11 || !tls12 || tls13 {
		t.Fatalf("expected tls12 only, got tls10=%v tls11=%v tls12=%v tls13=%v", tls10, tls11, tls12, tls13)
	}

	tls10, tls11, tls12, tls13 = detectCipherProtocol(Finding{ID: "cipher-tls1_3_x1302", Finding: "TLSv1.3 ..."})
	if tls10 || tls11 || tls12 || !tls13 {
		t.Fatalf("expected tls13 only, got tls10=%v tls11=%v tls12=%v tls13=%v", tls10, tls11, tls12, tls13)
	}

	tls10, tls11, tls12, tls13 = detectCipherProtocol(Finding{ID: "cipher-tls1_1_xc013", Finding: "TLSv1.1 ..."})
	if tls10 || !tls11 || tls12 || tls13 {
		t.Fatalf("expected tls11 only, got tls10=%v tls11=%v tls12=%v tls13=%v", tls10, tls11, tls12, tls13)
	}

	tls10, tls11, tls12, tls13 = detectCipherProtocol(Finding{ID: "cipher-tls1_xc013", Finding: "TLSv1 ..."})
	if !tls10 || tls11 || tls12 || tls13 {
		t.Fatalf("expected tls10 only, got tls10=%v tls11=%v tls12=%v tls13=%v", tls10, tls11, tls12, tls13)
	}
}
