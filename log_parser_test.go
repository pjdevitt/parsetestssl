package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseTestSSLLog_ProtocolsAndCiphers(t *testing.T) {
	raw, err := os.ReadFile("badssl.com_p443-20260308-1832.log")
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	got := ParseTestSSLLog(raw)

	if len(got.Protocols) == 0 {
		t.Fatalf("expected protocols to be parsed")
	}

	expectedProtocolOffered := map[string]bool{
		"SSLv2":   false,
		"SSLv3":   false,
		"TLS 1.0": true,
		"TLS 1.1": true,
		"TLS 1.2": true,
		"TLS 1.3": false,
	}

	actual := make(map[string]bool, len(got.Protocols))
	for _, p := range got.Protocols {
		actual[p.Name] = p.Offered
	}

	for name, expected := range expectedProtocolOffered {
		offered, ok := actual[name]
		if !ok {
			t.Fatalf("expected protocol %q in parsed output", name)
		}
		if offered != expected {
			t.Fatalf("protocol %q offered mismatch: want=%v got=%v", name, expected, offered)
		}
	}

	tls12Ciphers := got.CiphersByProtocol["TLS 1.2"]
	if len(tls12Ciphers) == 0 {
		t.Fatalf("expected TLS 1.2 ciphers to be parsed")
	}
	if !contains(tls12Ciphers, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
		t.Fatalf("expected TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 in TLS 1.2 ciphers")
	}

	if len(got.CiphersByProtocol["SSLv2"]) != 0 {
		t.Fatalf("expected SSLv2 to have no ciphers, got %v", got.CiphersByProtocol["SSLv2"])
	}
	if len(got.CiphersByProtocol["TLS 1.3"]) != 0 {
		t.Fatalf("expected TLS 1.3 to have no ciphers, got %v", got.CiphersByProtocol["TLS 1.3"])
	}
}

func TestStripANSI_RemovesControlSequences(t *testing.T) {
	in := []byte("\x1b[1m TLS 1.2 \x1b[moffered (OK)")
	out := string(stripANSI(in))
	if strings.Contains(out, "\x1b") {
		t.Fatalf("expected no ANSI escape codes, got %q", out)
	}
	if !strings.Contains(out, "TLS 1.2") {
		t.Fatalf("expected cleaned text to retain content, got %q", out)
	}
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
