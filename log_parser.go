package main

import (
	"bufio"
	"bytes"
	"regexp"
	"sort"
	"strings"
)

type LogProtocol struct {
	Name    string
	Offered bool
	Raw     string
}

type ParsedTestSSLLog struct {
	Protocols         []LogProtocol
	CiphersByProtocol map[string][]string
}

var (
	ansiCSIRe     = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiCharsetRe = regexp.MustCompile(`\x1b[\(\)][0-9A-Za-z]`)

	protocolLineRe = regexp.MustCompile(`^(SSLv2|SSLv3|TLS 1(?:\.1|\.2|\.3)?)\s+(.+)$`)
	cipherProtoRe  = regexp.MustCompile(`^(SSLv2|SSLv3|TLSv1(?:\.[123])?)\b`)
	cipherIANARe   = regexp.MustCompile(`(TLS_[A-Z0-9_]+)\s*$`)
)

func ParseTestSSLLog(raw []byte) ParsedTestSSLLog {
	clean := stripANSI(raw)
	out := ParsedTestSSLLog{
		CiphersByProtocol: make(map[string][]string),
	}

	var inProtocolSection bool
	var inCipherSection bool
	var currentCipherProtocol string
	protocolSeen := make(map[string]struct{})

	scanner := bufio.NewScanner(bytes.NewReader(clean))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case strings.Contains(line, "Testing protocols"):
			inProtocolSection = true
			inCipherSection = false
			continue
		case strings.Contains(line, "Testing cipher categories"):
			inProtocolSection = false
			continue
		case strings.Contains(line, "Testing server's cipher preferences"):
			inCipherSection = true
			inProtocolSection = false
			currentCipherProtocol = ""
			continue
		case strings.Contains(line, "Has server cipher order?"):
			inCipherSection = false
			currentCipherProtocol = ""
			continue
		}

		if inProtocolSection {
			matches := protocolLineRe.FindStringSubmatch(line)
			if len(matches) == 0 {
				continue
			}
			name := normalizeProtocolName(matches[1])
			rawStatus := strings.TrimSpace(matches[2])
			offered := strings.Contains(strings.ToLower(rawStatus), "offered") &&
				!strings.Contains(strings.ToLower(rawStatus), "not offered")

			if _, exists := protocolSeen[name]; exists {
				continue
			}
			protocolSeen[name] = struct{}{}

			out.Protocols = append(out.Protocols, LogProtocol{
				Name:    name,
				Offered: offered,
				Raw:     rawStatus,
			})
			continue
		}

		if !inCipherSection {
			continue
		}

		protoMatch := cipherProtoRe.FindStringSubmatch(line)
		if len(protoMatch) > 0 {
			currentCipherProtocol = normalizeProtocolName(protoMatch[1])
			if _, ok := out.CiphersByProtocol[currentCipherProtocol]; !ok {
				out.CiphersByProtocol[currentCipherProtocol] = nil
			}
			continue
		}

		if currentCipherProtocol == "" || line == "-" || !strings.HasPrefix(strings.ToLower(line), "x") {
			continue
		}

		cipher := extractCipherName(line)
		if cipher == "" {
			continue
		}
		out.CiphersByProtocol[currentCipherProtocol] = appendUnique(out.CiphersByProtocol[currentCipherProtocol], cipher)
	}

	for proto := range out.CiphersByProtocol {
		sort.Strings(out.CiphersByProtocol[proto])
	}

	return out
}

func stripANSI(raw []byte) []byte {
	s := string(raw)
	s = ansiCSIRe.ReplaceAllString(s, "")
	s = ansiCharsetRe.ReplaceAllString(s, "")
	return []byte(s)
}

func normalizeProtocolName(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "sslv2":
		return "SSLv2"
	case "sslv3":
		return "SSLv3"
	case "tls 1", "tlsv1":
		return "TLS 1.0"
	case "tls 1.1", "tlsv1.1":
		return "TLS 1.1"
	case "tls 1.2", "tlsv1.2":
		return "TLS 1.2"
	case "tls 1.3", "tlsv1.3":
		return "TLS 1.3"
	default:
		return strings.TrimSpace(v)
	}
}

func extractCipherName(line string) string {
	if m := cipherIANARe.FindStringSubmatch(line); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return strings.TrimSpace(fields[1])
	}
	return ""
}

func appendUnique(in []string, value string) []string {
	for _, existing := range in {
		if existing == value {
			return in
		}
	}
	return append(in, value)
}
