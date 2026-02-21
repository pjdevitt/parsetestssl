package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
)

type Finding struct {
	ID        string
	Severity  string
	Host      string
	Port      string
	Finding   string
	CWE       string
	CVSS      string
	Category  string
	SortScore int
}

type ViewData struct {
	Findings      []Finding
	RawCount      int
	SecurityCount int
	MinSeverity   string
	Error         string
	SourcePreview string
	MatrixHosts   []string
	MatrixRows    []IssueMatrixRow
	WeakCiphers   []WeakCipher
	WeakGroups    []WeakCipherGroup
}

type IssueMatrixRow struct {
	Category string
	IssueID  string
	Issue    string
	Cells    []string
}

type WeakCipher struct {
	Severity string
	Host     string
	Port     string
	ID       string
	Suite    string
	Risks    string
	Finding  string
}

type WeakCipherGroup struct {
	Host string
	Rows []WeakCipher
}

var tpl = template.Must(template.ParseFiles("templates/index.html"))

var severityScore = map[string]int{
	"OK":       0,
	"INFO":     1,
	"LOW":      2,
	"MEDIUM":   3,
	"HIGH":     4,
	"CRITICAL": 5,
	"WARN":     2,
	"UNKNOWN":  2,
}

var categoryPatterns = map[string][]string{
	"Protocol Weakness":       {"sslv2", "sslv3", "tls1", "tls1_1", "poodle", "drown"},
	"Cipher Weakness":         {"rc4", "3des", "sweet32", "freak", "logjam", "null cipher", "export"},
	"Known Vulnerability":     {"heartbleed", "ticketbleed", "robot", "ccs", "crime", "breach", "lucky13", "renegotiation"},
	"Certificate Risk":        {"expired", "not valid", "self-signed", "revocation", "cert", "ocsp", "hostname mismatch"},
	"Configuration Hardening": {"hsts", "secure renegotiation", "forward secrecy", "session resumption", "compression"},
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", indexHandler)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}

	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data := ViewData{MinSeverity: "MEDIUM"}

	if r.Method == http.MethodPost {
		raw, minSeverity, err := readInput(r)
		data.MinSeverity = minSeverity

		if err != nil {
			data.Error = err.Error()
			render(w, data)
			return
		}

		if len(raw) > 2000 {
			data.SourcePreview = string(raw[:2000]) + "\n..."
		} else {
			data.SourcePreview = string(raw)
		}

		allFindings, err := parseFindings(raw)
		if err != nil {
			data.Error = fmt.Sprintf("could not parse JSON: %v", err)
			render(w, data)
			return
		}

		data.RawCount = len(allFindings)
		data.Findings = filterSecurityFindings(allFindings, minSeverity)
		data.SecurityCount = len(data.Findings)
		data.MatrixHosts, data.MatrixRows = buildIssueMatrix(data.Findings)
		data.WeakCiphers = buildWeakCipherRows(data.Findings)
		data.WeakGroups = groupWeakCiphersByHost(data.WeakCiphers)
	}

	render(w, data)
}

func render(w http.ResponseWriter, data ViewData) {
	if err := tpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readInput(r *http.Request) ([]byte, string, error) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		return nil, "MEDIUM", fmt.Errorf("unable to read form: %w", err)
	}

	minSeverity := strings.ToUpper(strings.TrimSpace(r.FormValue("minSeverity")))
	if _, ok := severityScore[minSeverity]; !ok {
		minSeverity = "MEDIUM"
	}

	if f, _, err := r.FormFile("jsonFile"); err == nil {
		defer f.Close()
		b, readErr := io.ReadAll(f)
		if readErr != nil {
			return nil, minSeverity, fmt.Errorf("failed reading upload: %w", readErr)
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			return nil, minSeverity, fmt.Errorf("uploaded file is empty")
		}
		return b, minSeverity, nil
	}

	text := strings.TrimSpace(r.FormValue("jsonText"))
	if text == "" {
		return nil, minSeverity, fmt.Errorf("provide a JSON file or paste JSON output")
	}

	return []byte(text), minSeverity, nil
}

func parseFindings(raw []byte) ([]Finding, error) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}

	var findings []Finding
	walk(root, &findings)
	return findings, nil
}

func walk(node any, out *[]Finding) {
	switch t := node.(type) {
	case []any:
		for _, v := range t {
			walk(v, out)
		}
	case map[string]any:
		if f, ok := extractFinding(t); ok {
			*out = append(*out, f)
		}
		for _, v := range t {
			switch v.(type) {
			case map[string]any, []any:
				walk(v, out)
			}
		}
	}
}

func extractFinding(m map[string]any) (Finding, bool) {
	id := firstNonEmpty(m, "id", "check", "test", "finding_id")
	sev := strings.ToUpper(firstNonEmpty(m, "severity", "level", "risk", "rating"))
	findingText := firstNonEmpty(m, "finding", "result", "issue", "description")

	if id == "" && sev == "" && findingText == "" {
		return Finding{}, false
	}

	if sev == "" {
		sev = "UNKNOWN"
	}
	if _, ok := severityScore[sev]; !ok {
		sev = "UNKNOWN"
	}

	f := Finding{
		ID:        id,
		Severity:  sev,
		Host:      firstNonEmpty(m, "fqdn", "host", "ip"),
		Port:      firstNonEmpty(m, "port"),
		Finding:   findingText,
		CWE:       firstNonEmpty(m, "cwe"),
		CVSS:      firstNonEmpty(m, "cvss"),
		Category:  categorize(id + " " + findingText),
		SortScore: severityScore[sev],
	}

	return f, true
}

func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, key := range keys {
		for k, v := range m {
			if strings.EqualFold(k, key) {
				s := strings.TrimSpace(fmt.Sprintf("%v", v))
				if s != "" && s != "<nil>" {
					return s
				}
			}
		}
	}
	return ""
}

func categorize(text string) string {
	l := strings.ToLower(text)
	for category, patterns := range categoryPatterns {
		for _, p := range patterns {
			if strings.Contains(l, p) {
				return category
			}
		}
	}
	return "General TLS Risk"
}

func filterSecurityFindings(all []Finding, minSeverity string) []Finding {
	threshold := severityScore[minSeverity]
	seen := make(map[string]struct{})
	out := make([]Finding, 0, len(all))

	for _, f := range all {
		key := strings.ToLower(f.ID + "|" + f.Severity + "|" + f.Finding + "|" + f.Host + "|" + f.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if f.SortScore < threshold {
			continue
		}
		if f.Severity == "OK" || f.Severity == "INFO" {
			continue
		}
		out = append(out, f)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SortScore != out[j].SortScore {
			return out[i].SortScore > out[j].SortScore
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})

	return out
}

func buildIssueMatrix(findings []Finding) ([]string, []IssueMatrixRow) {
	type issueAcc struct {
		Category string
		IssueID  string
		Issue    string
		MaxSev   int
		PerHost  map[string]string
	}

	hostSet := make(map[string]struct{})
	issues := make(map[string]*issueAcc)

	for _, f := range findings {
		host := strings.TrimSpace(f.Host)
		if host == "" {
			host = "Unknown host"
		}
		hostSet[host] = struct{}{}

		for _, matrixIssue := range matrixIssuesForFinding(f) {
			key := strings.ToLower(matrixIssue.Category + "|" + matrixIssue.IssueID + "|" + matrixIssue.Issue)
			acc, ok := issues[key]
			if !ok {
				acc = &issueAcc{
					Category: matrixIssue.Category,
					IssueID:  matrixIssue.IssueID,
					Issue:    matrixIssue.Issue,
					MaxSev:   f.SortScore,
					PerHost:  make(map[string]string),
				}
				issues[key] = acc
			}

			if f.SortScore > acc.MaxSev {
				acc.MaxSev = f.SortScore
			}

			current, exists := acc.PerHost[host]
			if !exists || severityScore[current] < f.SortScore {
				acc.PerHost[host] = f.Severity
			}
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i] == "Unknown host" {
			return false
		}
		if hosts[j] == "Unknown host" {
			return true
		}
		return hosts[i] < hosts[j]
	})

	rowsWithScore := make([]struct {
		IssueMatrixRow
		MaxSev int
	}, 0, len(issues))

	for _, acc := range issues {
		row := IssueMatrixRow{
			Category: acc.Category,
			IssueID:  acc.IssueID,
			Issue:    acc.Issue,
			Cells:    make([]string, len(hosts)),
		}
		for i, host := range hosts {
			row.Cells[i] = acc.PerHost[host]
		}
		rowsWithScore = append(rowsWithScore, struct {
			IssueMatrixRow
			MaxSev int
		}{
			IssueMatrixRow: row,
			MaxSev:         acc.MaxSev,
		})
	}

	sort.Slice(rowsWithScore, func(i, j int) bool {
		if rowsWithScore[i].MaxSev != rowsWithScore[j].MaxSev {
			return rowsWithScore[i].MaxSev > rowsWithScore[j].MaxSev
		}
		if rowsWithScore[i].Category != rowsWithScore[j].Category {
			return rowsWithScore[i].Category < rowsWithScore[j].Category
		}
		if rowsWithScore[i].IssueID != rowsWithScore[j].IssueID {
			return rowsWithScore[i].IssueID < rowsWithScore[j].IssueID
		}
		return rowsWithScore[i].Issue < rowsWithScore[j].Issue
	})

	rows := make([]IssueMatrixRow, 0, len(rowsWithScore))
	for _, item := range rowsWithScore {
		rows = append(rows, item.IssueMatrixRow)
	}

	return hosts, rows
}

func matrixIssuesForFinding(f Finding) []IssueMatrixRow {
	if isCipherFinding(f) {
		risks := cipherRiskTypes(f)
		out := make([]IssueMatrixRow, 0, len(risks))
		for _, risk := range risks {
			out = append(out, IssueMatrixRow{
				Category: "Cipher Weakness",
				IssueID:  "cipher_risk",
				Issue:    risk,
			})
		}
		return out
	}

	return []IssueMatrixRow{
		{
			Category: f.Category,
			IssueID:  strings.TrimSpace(f.ID),
			Issue:    strings.TrimSpace(f.Finding),
		},
	}
}

func buildWeakCipherRows(findings []Finding) []WeakCipher {
	rows := make([]WeakCipher, 0)
	for _, f := range findings {
		if !isCipherFinding(f) {
			continue
		}
		risks := cipherRiskTypes(f)
		if len(risks) == 0 {
			continue
		}
		host := strings.TrimSpace(f.Host)
		if host == "" {
			host = "Unknown host"
		}
		rows = append(rows, WeakCipher{
			Severity: f.Severity,
			Host:     host,
			Port:     strings.TrimSpace(f.Port),
			ID:       strings.TrimSpace(f.ID),
			Suite:    extractCipherSuite(f),
			Risks:    strings.Join(risks, ", "),
			Finding:  strings.TrimSpace(f.Finding),
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if severityScore[rows[i].Severity] != severityScore[rows[j].Severity] {
			return severityScore[rows[i].Severity] > severityScore[rows[j].Severity]
		}
		if rows[i].Host != rows[j].Host {
			return rows[i].Host < rows[j].Host
		}
		if rows[i].Suite != rows[j].Suite {
			return rows[i].Suite < rows[j].Suite
		}
		return rows[i].ID < rows[j].ID
	})

	return rows
}

func groupWeakCiphersByHost(rows []WeakCipher) []WeakCipherGroup {
	if len(rows) == 0 {
		return nil
	}

	groupsMap := make(map[string][]WeakCipher)
	for _, row := range rows {
		host := strings.TrimSpace(row.Host)
		if host == "" {
			host = "Unknown host"
		}
		groupsMap[host] = append(groupsMap[host], row)
	}

	hosts := make([]string, 0, len(groupsMap))
	for host := range groupsMap {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	groups := make([]WeakCipherGroup, 0, len(hosts))
	for _, host := range hosts {
		groups = append(groups, WeakCipherGroup{
			Host: host,
			Rows: groupsMap[host],
		})
	}
	return groups
}

func isCipherFinding(f Finding) bool {
	id := strings.ToLower(f.ID)
	finding := strings.ToLower(f.Finding)
	if strings.Contains(id, "cipher") {
		return true
	}
	return strings.Contains(finding, "tls_") || strings.Contains(finding, "tlsv1.")
}

func cipherRiskTypes(f Finding) []string {
	text := strings.ToLower(f.ID + " " + f.Finding)
	var risks []string

	add := func(risk string) {
		for _, existing := range risks {
			if existing == risk {
				return
			}
		}
		risks = append(risks, risk)
	}

	if strings.Contains(text, "nofs") ||
		(strings.Contains(text, "rsa") && !strings.Contains(text, "ecdhe") && !strings.Contains(text, "dhe")) {
		add("No Forward Secrecy")
	}
	if strings.Contains(text, "cbc") {
		add("CBC Mode")
	}
	if strings.Contains(text, "sha") &&
		!strings.Contains(text, "sha256") &&
		!strings.Contains(text, "sha384") &&
		!strings.Contains(text, "sha512") {
		add("SHA-1 MAC")
	}
	if strings.Contains(text, "3des") || strings.Contains(text, "des") || strings.Contains(text, "sweet32") {
		add("3DES / SWEET32")
	}
	if strings.Contains(text, "rc4") {
		add("RC4")
	}
	if strings.Contains(text, "export") {
		add("Export-grade Cipher")
	}
	if strings.Contains(text, "null") || strings.Contains(text, "anull") {
		add("NULL / Anonymous Cipher")
	}
	if strings.Contains(text, "obsoleted") {
		add("Obsoleted Cipher")
	}

	if len(risks) == 0 && f.SortScore >= severityScore["LOW"] {
		add("Other Cipher Weakness")
	}

	return risks
}

func extractCipherSuite(f Finding) string {
	fields := strings.Fields(strings.TrimSpace(f.Finding))
	if len(fields) >= 3 && strings.HasPrefix(strings.ToUpper(fields[0]), "TLSV") {
		return fields[2]
	}
	if strings.TrimSpace(f.ID) != "" {
		return strings.TrimSpace(f.ID)
	}
	return strings.TrimSpace(f.Finding)
}
