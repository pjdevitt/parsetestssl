package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
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
	Findings           []Finding
	RawCount           int
	SecurityCount      int
	MinSeverity        string
	Error              string
	SourcePreview      string
	MatrixHosts        []string
	MatrixRows         []IssueMatrixRow
	WeakCiphers        []WeakCipher
	WeakGroups         []WeakCipherGroup
	WeakRiskTypes      []string
	WeakHostRisks      []WeakHostRiskRow
	RecommendedCiphers []RecommendedCipher
	CipherReports      []CipherWeaknessReport
}

type IssueMatrixRow struct {
	Category string
	IssueID  string
	Issue    string
	Cells    []string
}

type WeakCipher struct {
	Severity  string
	Host      string
	Port      string
	ID        string
	Suite     string
	Risks     string
	RiskList  []string
	RiskFlags []bool
	Finding   string
}

type WeakCipherGroup struct {
	Host string
	Rows []WeakCipher
}

type WeakHostRiskRow struct {
	Host      string
	RiskFlags []bool
}

type RecommendedCipher struct {
	Host   string
	Port   string
	Suite  string
	TLS10  bool
	TLS11  bool
	TLS12  bool
	TLS13  bool
	Reason string
}

type CipherWeaknessReport struct {
	Name         string
	TemplateFile string
	Count        int
	Content      string
}

var tpl = template.Must(template.ParseFiles("templates/index.html"))

const maxRequestBytes int64 = 12 << 20

var reportTemplatesDir = "report_templates"

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

type categoryRule struct {
	Category string
	Patterns []string
}

var categoryRules = []categoryRule{
	{Category: "Protocol Weakness", Patterns: []string{"sslv2", "sslv3", "tls1", "tls1_1", "poodle", "drown"}},
	{Category: "Cipher Weakness", Patterns: []string{"rc4", "3des", "sweet32", "freak", "logjam", "null cipher", "export"}},
	{Category: "Known Vulnerability", Patterns: []string{"heartbleed", "ticketbleed", "robot", "ccs", "crime", "breach", "lucky13", "renegotiation"}},
	{Category: "Certificate Risk", Patterns: []string{"expired", "not valid", "self-signed", "revocation", "cert", "ocsp", "hostname mismatch"}},
	{Category: "Configuration Hardening", Patterns: []string{"hsts", "secure renegotiation", "forward secrecy", "session resumption", "compression"}},
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
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

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
		data.RecommendedCiphers = buildRecommendedCipherRows(allFindings)
		data.MatrixHosts, data.MatrixRows = buildIssueMatrix(data.Findings)
		weakRows := buildWeakCipherRows(data.Findings)
		data.WeakRiskTypes = collectWeakRiskTypes(weakRows)
		data.WeakCiphers = annotateWeakCipherRiskFlags(weakRows, data.WeakRiskTypes)
		data.WeakHostRisks = buildWeakHostRiskRows(data.WeakCiphers, data.WeakRiskTypes)
		data.WeakGroups = groupWeakCiphersByHost(data.WeakCiphers)
		data.CipherReports = buildCipherWeaknessReports(data.WeakCiphers)
	}

	render(w, data)
}

func render(w http.ResponseWriter, data ViewData) {
	if err := tpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readInput(r *http.Request) ([]byte, string, error) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	parseErr := error(nil)
	if strings.HasPrefix(contentType, "multipart/form-data") {
		parseErr = r.ParseMultipartForm(10 << 20)
	} else {
		parseErr = r.ParseForm()
	}

	if parseErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(parseErr, &maxErr) {
			return nil, "MEDIUM", fmt.Errorf("request is too large (max %d MB)", maxRequestBytes>>20)
		}
		return nil, "MEDIUM", fmt.Errorf("unable to read form: %w", parseErr)
	}

	minSeverity := strings.ToUpper(strings.TrimSpace(r.FormValue("minSeverity")))
	if _, ok := severityScore[minSeverity]; !ok {
		minSeverity = "MEDIUM"
	}

	if strings.HasPrefix(contentType, "multipart/form-data") {
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
	for _, rule := range categoryRules {
		for _, p := range rule.Patterns {
			if strings.Contains(l, p) {
				return rule.Category
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
		if strings.EqualFold(strings.TrimSpace(f.ID), "cipherlist_OBSOLETED") {
			continue
		}
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
			RiskList: risks,
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

func collectWeakRiskTypes(rows []WeakCipher) []string {
	seen := make(map[string]struct{})
	for _, row := range rows {
		for _, risk := range row.RiskList {
			name := strings.TrimSpace(risk)
			if name == "" {
				continue
			}
			seen[name] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for risk := range seen {
		out = append(out, risk)
	}
	sort.Strings(out)
	return out
}

func annotateWeakCipherRiskFlags(rows []WeakCipher, riskTypes []string) []WeakCipher {
	if len(rows) == 0 {
		return nil
	}

	out := make([]WeakCipher, 0, len(rows))
	for _, row := range rows {
		rowRisk := make(map[string]struct{}, len(row.RiskList))
		for _, risk := range row.RiskList {
			name := strings.TrimSpace(risk)
			if name == "" {
				continue
			}
			rowRisk[name] = struct{}{}
		}

		flags := make([]bool, len(riskTypes))
		for i, riskType := range riskTypes {
			_, ok := rowRisk[riskType]
			flags[i] = ok
		}

		row.RiskFlags = flags
		out = append(out, row)
	}
	return out
}

func buildWeakHostRiskRows(rows []WeakCipher, riskTypes []string) []WeakHostRiskRow {
	if len(rows) == 0 || len(riskTypes) == 0 {
		return nil
	}

	hostRisk := make(map[string]map[string]struct{})
	for _, row := range rows {
		host := strings.TrimSpace(row.Host)
		if host == "" {
			host = "Unknown host"
		}
		if _, ok := hostRisk[host]; !ok {
			hostRisk[host] = make(map[string]struct{})
		}
		for _, risk := range row.RiskList {
			name := strings.TrimSpace(risk)
			if name == "" {
				continue
			}
			hostRisk[host][name] = struct{}{}
		}
	}

	hosts := make([]string, 0, len(hostRisk))
	for host := range hostRisk {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	out := make([]WeakHostRiskRow, 0, len(hosts))
	for _, host := range hosts {
		flags := make([]bool, len(riskTypes))
		for i, risk := range riskTypes {
			_, ok := hostRisk[host][risk]
			flags[i] = ok
		}
		out = append(out, WeakHostRiskRow{
			Host:      host,
			RiskFlags: flags,
		})
	}

	return out
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
	id := strings.ToLower(strings.TrimSpace(f.ID))
	finding := strings.ToLower(f.Finding)
	if strings.HasPrefix(id, "cipher-") ||
		strings.HasPrefix(id, "cipher_") ||
		strings.HasPrefix(id, "cipherlist_") ||
		strings.HasPrefix(id, "supportedciphers_") ||
		strings.HasPrefix(id, "cipherorder_") {
		return true
	}
	if strings.Contains(finding, "tls_") && strings.Contains(finding, "_with_") {
		return true
	}
	if strings.Contains(finding, "tlsv1.") && strings.Contains(finding, "_with_") {
		return true
	}
	return strings.Contains(finding, "tlsv1.3") && strings.Contains(finding, "tls_")
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

func buildRecommendedCipherRows(all []Finding) []RecommendedCipher {
	type acc struct {
		Suite string
		TLS10 bool
		TLS11 bool
		TLS12 bool
		TLS13 bool
	}
	agg := make(map[string]*acc)

	for _, f := range all {
		if !isCipherSuiteFinding(f) || !isStrongCipherFinding(f) {
			continue
		}

		suite := strings.TrimSpace(extractCipherSuite(f))
		if suite == "" {
			continue
		}

		key := strings.ToLower(suite)
		item, ok := agg[key]
		if !ok {
			item = &acc{
				Suite: suite,
			}
			agg[key] = item
		}
		tls10, tls11, tls12, tls13 := detectCipherProtocol(f)
		item.TLS10 = item.TLS10 || tls10
		item.TLS11 = item.TLS11 || tls11
		item.TLS12 = item.TLS12 || tls12
		item.TLS13 = item.TLS13 || tls13
	}

	out := make([]RecommendedCipher, 0, len(agg))
	for _, item := range agg {
		out = append(out, RecommendedCipher{
			Suite:  item.Suite,
			TLS10:  item.TLS10,
			TLS11:  item.TLS11,
			TLS12:  item.TLS12,
			TLS13:  item.TLS13,
			Reason: recommendedCipherReason(item.Suite),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Suite < out[j].Suite
	})

	return out
}

func detectCipherProtocol(f Finding) (bool, bool, bool, bool) {
	text := strings.ToLower(strings.TrimSpace(f.ID + " " + f.Finding))
	isTLS10 := strings.Contains(text, "tlsv1.0") || strings.Contains(text, "tls1_0") || strings.Contains(text, "tlsv1 ")
	isTLS11 := strings.Contains(text, "tlsv1.1") || strings.Contains(text, "tls1_1")
	isTLS12 := strings.Contains(text, "tlsv1.2") || strings.Contains(text, "tls1_2")
	isTLS13 := strings.Contains(text, "tlsv1.3") || strings.Contains(text, "tls1_3")
	return isTLS10, isTLS11, isTLS12, isTLS13
}

func isCipherSuiteFinding(f Finding) bool {
	id := strings.ToLower(strings.TrimSpace(f.ID))
	if !strings.HasPrefix(id, "cipher-") {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(f.Finding))
	return len(fields) >= 3 && strings.HasPrefix(strings.ToUpper(fields[0]), "TLSV")
}

func isStrongCipherFinding(f Finding) bool {
	suite := strings.ToUpper(strings.TrimSpace(extractCipherSuite(f)))
	if suite == "" {
		return false
	}
	text := strings.ToUpper(strings.TrimSpace(f.ID + " " + f.Finding + " " + suite))

	if strings.Contains(text, "RC4") ||
		strings.Contains(text, "3DES") ||
		strings.Contains(text, "DES-CBC") ||
		strings.Contains(text, "_NULL_") ||
		strings.Contains(text, "ANULL") ||
		strings.Contains(text, "EXPORT") ||
		strings.Contains(text, "CAMELLIA") ||
		strings.Contains(text, " CBC") ||
		strings.Contains(text, "_CBC_") {
		return false
	}
	if strings.Contains(text, "SHA") &&
		!strings.Contains(text, "SHA256") &&
		!strings.Contains(text, "SHA384") &&
		!strings.Contains(text, "SHA512") {
		return false
	}

	// Pre-TLS 1.3 suites should be FS + AEAD to be considered recommended.
	if !strings.Contains(strings.ToLower(f.Finding), "tlsv1.3") {
		if !(strings.Contains(text, "ECDHE") || strings.Contains(text, " DHE")) {
			return false
		}
		if !(strings.Contains(text, "GCM") || strings.Contains(text, "CHACHA20_POLY1305")) {
			return false
		}
	}

	return true
}

func strongCipherReason(f Finding) string {
	suite := strings.ToUpper(strings.TrimSpace(extractCipherSuite(f)))
	text := strings.ToUpper(strings.TrimSpace(f.ID + " " + f.Finding + " " + suite))
	reasons := make([]string, 0, 3)

	if strings.Contains(strings.ToLower(f.Finding), "tlsv1.3") {
		reasons = append(reasons, "TLS 1.3")
	}
	if strings.Contains(text, "GCM") || strings.Contains(text, "CHACHA20_POLY1305") {
		reasons = append(reasons, "AEAD")
	}
	if strings.Contains(text, "ECDHE") || strings.Contains(text, " DHE") || strings.Contains(strings.ToLower(f.Finding), "tlsv1.3") {
		reasons = append(reasons, "Forward secrecy")
	}

	if len(reasons) == 0 {
		return "Modern strong cipher profile"
	}
	return strings.Join(reasons, ", ")
}

func recommendedCipherReason(suite string) string {
	upper := strings.ToUpper(strings.TrimSpace(suite))
	reasons := make([]string, 0, 2)
	if strings.Contains(upper, "GCM") || strings.Contains(upper, "CHACHA20_POLY1305") {
		reasons = append(reasons, "AEAD")
	}
	if strings.Contains(upper, "ECDHE") || strings.Contains(upper, "_DHE_") {
		reasons = append(reasons, "Forward secrecy")
	}
	if len(reasons) == 0 {
		return "Modern strong cipher profile"
	}
	return strings.Join(reasons, ", ")
}

func buildCipherWeaknessReports(rows []WeakCipher) []CipherWeaknessReport {
	if len(rows) == 0 {
		return nil
	}

	counts := make(map[string]int)
	for _, row := range rows {
		source := row.RiskList
		if len(source) == 0 && strings.TrimSpace(row.Risks) != "" {
			source = strings.Split(row.Risks, ",")
		}
		for _, part := range source {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}
			counts[name]++
		}
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]CipherWeaknessReport, 0, len(names))
	for _, name := range names {
		fileName := weaknessTemplateFileName(name)
		content := loadWeaknessTemplate(fileName)
		out = append(out, CipherWeaknessReport{
			Name:         name,
			TemplateFile: fileName,
			Count:        counts[name],
			Content:      content,
		})
	}

	return out
}

func weaknessTemplateFileName(name string) string {
	return slugify(name) + ".md"
}

func loadWeaknessTemplate(fileName string) string {
	path := filepath.Join(reportTemplatesDir, fileName)
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("Template not found: %s", fileName)
	}
	return strings.TrimSpace(string(b))
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}

	var b strings.Builder
	prevUnderscore := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
			prevUnderscore = false
		default:
			if !prevUnderscore {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
	}

	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}
