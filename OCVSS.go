// OCVSS — CVSS 3.1/4.0 Calculator
// Part of the OWL security suite.
// Author : khaled.s.haddad
// Website: owlsec.org
// Language: Go (standard library only, no external modules, no cgo)
//
// This tool is a professional, self-contained Go program. It provides an
// interactive cyan terminal UI and a full command-line interface with
// multi-format export (TXT, Markdown, JSON, CSV, SARIF 2.1.0), MITRE ATT&CK
// tagging on findings where meaningful, and A+..F posture grading.
//
// DESIGN NOTES
// ------------
// The code is organised in clearly named sections: the embedded UI KIT, the
// shared reporting/export engine, the deep domain engine for this tool's
// concept, and finally the CLI + interactive dispatcher. Everything compiles
// with: CGO_ENABLED=0 go build -ldflags="-s -w" -o OCVSS OCVSS.go

package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// SECTION: embedded OWL UI KIT (cyan house style, stdlib only)
// ============================================================================

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	UN  = "\033[4m"        // underline
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former "dark red" frame → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

type menuItem struct {
	key, name, desc, clr string
}

// header prints an ONode-style section header (⬡ Title between cyan rules).
func header(title string) {
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

// showMenu renders the ONode-style main menu and returns the selection.
func showMenu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 22), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 22), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 22), W) + col("─ Quit OCVSS", DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const APPNAME = "OCVSS"
const SUITE = "Owl CVSS Suite"
const TAGLINE = "CVSS 3.1/4.0 Calculator"
const SUBLINE = "Score · Explain · Compare · Batch · Sensitivity · Normalize · Grade"
const BANNER = `
  ██████╗  ██████╗ ██╗   ██╗███████╗███████╗
 ██╔═══██╗██╔════╝ ██║   ██║██╔════╝██╔════╝
 ██║   ██║██║      ██║   ██║███████╗███████╗
 ██║   ██║██║      ╚██╗ ██╔╝╚════██║╚════██║
 ╚██████╔╝╚██████╗  ╚████╔╝ ███████║███████║
  ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚══════╝
`
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

// ============================================================================
// SECTION: shared reporting & export engine (used by every OWL tool)
// ============================================================================

// Severity levels, ordered.
const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical:
		return R + B
	case SevHigh:
		return R
	case SevMedium:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

// Finding is the universal record emitted by the domain engine.
type Finding struct {
	ID       string            `json:"id"`
	Title    string            `json:"title"`
	Severity string            `json:"severity"`
	Category string            `json:"category"`
	Detail   string            `json:"detail"`
	Evidence string            `json:"evidence,omitempty"`
	Location string            `json:"location,omitempty"`
	Remedy   string            `json:"remediation,omitempty"`
	Attck    []string          `json:"attack,omitempty"`
	CWE      string            `json:"cwe,omitempty"`
	Score    float64           `json:"score,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// Report groups findings plus metadata for export.
type Report struct {
	Tool     string            `json:"tool"`
	Version  string            `json:"version"`
	Target   string            `json:"target"`
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
	Summary  map[string]int    `json:"summary"`
	Grade    string            `json:"grade"`
	Score    float64           `json:"score"`
	Findings []Finding         `json:"findings"`
	Extra    map[string]string `json:"extra,omitempty"`
}

func newReport(target string) *Report {
	return &Report{
		Tool:    APPNAME,
		Version: VERSION,
		Target:  target,
		Started: time.Now(),
		Summary: map[string]int{},
		Extra:   map[string]string{},
	}
}

func (r *Report) add(f Finding) {
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s-%04d", strings.ToUpper(APPNAME), len(r.Findings)+1)
	}
	r.Findings = append(r.Findings, f)
}

func (r *Report) finalize() {
	r.Finished = time.Now()
	r.Summary = map[string]int{}
	for _, f := range r.Findings {
		r.Summary[strings.ToUpper(f.Severity)]++
	}
	r.Score, r.Grade = gradeFindings(r.Findings)
}

// gradeFindings returns a 0..100 posture score and an A+..F letter grade.
// The score penalises by severity using a weighted, saturating model so that a
// single critical issue cannot be masked by many clean checks.
func gradeFindings(fs []Finding) (float64, string) {
	if len(fs) == 0 {
		return 100.0, "A+"
	}
	weights := map[string]float64{SevCritical: 40, SevHigh: 20, SevMedium: 8, SevLow: 3, SevInfo: 0}
	var penalty float64
	for _, f := range fs {
		penalty += weights[strings.ToUpper(f.Severity)]
	}
	// saturating curve
	score := 100.0 - penalty
	if score < 0 {
		score = 0
	}
	return score, letterGrade(score)
}

func letterGrade(score float64) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 67:
		return "D+"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func gradeColor(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return GRN + B
	case strings.HasPrefix(g, "B"):
		return GRN
	case strings.HasPrefix(g, "C"):
		return YLW
	case strings.HasPrefix(g, "D"):
		return R
	default:
		return R + B
	}
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK — a curated, real subset of enterprise techniques used for
// tagging findings. IDs follow the Txxxx / Txxxx.yyy convention.
// ---------------------------------------------------------------------------

var attckNames = map[string]string{
	"T1003": "OS Credential Dumping",
	"T1005": "Data from Local System",
	"T1014": "Rootkit",
	"T1021": "Remote Services",
	"T1027": "Obfuscated Files or Information",
	"T1036": "Masquerading",
	"T1040": "Network Sniffing",
	"T1046": "Network Service Discovery",
	"T1048": "Exfiltration Over Alternative Protocol",
	"T1055": "Process Injection",
	"T1059": "Command and Scripting Interpreter",
	"T1068": "Exploitation for Privilege Escalation",
	"T1070": "Indicator Removal",
	"T1071": "Application Layer Protocol",
	"T1078": "Valid Accounts",
	"T1090": "Proxy",
	"T1095": "Non-Application Layer Protocol",
	"T1098": "Account Manipulation",
	"T1105": "Ingress Tool Transfer",
	"T1110": "Brute Force",
	"T1132": "Data Encoding",
	"T1140": "Deobfuscate/Decode Files or Information",
	"T1176": "Browser Extensions",
	"T1190": "Exploit Public-Facing Application",
	"T1203": "Exploitation for Client Execution",
	"T1204": "User Execution",
	"T1210": "Exploitation of Remote Services",
	"T1211": "Exploitation for Defense Evasion",
	"T1212": "Exploitation for Credential Access",
	"T1497": "Virtualization/Sandbox Evasion",
	"T1518": "Software Discovery",
	"T1552": "Unsecured Credentials",
	"T1553": "Subvert Trust Controls",
	"T1557": "Adversary-in-the-Middle",
	"T1562": "Impair Defenses",
	"T1564": "Hide Artifacts",
	"T1570": "Lateral Tool Transfer",
	"T1571": "Non-Standard Port",
	"T1572": "Protocol Tunneling",
	"T1573": "Encrypted Channel",
	"T1587": "Develop Capabilities",
	"T1588": "Obtain Capabilities",
	"T1590": "Gather Victim Network Information",
	"T1600": "Weaken Encryption",
	"T1601": "Modify System Image",
	"T1649": "Steal or Forge Authentication Certificates",
}

func attckName(id string) string {
	base := id
	if i := strings.Index(id, "."); i >= 0 {
		base = id[:i]
	}
	if n, ok := attckNames[base]; ok {
		return n
	}
	return "technique"
}

// ---------------------------------------------------------------------------
// Export engine: TXT, Markdown, JSON, CSV, SARIF 2.1.0
// ---------------------------------------------------------------------------

func exportReport(r *Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "", "txt", "text":
		return exportTXT(r), nil
	case "md", "markdown":
		return exportMD(r), nil
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return "", fmt.Errorf("unknown format %q (want txt|md|json|csv|sarif)", format)
	}
}

func exportTXT(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s v%s — report\n", r.Tool, r.Version)
	fmt.Fprintf(&b, "Target   : %s\n", r.Target)
	fmt.Fprintf(&b, "Started  : %s\n", r.Started.Format(time.RFC3339))
	fmt.Fprintf(&b, "Finished : %s\n", r.Finished.Format(time.RFC3339))
	fmt.Fprintf(&b, "Grade    : %s (%.1f/100)\n", r.Grade, r.Score)
	b.WriteString(strings.Repeat("=", 72) + "\n")
	keys := []string{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}
	b.WriteString("Summary: ")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d  ", k, r.Summary[k])
	}
	b.WriteString("\n" + strings.Repeat("=", 72) + "\n\n")
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "[%d] %s  <%s>\n", i+1, f.Title, strings.ToUpper(f.Severity))
		fmt.Fprintf(&b, "    id       : %s\n", f.ID)
		if f.Category != "" {
			fmt.Fprintf(&b, "    category : %s\n", f.Category)
		}
		if f.Location != "" {
			fmt.Fprintf(&b, "    location : %s\n", f.Location)
		}
		if f.Detail != "" {
			fmt.Fprintf(&b, "    detail   : %s\n", f.Detail)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "    evidence : %s\n", f.Evidence)
		}
		if f.CWE != "" {
			fmt.Fprintf(&b, "    cwe      : %s\n", f.CWE)
		}
		if len(f.Attck) > 0 {
			var parts []string
			for _, a := range f.Attck {
				parts = append(parts, a+" ("+attckName(a)+")")
			}
			fmt.Fprintf(&b, "    att&ck   : %s\n", strings.Join(parts, ", "))
		}
		if f.Remedy != "" {
			fmt.Fprintf(&b, "    remedy   : %s\n", f.Remedy)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportMD(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s v%s — Report\n\n", r.Tool, r.Version)
	fmt.Fprintf(&b, "- **Target:** %s\n", r.Target)
	fmt.Fprintf(&b, "- **Started:** %s\n", r.Started.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Finished:** %s\n", r.Finished.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Grade:** %s (%.1f/100)\n\n", r.Grade, r.Score)
	b.WriteString("## Summary\n\n| Severity | Count |\n|---|---|\n")
	for _, k := range []string{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		fmt.Fprintf(&b, "| %s | %d |\n", k, r.Summary[k])
	}
	b.WriteString("\n## Findings\n\n")
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "### %d. %s `%s`\n\n", i+1, f.Title, strings.ToUpper(f.Severity))
		if f.Detail != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Detail)
		}
		fmt.Fprintf(&b, "- id: `%s`\n", f.ID)
		if f.Category != "" {
			fmt.Fprintf(&b, "- category: %s\n", f.Category)
		}
		if f.Location != "" {
			fmt.Fprintf(&b, "- location: `%s`\n", f.Location)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- evidence: `%s`\n", f.Evidence)
		}
		if f.CWE != "" {
			fmt.Fprintf(&b, "- cwe: %s\n", f.CWE)
		}
		if len(f.Attck) > 0 {
			var parts []string
			for _, a := range f.Attck {
				parts = append(parts, fmt.Sprintf("%s (%s)", a, attckName(a)))
			}
			fmt.Fprintf(&b, "- att&ck: %s\n", strings.Join(parts, ", "))
		}
		if f.Remedy != "" {
			fmt.Fprintf(&b, "- remediation: %s\n", f.Remedy)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportJSON(r *Report) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func exportCSV(r *Report) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "title", "severity", "category", "location", "cwe", "attack", "detail", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Title, strings.ToUpper(f.Severity), f.Category, f.Location, f.CWE, strings.Join(f.Attck, " "), f.Detail, f.Remedy})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SARIF 2.1.0 export.
func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	default:
		return "none"
	}
}

func exportSARIF(r *Report) (string, error) {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifArtifactLoc struct {
		URI string `json:"uri"`
	}
	type sarifPhysLoc struct {
		ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string            `json:"ruleId"`
		Level     string            `json:"level"`
		Message   sarifMsg          `json:"message"`
		Locations []sarifLoc        `json:"locations,omitempty"`
		Props     map[string]string `json:"properties,omitempty"`
	}
	type sarifRule struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		ShortDescription sarifMsg `json:"shortDescription"`
		Tags             []string `json:"-"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	ruleIdx := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		rid := f.ID
		if rid == "" {
			rid = strings.ToUpper(APPNAME)
		}
		if !ruleIdx[rid] {
			ruleIdx[rid] = true
			rules = append(rules, sarifRule{ID: rid, Name: f.Title, ShortDescription: sarifMsg{Text: f.Title}})
		}
		loc := []sarifLoc{}
		if f.Location != "" {
			loc = append(loc, sarifLoc{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtifactLoc{URI: f.Location}}})
		}
		props := map[string]string{"severity": strings.ToUpper(f.Severity)}
		if len(f.Attck) > 0 {
			props["attack"] = strings.Join(f.Attck, " ")
		}
		if f.CWE != "" {
			props["cwe"] = f.CWE
		}
		results = append(results, sarifResult{
			RuleID:    rid,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMsg{Text: f.Detail},
			Locations: loc,
			Props:     props,
		})
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: APPNAME, Version: VERSION, InformationURI: "https://" + WEBSITE, Rules: rules}},
			Results: results,
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// writeOut writes s to path, or to stdout when path is empty.
func writeOut(path, s string) error {
	if path == "" {
		fmt.Print(s)
		if !strings.HasSuffix(s, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(s), 0644)
}

// ---------------------------------------------------------------------------
// misc shared helpers
// ---------------------------------------------------------------------------

func atoiDef(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func hexdump(data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(&b, "%08x  ", i)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(&b, "%02x ", data[i+j])
			} else {
				b.WriteString("   ")
			}
			if j == 7 {
				b.WriteString(" ")
			}
		}
		b.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			c := data[i+j]
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
	})
}

func printReportTUI(r *Report) {
	fmt.Println()
	info(fmt.Sprintf("Target: %s", r.Target))
	fmt.Printf("  %s %s  %s\n",
		col("Grade:", W+B),
		col(r.Grade, gradeColor(r.Grade)),
		col(fmt.Sprintf("(%.1f/100)", r.Score), GY))
	fmt.Println()
	var rows [][]string
	for _, f := range r.Findings {
		att := ""
		if len(f.Attck) > 0 {
			att = strings.Join(f.Attck, ",")
		}
		rows = append(rows, []string{f.ID, f.Title, strings.ToUpper(f.Severity), att})
	}
	if len(rows) > 0 {
		table([]string{"ID", "FINDING", "SEVERITY", "ATT&CK"}, rows)
	}
	fmt.Println()
	for _, k := range []string{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		if r.Summary[k] > 0 {
			fmt.Printf("  %s %d\n", col(k+":", sevColor(k)), r.Summary[k])
		}
	}
}

func readStdin() string {
	var b strings.Builder
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		b.WriteString(sc.Text())
		b.WriteString("\n")
	}
	return b.String()
}

func readFileOrStdin(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return []byte(readStdin()), nil
	}
	return os.ReadFile(path)
}

// ============================================================================
// SECTION: CVSS v4.0 engine (faithful port of the FIRST reference algorithm)
// ============================================================================
//
// CVSS v4.0 scoring is table-driven. Every base vector maps to a 6-digit
// "MacroVector"; the official lookup table gives each MacroVector a score, and
// the final score is interpolated by severity distance within the MacroVector.
// The lookup table, max-composed highest vectors, and max-severity depths below
// are the authoritative data published by FIRST.

var cvss4Lookup = map[string]float64{
	"000000": 10,
	"000001": 9.9,
	"000010": 9.8,
	"000011": 9.5,
	"000020": 9.5,
	"000021": 9.2,
	"000100": 10,
	"000101": 9.6,
	"000110": 9.3,
	"000111": 8.7,
	"000120": 9.1,
	"000121": 8.1,
	"000200": 9.3,
	"000201": 9,
	"000210": 8.9,
	"000211": 8,
	"000220": 8.1,
	"000221": 6.8,
	"001000": 9.8,
	"001001": 9.5,
	"001010": 9.5,
	"001011": 9.2,
	"001020": 9,
	"001021": 8.4,
	"001100": 9.3,
	"001101": 9.2,
	"001110": 8.9,
	"001111": 8.1,
	"001120": 8.1,
	"001121": 6.5,
	"001200": 8.8,
	"001201": 8,
	"001210": 7.8,
	"001211": 7,
	"001220": 6.9,
	"001221": 4.8,
	"002001": 9.2,
	"002011": 8.2,
	"002021": 7.2,
	"002101": 7.9,
	"002111": 6.9,
	"002121": 5,
	"002201": 6.9,
	"002211": 5.5,
	"002221": 2.7,
	"010000": 9.9,
	"010001": 9.7,
	"010010": 9.5,
	"010011": 9.2,
	"010020": 9.2,
	"010021": 8.5,
	"010100": 9.5,
	"010101": 9.1,
	"010110": 9,
	"010111": 8.3,
	"010120": 8.4,
	"010121": 7.1,
	"010200": 9.2,
	"010201": 8.1,
	"010210": 8.2,
	"010211": 7.1,
	"010220": 7.2,
	"010221": 5.3,
	"011000": 9.5,
	"011001": 9.3,
	"011010": 9.2,
	"011011": 8.5,
	"011020": 8.5,
	"011021": 7.3,
	"011100": 9.2,
	"011101": 8.2,
	"011110": 8,
	"011111": 7.2,
	"011120": 7,
	"011121": 5.9,
	"011200": 8.4,
	"011201": 7,
	"011210": 7.1,
	"011211": 5.2,
	"011220": 5,
	"011221": 3,
	"012001": 8.6,
	"012011": 7.5,
	"012021": 5.2,
	"012101": 7.1,
	"012111": 5.2,
	"012121": 2.9,
	"012201": 6.3,
	"012211": 2.9,
	"012221": 1.7,
	"100000": 9.8,
	"100001": 9.5,
	"100010": 9.4,
	"100011": 8.7,
	"100020": 9.1,
	"100021": 8.1,
	"100100": 9.4,
	"100101": 8.9,
	"100110": 8.6,
	"100111": 7.4,
	"100120": 7.7,
	"100121": 6.4,
	"100200": 8.7,
	"100201": 7.5,
	"100210": 7.4,
	"100211": 6.3,
	"100220": 6.3,
	"100221": 4.9,
	"101000": 9.4,
	"101001": 8.9,
	"101010": 8.8,
	"101011": 7.7,
	"101020": 7.6,
	"101021": 6.7,
	"101100": 8.6,
	"101101": 7.6,
	"101110": 7.4,
	"101111": 5.8,
	"101120": 5.9,
	"101121": 5,
	"101200": 7.2,
	"101201": 5.7,
	"101210": 5.7,
	"101211": 5.2,
	"101220": 5.2,
	"101221": 2.5,
	"102001": 8.3,
	"102011": 7,
	"102021": 5.4,
	"102101": 6.5,
	"102111": 5.8,
	"102121": 2.6,
	"102201": 5.3,
	"102211": 2.1,
	"102221": 1.3,
	"110000": 9.5,
	"110001": 9,
	"110010": 8.8,
	"110011": 7.6,
	"110020": 7.6,
	"110021": 7,
	"110100": 9,
	"110101": 7.7,
	"110110": 7.5,
	"110111": 6.2,
	"110120": 6.1,
	"110121": 5.3,
	"110200": 7.7,
	"110201": 6.6,
	"110210": 6.8,
	"110211": 5.9,
	"110220": 5.2,
	"110221": 3,
	"111000": 8.9,
	"111001": 7.8,
	"111010": 7.6,
	"111011": 6.7,
	"111020": 6.2,
	"111021": 5.8,
	"111100": 7.4,
	"111101": 5.9,
	"111110": 5.7,
	"111111": 5.7,
	"111120": 4.7,
	"111121": 2.3,
	"111200": 6.1,
	"111201": 5.2,
	"111210": 5.7,
	"111211": 2.9,
	"111220": 2.4,
	"111221": 1.6,
	"112001": 7.1,
	"112011": 5.9,
	"112021": 3,
	"112101": 5.8,
	"112111": 2.6,
	"112121": 1.5,
	"112201": 2.3,
	"112211": 1.3,
	"112221": 0.6,
	"200000": 9.3,
	"200001": 8.7,
	"200010": 8.6,
	"200011": 7.2,
	"200020": 7.5,
	"200021": 5.8,
	"200100": 8.6,
	"200101": 7.4,
	"200110": 7.4,
	"200111": 6.1,
	"200120": 5.6,
	"200121": 3.4,
	"200200": 7,
	"200201": 5.4,
	"200210": 5.2,
	"200211": 4,
	"200220": 4,
	"200221": 2.2,
	"201000": 8.5,
	"201001": 7.5,
	"201010": 7.4,
	"201011": 5.5,
	"201020": 6.2,
	"201021": 5.1,
	"201100": 7.2,
	"201101": 5.7,
	"201110": 5.5,
	"201111": 4.1,
	"201120": 4.6,
	"201121": 1.9,
	"201200": 5.3,
	"201201": 3.6,
	"201210": 3.4,
	"201211": 1.9,
	"201220": 1.9,
	"201221": 0.8,
	"202001": 6.4,
	"202011": 5.1,
	"202021": 2,
	"202101": 4.7,
	"202111": 2.1,
	"202121": 1.1,
	"202201": 2.4,
	"202211": 0.9,
	"202221": 0.4,
	"210000": 8.8,
	"210001": 7.5,
	"210010": 7.3,
	"210011": 5.3,
	"210020": 6,
	"210021": 5,
	"210100": 7.3,
	"210101": 5.5,
	"210110": 5.9,
	"210111": 4,
	"210120": 4.1,
	"210121": 2,
	"210200": 5.4,
	"210201": 4.3,
	"210210": 4.5,
	"210211": 2.2,
	"210220": 2,
	"210221": 1.1,
	"211000": 7.5,
	"211001": 5.5,
	"211010": 5.8,
	"211011": 4.5,
	"211020": 4,
	"211021": 2.1,
	"211100": 6.1,
	"211101": 5.1,
	"211110": 4.8,
	"211111": 1.8,
	"211120": 2,
	"211121": 0.9,
	"211200": 4.6,
	"211201": 1.8,
	"211210": 1.7,
	"211211": 0.7,
	"211220": 0.8,
	"211221": 0.2,
	"212001": 5.3,
	"212011": 2.4,
	"212021": 1.4,
	"212101": 2.4,
	"212111": 1.2,
	"212121": 0.5,
	"212201": 1,
	"212211": 0.3,
	"212221": 0.1,
}

// maxComposed: for each EQ and level, the list of highest-severity vectors.
var maxComposedEQ1 = map[int][]string{
	0: {"AV:N/PR:N/UI:N/"},
	1: {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
	2: {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
}
var maxComposedEQ2 = map[int][]string{
	0: {"AC:L/AT:N/"},
	1: {"AC:H/AT:N/", "AC:L/AT:P/"},
}
var maxComposedEQ3 = map[int]map[string][]string{
	0: {"0": {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"}, "1": {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"}},
	1: {"0": {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"}, "1": {"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"}},
	2: {"1": {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"}},
}
var maxComposedEQ4 = map[int][]string{
	0: {"SC:H/SI:S/SA:S/"},
	1: {"SC:H/SI:H/SA:H/"},
	2: {"SC:L/SI:L/SA:L/"},
}
var maxComposedEQ5 = map[int][]string{
	0: {"E:A/"},
	1: {"E:P/"},
	2: {"E:U/"},
}

var maxSevEQ1 = map[int]int{0: 1, 1: 4, 2: 5}
var maxSevEQ2 = map[int]int{0: 1, 1: 2}
var maxSevEQ3EQ6 = map[int]map[int]int{0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}}
var maxSevEQ4 = map[int]int{0: 6, 1: 5, 2: 4}

// severity level indices, from the reference implementation.
var avLevels = map[string]float64{"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
var prLevels = map[string]float64{"N": 0.0, "L": 0.1, "H": 0.2}
var uiLevels = map[string]float64{"N": 0.0, "P": 0.1, "A": 0.2}
var acLevels = map[string]float64{"L": 0.0, "H": 0.1}
var atLevels = map[string]float64{"N": 0.0, "P": 0.1}
var vcLevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
var viLevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
var vaLevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
var scLevels = map[string]float64{"H": 0.1, "L": 0.2, "N": 0.3}
var siLevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
var saLevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
var crLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
var irLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
var arLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}

// v4Metric describes one CVSS v4.0 metric for validation and explanation.
type v4Metric struct {
	Key      string
	Name     string
	Group    string
	Values   []string
	ValNames map[string]string
	Help     string
}

var v4Metrics = []v4Metric{
	{"AV", "Attack Vector", "Base", []string{"N", "A", "L", "P"}, map[string]string{"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}, "The context by which vulnerability exploitation is possible."},
	{"AC", "Attack Complexity", "Base", []string{"L", "H"}, map[string]string{"L": "Low", "H": "High"}, "Measurable conditions beyond the attacker's control that must exist."},
	{"AT", "Attack Requirements", "Base", []string{"N", "P"}, map[string]string{"N": "None", "P": "Present"}, "Prerequisite deployment and execution conditions of the target."},
	{"PR", "Privileges Required", "Base", []string{"N", "L", "H"}, map[string]string{"N": "None", "L": "Low", "H": "High"}, "Level of privileges an attacker must possess before exploiting."},
	{"UI", "User Interaction", "Base", []string{"N", "P", "A"}, map[string]string{"N": "None", "P": "Passive", "A": "Active"}, "Requirement for a human user, other than the attacker."},
	{"VC", "Vuln. Confidentiality", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to the confidentiality of the vulnerable system."},
	{"VI", "Vuln. Integrity", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to the integrity of the vulnerable system."},
	{"VA", "Vuln. Availability", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to the availability of the vulnerable system."},
	{"SC", "Subseq. Confidentiality", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to the confidentiality of subsequent systems."},
	{"SI", "Subseq. Integrity", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to the integrity of subsequent systems."},
	{"SA", "Subseq. Availability", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to the availability of subsequent systems."},
	{"E", "Exploit Maturity", "Threat", []string{"X", "A", "P", "U"}, map[string]string{"X": "Not Defined", "A": "Attacked", "P": "PoC", "U": "Unreported"}, "Likelihood of the vulnerability being attacked."},
	{"CR", "Confidentiality Req.", "Env", []string{"X", "H", "M", "L"}, map[string]string{"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}, "Importance of confidentiality to the organization."},
	{"IR", "Integrity Req.", "Env", []string{"X", "H", "M", "L"}, map[string]string{"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}, "Importance of integrity to the organization."},
	{"AR", "Availability Req.", "Env", []string{"X", "H", "M", "L"}, map[string]string{"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}, "Importance of availability to the organization."},
	{"MAV", "Modified Attack Vector", "Env", []string{"X", "N", "A", "L", "P"}, map[string]string{"X": "Not Defined", "N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}, "Environmental override for Attack Vector."},
	{"MAC", "Modified Attack Complexity", "Env", []string{"X", "L", "H"}, map[string]string{"X": "Not Defined", "L": "Low", "H": "High"}, "Environmental override for Attack Complexity."},
	{"MAT", "Modified Attack Requirements", "Env", []string{"X", "N", "P"}, map[string]string{"X": "Not Defined", "N": "None", "P": "Present"}, "Environmental override for Attack Requirements."},
	{"MPR", "Modified Privileges Required", "Env", []string{"X", "N", "L", "H"}, map[string]string{"X": "Not Defined", "N": "None", "L": "Low", "H": "High"}, "Environmental override for Privileges Required."},
	{"MUI", "Modified User Interaction", "Env", []string{"X", "N", "P", "A"}, map[string]string{"X": "Not Defined", "N": "None", "P": "Passive", "A": "Active"}, "Environmental override for User Interaction."},
	{"MVC", "Modified Vuln. Confidentiality", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for Vulnerable Confidentiality."},
	{"MVI", "Modified Vuln. Integrity", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for Vulnerable Integrity."},
	{"MVA", "Modified Vuln. Availability", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for Vulnerable Availability."},
	{"MSC", "Modified Subseq. Confidentiality", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for Subsequent Confidentiality."},
	{"MSI", "Modified Subseq. Integrity", "Env", []string{"X", "S", "H", "L", "N"}, map[string]string{"X": "Not Defined", "S": "Safety", "H": "High", "L": "Low", "N": "None"}, "Environmental override for Subsequent Integrity (adds Safety)."},
	{"MSA", "Modified Subseq. Availability", "Env", []string{"X", "S", "H", "L", "N"}, map[string]string{"X": "Not Defined", "S": "Safety", "H": "High", "L": "Low", "N": "None"}, "Environmental override for Subsequent Availability (adds Safety)."},
	{"S", "Safety", "Supp", []string{"X", "N", "P"}, map[string]string{"X": "Not Defined", "N": "Negligible", "P": "Present"}, "Supplemental: safety impact per IEC 61508."},
	{"AU", "Automatable", "Supp", []string{"X", "N", "Y"}, map[string]string{"X": "Not Defined", "N": "No", "Y": "Yes"}, "Supplemental: can the attack be automated across many targets."},
	{"R", "Recovery", "Supp", []string{"X", "A", "U", "I"}, map[string]string{"X": "Not Defined", "A": "Automatic", "U": "User", "I": "Irrecoverable"}, "Supplemental: resilience/recovery of the system."},
	{"V", "Value Density", "Supp", []string{"X", "D", "C"}, map[string]string{"X": "Not Defined", "D": "Diffuse", "C": "Concentrated"}, "Supplemental: resources the attacker gains control over."},
	{"RE", "Vuln. Response Effort", "Supp", []string{"X", "L", "M", "H"}, map[string]string{"X": "Not Defined", "L": "Low", "M": "Moderate", "H": "High"}, "Supplemental: effort required to respond to the vulnerability."},
	{"U", "Provider Urgency", "Supp", []string{"X", "Clear", "Green", "Amber", "Red"}, map[string]string{"X": "Not Defined", "Clear": "Clear", "Green": "Green", "Amber": "Amber", "Red": "Red"}, "Supplemental: provider's assessment of urgency."},
}

func v4MetricByKey(k string) (v4Metric, bool) {
	for _, m := range v4Metrics {
		if m.Key == k {
			return m, true
		}
	}
	return v4Metric{}, false
}

// parseV4 parses a CVSS:4.0 vector string into a selection map.
func parseV4(vec string) (map[string]string, error) {
	sel := map[string]string{}
	vec = strings.TrimSpace(vec)
	parts := strings.Split(vec, "/")
	if len(parts) == 0 || !strings.EqualFold(parts[0], "CVSS:4.0") {
		return nil, fmt.Errorf("vector must start with CVSS:4.0")
	}
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed metric segment %q", p)
		}
		m, ok := v4MetricByKey(kv[0])
		if !ok {
			return nil, fmt.Errorf("unknown metric %q", kv[0])
		}
		valid := false
		for _, v := range m.Values {
			if v == kv[1] {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid value %q for metric %s", kv[1], kv[0])
		}
		sel[kv[0]] = kv[1]
	}
	// mandatory base metrics
	for _, k := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"} {
		if _, ok := sel[k]; !ok {
			return nil, fmt.Errorf("missing mandatory base metric %s", k)
		}
	}
	return sel, nil
}

// mSel implements the reference m() helper: environmental overrides and the
// worst-case defaults for E, CR, IR, AR.
func mSel(sel map[string]string, metric string) string {
	selected := sel[metric]
	if metric == "E" && (selected == "X" || selected == "") {
		return "A"
	}
	if (metric == "CR" || metric == "IR" || metric == "AR") && (selected == "X" || selected == "") {
		return "H"
	}
	if mv, ok := sel["M"+metric]; ok && mv != "X" {
		return mv
	}
	return selected
}

// macroVectorV4 computes the 6-digit MacroVector string.
func macroVectorV4(sel map[string]string) string {
	var eq1, eq2, eq3, eq4, eq5, eq6 int
	av, pr, ui := mSel(sel, "AV"), mSel(sel, "PR"), mSel(sel, "UI")
	if av == "N" && pr == "N" && ui == "N" {
		eq1 = 0
	} else if (av == "N" || pr == "N" || ui == "N") && !(av == "N" && pr == "N" && ui == "N") && av != "P" {
		eq1 = 1
	} else {
		eq1 = 2
	}
	ac, at := mSel(sel, "AC"), mSel(sel, "AT")
	if ac == "L" && at == "N" {
		eq2 = 0
	} else {
		eq2 = 1
	}
	vc, vi, va := mSel(sel, "VC"), mSel(sel, "VI"), mSel(sel, "VA")
	if vc == "H" && vi == "H" {
		eq3 = 0
	} else if vc == "H" || vi == "H" || va == "H" {
		eq3 = 1
	} else {
		eq3 = 2
	}
	msi, msa := mSel(sel, "MSI"), mSel(sel, "MSA")
	sc, si, sa := mSel(sel, "SC"), mSel(sel, "SI"), mSel(sel, "SA")
	if msi == "S" || msa == "S" {
		eq4 = 0
	} else if sc == "H" || si == "H" || sa == "H" {
		eq4 = 1
	} else {
		eq4 = 2
	}
	switch mSel(sel, "E") {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	default:
		eq5 = 2
	}
	cr, ir, ar := mSel(sel, "CR"), mSel(sel, "IR"), mSel(sel, "AR")
	if (cr == "H" && vc == "H") || (ir == "H" && vi == "H") || (ar == "H" && va == "H") {
		eq6 = 0
	} else {
		eq6 = 1
	}
	return fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6)
}

func extractValueMetric(metric, str string) string {
	idx := strings.Index(str, metric)
	if idx < 0 {
		return ""
	}
	extracted := str[idx+len(metric)+1:]
	if s := strings.Index(extracted, "/"); s > 0 {
		return extracted[:s]
	}
	return extracted
}

func getEQMaxes(macro string, eq int) []string {
	switch eq {
	case 1:
		return maxComposedEQ1[int(macro[0]-'0')]
	case 2:
		return maxComposedEQ2[int(macro[1]-'0')]
	case 4:
		return maxComposedEQ4[int(macro[3]-'0')]
	case 5:
		return maxComposedEQ5[int(macro[4]-'0')]
	}
	return nil
}

// cvss4Score computes the final CVSS v4.0 score (faithful to the reference).
func cvss4Score(sel map[string]string) float64 {
	allNone := true
	for _, mk := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if mSel(sel, mk) != "N" {
			allNone = false
			break
		}
	}
	if allNone {
		return 0.0
	}
	macro := macroVectorV4(sel)
	value := cvss4Lookup[macro]
	eq1 := int(macro[0] - '0')
	eq2 := int(macro[1] - '0')
	eq3 := int(macro[2] - '0')
	eq4 := int(macro[3] - '0')
	eq5 := int(macro[4] - '0')
	eq6 := int(macro[5] - '0')

	eq1nl := fmt.Sprintf("%d%d%d%d%d%d", eq1+1, eq2, eq3, eq4, eq5, eq6)
	eq2nl := fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2+1, eq3, eq4, eq5, eq6)
	var eq3eq6nl, eq3eq6nlL, eq3eq6nlR string
	var splitPath bool
	if eq3 == 1 && eq6 == 1 {
		eq3eq6nl = fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3+1, eq4, eq5, eq6)
	} else if eq3 == 0 && eq6 == 1 {
		eq3eq6nl = fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3+1, eq4, eq5, eq6)
	} else if eq3 == 1 && eq6 == 0 {
		eq3eq6nl = fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6+1)
	} else if eq3 == 0 && eq6 == 0 {
		splitPath = true
		eq3eq6nlL = fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6+1)
		eq3eq6nlR = fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3+1, eq4, eq5, eq6)
	} else {
		eq3eq6nl = fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3+1, eq4, eq5, eq6+1)
	}
	eq4nl := fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4+1, eq5, eq6)
	eq5nl := fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5+1, eq6)

	look := func(k string) float64 {
		if v, ok := cvss4Lookup[k]; ok {
			return v
		}
		return math.NaN()
	}
	sEq1 := look(eq1nl)
	sEq2 := look(eq2nl)
	var sEq3eq6 float64
	if splitPath {
		l := look(eq3eq6nlL)
		r := look(eq3eq6nlR)
		if (math.IsNaN(r)) || (!math.IsNaN(l) && l > r) {
			sEq3eq6 = l
		} else {
			sEq3eq6 = r
		}
	} else {
		sEq3eq6 = look(eq3eq6nl)
	}
	sEq4 := look(eq4nl)
	sEq5 := look(eq5nl)

	eq1maxes := getEQMaxes(macro, 1)
	eq2maxes := getEQMaxes(macro, 2)
	eq3eq6maxes := maxComposedEQ3[eq3][string(macro[5])]
	eq4maxes := getEQMaxes(macro, 4)
	eq5maxes := getEQMaxes(macro, 5)

	var maxVectors []string
	for _, a := range eq1maxes {
		for _, b := range eq2maxes {
			for _, c := range eq3eq6maxes {
				for _, d := range eq4maxes {
					for _, e := range eq5maxes {
						maxVectors = append(maxVectors, a+b+c+d+e)
					}
				}
			}
		}
	}

	lv := func(tbl map[string]float64, v string) float64 { return tbl[v] }
	var sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR float64
	for _, mv := range maxVectors {
		sdAV = lv(avLevels, mSel(sel, "AV")) - lv(avLevels, extractValueMetric("AV", mv))
		sdPR = lv(prLevels, mSel(sel, "PR")) - lv(prLevels, extractValueMetric("PR", mv))
		sdUI = lv(uiLevels, mSel(sel, "UI")) - lv(uiLevels, extractValueMetric("UI", mv))
		sdAC = lv(acLevels, mSel(sel, "AC")) - lv(acLevels, extractValueMetric("AC", mv))
		sdAT = lv(atLevels, mSel(sel, "AT")) - lv(atLevels, extractValueMetric("AT", mv))
		sdVC = lv(vcLevels, mSel(sel, "VC")) - lv(vcLevels, extractValueMetric("VC", mv))
		sdVI = lv(viLevels, mSel(sel, "VI")) - lv(viLevels, extractValueMetric("VI", mv))
		sdVA = lv(vaLevels, mSel(sel, "VA")) - lv(vaLevels, extractValueMetric("VA", mv))
		sdSC = lv(scLevels, mSel(sel, "SC")) - lv(scLevels, extractValueMetric("SC", mv))
		sdSI = lv(siLevels, mSel(sel, "SI")) - lv(siLevels, extractValueMetric("SI", mv))
		sdSA = lv(saLevels, mSel(sel, "SA")) - lv(saLevels, extractValueMetric("SA", mv))
		sdCR = lv(crLevels, mSel(sel, "CR")) - lv(crLevels, extractValueMetric("CR", mv))
		sdIR = lv(irLevels, mSel(sel, "IR")) - lv(irLevels, extractValueMetric("IR", mv))
		sdAR = lv(arLevels, mSel(sel, "AR")) - lv(arLevels, extractValueMetric("AR", mv))
		neg := false
		for _, d := range []float64{sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR} {
			if d < 0 {
				neg = true
				break
			}
		}
		if neg {
			continue
		}
		break
	}
	curEq1 := sdAV + sdPR + sdUI
	curEq2 := sdAC + sdAT
	curEq3eq6 := sdVC + sdVI + sdVA + sdCR + sdIR + sdAR
	curEq4 := sdSC + sdSI + sdSA
	step := 0.1
	availEq1 := value - sEq1
	availEq2 := value - sEq2
	availEq3eq6 := value - sEq3eq6
	availEq4 := value - sEq4
	availEq5 := value - sEq5
	maxEq1 := float64(maxSevEQ1[eq1]) * step
	maxEq2 := float64(maxSevEQ2[eq2]) * step
	maxEq3eq6 := float64(maxSevEQ3EQ6[eq3][eq6]) * step
	maxEq4 := float64(maxSevEQ4[eq4]) * step
	n := 0
	var nEq1, nEq2, nEq3eq6, nEq4, nEq5 float64
	if !math.IsNaN(availEq1) {
		n++
		nEq1 = availEq1 * (curEq1 / maxEq1)
	}
	if !math.IsNaN(availEq2) {
		n++
		nEq2 = availEq2 * (curEq2 / maxEq2)
	}
	if !math.IsNaN(availEq3eq6) {
		n++
		nEq3eq6 = availEq3eq6 * (curEq3eq6 / maxEq3eq6)
	}
	if !math.IsNaN(availEq4) {
		n++
		nEq4 = availEq4 * (curEq4 / maxEq4)
	}
	if !math.IsNaN(availEq5) {
		n++
		nEq5 = 0
	}
	var mean float64
	if n != 0 {
		mean = (nEq1 + nEq2 + nEq3eq6 + nEq4 + nEq5) / float64(n)
	}
	value -= mean
	if value < 0 {
		value = 0
	}
	if value > 10 {
		value = 10
	}
	return math.Round(value*10) / 10
}

// v4Nomenclature returns the vector's nomenclature (CVSS-B, CVSS-BE, ...).
func v4Nomenclature(sel map[string]string) string {
	threat := sel["E"] != "" && sel["E"] != "X"
	env := false
	for _, k := range []string{"CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"} {
		if v, ok := sel[k]; ok && v != "X" {
			env = true
			break
		}
	}
	switch {
	case threat && env:
		return "CVSS-BTE"
	case threat:
		return "CVSS-BT"
	case env:
		return "CVSS-BE"
	default:
		return "CVSS-B"
	}
}

// ============================================================================
// SECTION: CVSS v3.1 engine (exact specification equations)
// ============================================================================

type v3Metric struct {
	Key      string
	Name     string
	Group    string
	Values   []string
	ValNames map[string]string
	Help     string
}

var v3Metrics = []v3Metric{
	{"AV", "Attack Vector", "Base", []string{"N", "A", "L", "P"}, map[string]string{"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}, "Context by which exploitation is possible."},
	{"AC", "Attack Complexity", "Base", []string{"L", "H"}, map[string]string{"L": "Low", "H": "High"}, "Conditions beyond attacker control that must exist."},
	{"PR", "Privileges Required", "Base", []string{"N", "L", "H"}, map[string]string{"N": "None", "L": "Low", "H": "High"}, "Privileges an attacker must possess."},
	{"UI", "User Interaction", "Base", []string{"N", "R"}, map[string]string{"N": "None", "R": "Required"}, "Requirement for user participation."},
	{"S", "Scope", "Base", []string{"U", "C"}, map[string]string{"U": "Unchanged", "C": "Changed"}, "Can the vulnerability affect resources beyond its security scope."},
	{"C", "Confidentiality", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to confidentiality."},
	{"I", "Integrity", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to integrity."},
	{"A", "Availability", "Base", []string{"H", "L", "N"}, map[string]string{"H": "High", "L": "Low", "N": "None"}, "Impact to availability."},
	{"E", "Exploit Code Maturity", "Temporal", []string{"X", "H", "F", "P", "U"}, map[string]string{"X": "Not Defined", "H": "High", "F": "Functional", "P": "Proof-of-Concept", "U": "Unproven"}, "Likelihood based on exploit availability."},
	{"RL", "Remediation Level", "Temporal", []string{"X", "U", "W", "T", "O"}, map[string]string{"X": "Not Defined", "U": "Unavailable", "W": "Workaround", "T": "Temporary Fix", "O": "Official Fix"}, "Availability of a remediation."},
	{"RC", "Report Confidence", "Temporal", []string{"X", "C", "R", "U"}, map[string]string{"X": "Not Defined", "C": "Confirmed", "R": "Reasonable", "U": "Unknown"}, "Confidence in the vulnerability's existence."},
	{"CR", "Confidentiality Req.", "Env", []string{"X", "H", "M", "L"}, map[string]string{"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}, "Importance of confidentiality."},
	{"IR", "Integrity Req.", "Env", []string{"X", "H", "M", "L"}, map[string]string{"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}, "Importance of integrity."},
	{"AR", "Availability Req.", "Env", []string{"X", "H", "M", "L"}, map[string]string{"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}, "Importance of availability."},
	{"MAV", "Modified Attack Vector", "Env", []string{"X", "N", "A", "L", "P"}, map[string]string{"X": "Not Defined", "N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}, "Environmental override for AV."},
	{"MAC", "Modified Attack Complexity", "Env", []string{"X", "L", "H"}, map[string]string{"X": "Not Defined", "L": "Low", "H": "High"}, "Environmental override for AC."},
	{"MPR", "Modified Privileges Required", "Env", []string{"X", "N", "L", "H"}, map[string]string{"X": "Not Defined", "N": "None", "L": "Low", "H": "High"}, "Environmental override for PR."},
	{"MUI", "Modified User Interaction", "Env", []string{"X", "N", "R"}, map[string]string{"X": "Not Defined", "N": "None", "R": "Required"}, "Environmental override for UI."},
	{"MS", "Modified Scope", "Env", []string{"X", "U", "C"}, map[string]string{"X": "Not Defined", "U": "Unchanged", "C": "Changed"}, "Environmental override for Scope."},
	{"MC", "Modified Confidentiality", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for C."},
	{"MI", "Modified Integrity", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for I."},
	{"MA", "Modified Availability", "Env", []string{"X", "H", "L", "N"}, map[string]string{"X": "Not Defined", "H": "High", "L": "Low", "N": "None"}, "Environmental override for A."},
}

func v3MetricByKey(k string) (v3Metric, bool) {
	for _, m := range v3Metrics {
		if m.Key == k {
			return m, true
		}
	}
	return v3Metric{}, false
}

// numeric weights per CVSS v3.1 specification.
var v3AV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
var v3AC = map[string]float64{"L": 0.77, "H": 0.44}
var v3PRu = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
var v3PRc = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
var v3UI = map[string]float64{"N": 0.85, "R": 0.62}
var v3CIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
var v3E = map[string]float64{"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
var v3RL = map[string]float64{"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
var v3RC = map[string]float64{"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
var v3CIAReq = map[string]float64{"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}

func parseV3(vec string) (map[string]string, error) {
	sel := map[string]string{}
	vec = strings.TrimSpace(vec)
	parts := strings.Split(vec, "/")
	if len(parts) == 0 || !strings.EqualFold(parts[0], "CVSS:3.1") && !strings.EqualFold(parts[0], "CVSS:3.0") {
		return nil, fmt.Errorf("vector must start with CVSS:3.1 or CVSS:3.0")
	}
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed segment %q", p)
		}
		m, ok := v3MetricByKey(kv[0])
		if !ok {
			return nil, fmt.Errorf("unknown metric %q", kv[0])
		}
		ok2 := false
		for _, v := range m.Values {
			if v == kv[1] {
				ok2 = true
			}
		}
		if !ok2 {
			return nil, fmt.Errorf("invalid value %q for %s", kv[1], kv[0])
		}
		sel[kv[0]] = kv[1]
	}
	for _, k := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, ok := sel[k]; !ok {
			return nil, fmt.Errorf("missing mandatory base metric %s", k)
		}
	}
	return sel, nil
}

func roundUp1(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000.0) + 1) / 10.0
}

type v3Result struct {
	Base          float64
	Temporal      float64
	Environmental float64
	Overall       float64
	ImpactSub     float64
	ExploitSub    float64
	Severity      string
}

func v3Severity(score float64) string {
	switch {
	case score == 0:
		return "None"
	case score < 4.0:
		return "Low"
	case score < 7.0:
		return "Medium"
	case score < 9.0:
		return "High"
	default:
		return "Critical"
	}
}

func cvss3Compute(sel map[string]string) v3Result {
	g := func(k, def string) string {
		if v, ok := sel[k]; ok && v != "" {
			return v
		}
		return def
	}
	scope := g("S", "U")
	pr := v3PRu[g("PR", "N")]
	if scope == "C" {
		pr = v3PRc[g("PR", "N")]
	}
	iscBase := 1 - (1-v3CIA[g("C", "N")])*(1-v3CIA[g("I", "N")])*(1-v3CIA[g("A", "N")])
	var impact float64
	if scope == "U" {
		impact = 6.42 * iscBase
	} else {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}
	expl := 8.22 * v3AV[g("AV", "N")] * v3AC[g("AC", "L")] * pr * v3UI[g("UI", "N")]
	var base float64
	if impact <= 0 {
		base = 0
	} else if scope == "U" {
		base = roundUp1(math.Min(impact+expl, 10))
	} else {
		base = roundUp1(math.Min(1.08*(impact+expl), 10))
	}
	temporal := roundUp1(base * v3E[g("E", "X")] * v3RL[g("RL", "X")] * v3RC[g("RC", "X")])

	// environmental
	mscope := g("MS", scope)
	if mscope == "X" {
		mscope = scope
	}
	mav := g("MAV", g("AV", "N"))
	if mav == "X" {
		mav = g("AV", "N")
	}
	mac := g("MAC", g("AC", "L"))
	if mac == "X" {
		mac = g("AC", "L")
	}
	mpr := g("MPR", g("PR", "N"))
	if mpr == "X" {
		mpr = g("PR", "N")
	}
	mui := g("MUI", g("UI", "N"))
	if mui == "X" {
		mui = g("UI", "N")
	}
	mc := g("MC", g("C", "N"))
	if mc == "X" {
		mc = g("C", "N")
	}
	mi := g("MI", g("I", "N"))
	if mi == "X" {
		mi = g("I", "N")
	}
	ma := g("MA", g("A", "N"))
	if ma == "X" {
		ma = g("A", "N")
	}
	prW := v3PRu[mpr]
	if mscope == "C" {
		prW = v3PRc[mpr]
	}
	iscMod := math.Min(1-(1-v3CIA[mc]*v3CIAReq[g("CR", "X")])*(1-v3CIA[mi]*v3CIAReq[g("IR", "X")])*(1-v3CIA[ma]*v3CIAReq[g("AR", "X")]), 0.915)
	var modImpact float64
	if mscope == "U" {
		modImpact = 6.42 * iscMod
	} else {
		modImpact = 7.52*(iscMod-0.029) - 3.25*math.Pow(iscMod*0.9731-0.02, 13)
	}
	modExpl := 8.22 * v3AV[mav] * v3AC[mac] * prW * v3UI[mui]
	var env float64
	if modImpact <= 0 {
		env = 0
	} else if mscope == "U" {
		env = roundUp1(roundUp1(math.Min(modImpact+modExpl, 10)) * v3E[g("E", "X")] * v3RL[g("RL", "X")] * v3RC[g("RC", "X")])
	} else {
		env = roundUp1(roundUp1(math.Min(1.08*(modImpact+modExpl), 10)) * v3E[g("E", "X")] * v3RL[g("RL", "X")] * v3RC[g("RC", "X")])
	}
	overall := env
	if overall == 0 {
		overall = temporal
	}
	return v3Result{Base: base, Temporal: temporal, Environmental: env, Overall: overall, ImpactSub: math.Round(impact*10) / 10, ExploitSub: math.Round(expl*10) / 10, Severity: v3Severity(base)}
}

// ============================================================================
// SECTION: official metric value descriptions (FIRST CVSS specification text)
// ============================================================================
//
// These descriptions back the interactive "explain" and "reference" features.
// They are paraphrased from the published CVSS v3.1 and v4.0 specifications so
// that an analyst can understand precisely what each selected value means.

var v3ValueDesc = map[string]string{
	"AV:N": "Network: the vulnerable component is bound to the network stack and the attacker's path is through OSI layer 3 (the Internet). Remotely exploitable.",
	"AV:A": "Adjacent: limited to the same shared physical or logical network (e.g. same subnet, Bluetooth, local VLAN or secure VPN).",
	"AV:L": "Local: the attacker accesses the target via local read/write/execute, or relies on user interaction to open a malicious file.",
	"AV:P": "Physical: the attacker must physically touch or manipulate the vulnerable component (e.g. evil-maid, cold-boot).",
	"AC:L": "Low: specialised conditions do not exist; the attacker can expect repeatable success against the vulnerable component.",
	"AC:H": "High: a successful attack depends on conditions beyond the attacker's control (e.g. winning a race, defeating ASLR).",
	"PR:N": "None: the attacker is unauthorised prior to attack and requires no access to settings or files to carry out the attack.",
	"PR:L": "Low: the attacker is authorised with privileges that provide basic user capabilities affecting only user-owned resources.",
	"PR:H": "High: the attacker is authorised with privileges that provide significant (administrative) control over the component.",
	"UI:N": "None: the vulnerable system can be exploited without any interaction from any user.",
	"UI:R": "Required: a user must take some action before the vulnerability can be exploited (e.g. opening a document).",
	"S:U":  "Unchanged: an exploited vulnerability can only affect resources managed by the same security authority.",
	"S:C":  "Changed: an exploited vulnerability can affect resources beyond the security scope managed by the vulnerable component.",
	"C:H":  "High: total loss of confidentiality; all resources are divulged, or disclosure of restricted information with serious impact.",
	"C:L":  "Low: some loss of confidentiality; access to some restricted information but the attacker does not control what is obtained.",
	"C:N":  "None: there is no loss of confidentiality within the impacted component.",
	"I:H":  "High: total loss of integrity; the attacker can modify any/all files, or the consequence of modification is serious.",
	"I:L":  "Low: modification of data is possible but the attacker has no control over the consequence, or the amount is limited.",
	"I:N":  "None: there is no loss of integrity within the impacted component.",
	"A:H":  "High: total loss of availability; the attacker can fully deny access to resources in the impacted component.",
	"A:L":  "Low: reduced performance or interruptions in resource availability; no direct, serious consequence to the component.",
	"A:N":  "None: there is no impact to availability within the impacted component.",
}

var v4ValueDesc = map[string]string{
	"AV:N": "Network: remotely exploitable across one or more network hops (OSI layer 3).",
	"AV:A": "Adjacent: restricted to a logically adjacent topology (same subnet, Bluetooth, limited-range protocol).",
	"AV:L": "Local: via local access (keyboard, console or SSH) or through user interaction opening a malicious file.",
	"AV:P": "Physical: requires physical manipulation of the vulnerable component.",
	"AC:L": "Low: the attacker does not need to evade or circumvent any built-in security-enhancing conditions.",
	"AC:H": "High: the attacker must overcome security-hardening measures (e.g. defeat ASLR, break encryption) for the attack to succeed.",
	"AT:N": "None: the attack can be performed repeatably and does not depend on specific deployment or execution conditions.",
	"AT:P": "Present: a prerequisite deployment/execution condition must be met (race window, specific configuration, injected position).",
	"PR:N": "None: the attacker is unauthenticated prior to attack.",
	"PR:L": "Low: the attacker has privileges providing basic capabilities.",
	"PR:H": "High: the attacker has significant (administrative) privileges.",
	"UI:N": "None: no human user interaction is required.",
	"UI:P": "Passive: limited, unintentional interaction is required (e.g. a user visiting a page).",
	"UI:A": "Active: the user must perform specific, conscious interactions for exploitation.",
	"VC:H": "High: total loss of confidentiality of the vulnerable system.",
	"VC:L": "Low: some loss of confidentiality of the vulnerable system.",
	"VC:N": "None: no confidentiality impact to the vulnerable system.",
	"VI:H": "High: total loss of integrity of the vulnerable system.",
	"VI:L": "Low: some loss of integrity of the vulnerable system.",
	"VI:N": "None: no integrity impact to the vulnerable system.",
	"VA:H": "High: total loss of availability of the vulnerable system.",
	"VA:L": "Low: reduced availability of the vulnerable system.",
	"VA:N": "None: no availability impact to the vulnerable system.",
	"SC:H": "High: total loss of confidentiality of subsequent systems.",
	"SC:L": "Low: some loss of confidentiality of subsequent systems.",
	"SC:N": "None: no confidentiality impact to subsequent systems.",
	"SI:H": "High: total loss of integrity of subsequent systems.",
	"SI:L": "Low: some loss of integrity of subsequent systems.",
	"SI:N": "None: no integrity impact to subsequent systems.",
	"SI:S": "Safety: the subsequent-system integrity impact has a safety consequence (IEC 61508 category).",
	"SA:H": "High: total loss of availability of subsequent systems.",
	"SA:L": "Low: reduced availability of subsequent systems.",
	"SA:N": "None: no availability impact to subsequent systems.",
	"SA:S": "Safety: the subsequent-system availability impact has a safety consequence.",
	"E:A":  "Attacked: reliable exploitation is known to occur, or automated exploitation is available.",
	"E:P":  "Proof-of-Concept: proof-of-concept exploit code is publicly available.",
	"E:U":  "Unreported: no known proof-of-concept nor exploitation has been reported.",
}

func descV3(key string) string {
	if d, ok := v3ValueDesc[key]; ok {
		return d
	}
	return ""
}
func descV4(key string) string {
	if d, ok := v4ValueDesc[key]; ok {
		return d
	}
	return ""
}

// ============================================================================
// SECTION: sensitivity / what-if analysis
// ============================================================================
//
// Sensitivity analysis recomputes the score with each base metric driven to its
// most- and least-severe value in turn, revealing which metric contributes the
// most to the final number. This helps analysts understand drivers and triage.

type sensitivityRow struct {
	Metric   string
	Worst    float64
	Best     float64
	Delta    float64
	Baseline float64
}

func cloneSel(sel map[string]string) map[string]string {
	n := map[string]string{}
	for k, v := range sel {
		n[k] = v
	}
	return n
}

func rebuildVector(version string, sel map[string]string, order []string) string {
	vec := "CVSS:" + version
	for _, k := range order {
		if v, ok := sel[k]; ok {
			vec += "/" + k + ":" + v
		}
	}
	return vec
}

var v4BaseOrder = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
var v3BaseOrder = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

func sensitivityV4(sel map[string]string) []sensitivityRow {
	baseScore := cvss4Score(sel)
	var rows []sensitivityRow
	for _, k := range v4BaseOrder {
		m, _ := v4MetricByKey(k)
		// most severe = first value in Values (ordered high->low by our tables for impacts),
		// but for AV/AC/AT/PR/UI severity order differs; evaluate all values and take min/max.
		var worst, best float64 = -1, 11
		for _, v := range m.Values {
			if v == "X" {
				continue
			}
			c := cloneSel(sel)
			c[k] = v
			s := cvss4Score(c)
			if s > worst {
				worst = s
			}
			if s < best {
				best = s
			}
		}
		rows = append(rows, sensitivityRow{Metric: m.Name, Worst: worst, Best: best, Delta: worst - best, Baseline: baseScore})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Delta > rows[j].Delta })
	return rows
}

func sensitivityV3(sel map[string]string) []sensitivityRow {
	base := cvss3Compute(sel).Overall
	var rows []sensitivityRow
	for _, k := range v3BaseOrder {
		m, _ := v3MetricByKey(k)
		var worst, best float64 = -1, 11
		for _, v := range m.Values {
			c := cloneSel(sel)
			c[k] = v
			s := cvss3Compute(c).Overall
			if s > worst {
				worst = s
			}
			if s < best {
				best = s
			}
		}
		rows = append(rows, sensitivityRow{Metric: m.Name, Worst: worst, Best: best, Delta: worst - best, Baseline: base})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Delta > rows[j].Delta })
	return rows
}

func printSensitivity(vec string) {
	up := strings.ToUpper(vec)
	var rows []sensitivityRow
	if strings.HasPrefix(up, "CVSS:4.0") {
		sel, err := parseV4(vec)
		if err != nil {
			errMsg(err.Error())
			return
		}
		rows = sensitivityV4(sel)
	} else {
		sel, err := parseV3(vec)
		if err != nil {
			errMsg(err.Error())
			return
		}
		rows = sensitivityV3(sel)
	}
	var tr [][]string
	for _, r := range rows {
		tr = append(tr, []string{r.Metric, fmt.Sprintf("%.1f", r.Best), fmt.Sprintf("%.1f", r.Worst), fmt.Sprintf("%.1f", r.Delta)})
	}
	table([]string{"METRIC", "MIN", "MAX", "SWING"}, tr)
}

// ============================================================================
// SECTION: real-world CVE example vector library
// ============================================================================
//
// A curated set of well-known vulnerabilities with their published CVSS vectors,
// useful for teaching, regression-testing the engine and quick comparisons.

type cveExample struct {
	CVE    string
	Name   string
	Vector string
	Note   string
}

var cveLibrary = []cveExample{
	{"CVE-2021-44228", "Log4Shell (Apache Log4j JNDI)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Unauthenticated RCE via JNDI lookup; scope changed."},
	{"CVE-2014-0160", "Heartbleed (OpenSSL)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Remote memory disclosure, confidentiality only."},
	{"CVE-2017-0144", "EternalBlue (SMBv1)", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Wormable SMB RCE used by WannaCry."},
	{"CVE-2019-0708", "BlueKeep (RDP)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Pre-auth wormable RDP RCE."},
	{"CVE-2014-6271", "Shellshock (Bash)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Env-var command injection in Bash."},
	{"CVE-2018-7600", "Drupalgeddon2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Unauthenticated RCE in Drupal."},
	{"CVE-2017-5638", "Apache Struts2 OGNL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Content-Type OGNL injection (Equifax breach)."},
	{"CVE-2020-1472", "Zerologon (Netlogon)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Privilege escalation to Domain Admin."},
	{"CVE-2021-34527", "PrintNightmare", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "Windows Print Spooler RCE/LPE."},
	{"CVE-2022-22965", "Spring4Shell", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Spring Framework data-binding RCE."},
	{"CVE-2023-4863", "libwebp heap overflow", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "Zero-click image parsing memory corruption."},
	{"CVE-2024-3094", "XZ Utils backdoor", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Supply-chain backdoor in liblzma."},
	{"example-v4-rce", "Illustrative v4.0 unauth RCE", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "Maximum-impact v4.0 base vector."},
	{"example-v4-local", "Illustrative v4.0 local info-leak", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "Low-severity local confidentiality issue."},
}

func printCVELibrary() {
	var rows [][]string
	for _, e := range cveLibrary {
		r := scoreVector(e.Vector)
		rows = append(rows, []string{e.CVE, trunc(e.Name, 30), fmt.Sprintf("%.1f", r.Score), r.Severity})
	}
	table([]string{"CVE", "NAME", "SCORE", "SEVERITY"}, rows)
}

// ============================================================================
// SECTION: batch histogram & statistics
// ============================================================================

func batchStats(results []scoreResult) {
	buckets := map[string]int{"None": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
	var sum, max float64
	var minv float64 = 11
	var n int
	for _, r := range results {
		if r.Err != "" {
			continue
		}
		buckets[r.Severity]++
		sum += r.Score
		if r.Score > max {
			max = r.Score
		}
		if r.Score < minv {
			minv = r.Score
		}
		n++
	}
	if n == 0 {
		warnMsg("no valid vectors")
		return
	}
	order := []string{"Critical", "High", "Medium", "Low", "None"}
	maxc := 1
	for _, k := range order {
		if buckets[k] > maxc {
			maxc = buckets[k]
		}
	}
	fmt.Println()
	for _, k := range order {
		barlen := buckets[k] * 40 / maxc
		bar := strings.Repeat("█", barlen)
		fmt.Printf("  %-9s %3d %s\n", k, buckets[k], col(bar, sevColor(severityToSev(k))))
	}
	fmt.Println()
	info(fmt.Sprintf("count=%d  mean=%.2f  min=%.1f  max=%.1f", n, sum/float64(n), minv, max))
}

// ============================================================================
// SECTION: engine self-test (regression suite with published reference scores)
// ============================================================================
//
// Each case pairs a vector with its authoritative FIRST score. The self-test
// guards against regressions in the scoring equations and the v4.0 MacroVector
// interpolation. Run with --selftest or from the interactive menu.

type testCase struct {
	Vector string
	Expect float64
}

var selfTestCases = []testCase{
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
	{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
	{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
	{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C", 9.3},
	{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0},
	{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
	{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0},
}

type testOutcome struct {
	Vector string
	Expect float64
	Got    float64
	Pass   bool
}

func runSelfTest() ([]testOutcome, int, int) {
	var out []testOutcome
	pass, fail := 0, 0
	for _, tc := range selfTestCases {
		r := scoreVector(tc.Vector)
		ok := r.Err == "" && r.Score == tc.Expect
		if ok {
			pass++
		} else {
			fail++
		}
		out = append(out, testOutcome{Vector: tc.Vector, Expect: tc.Expect, Got: r.Score, Pass: ok})
	}
	return out, pass, fail
}

func printSelfTest() int {
	outs, pass, fail := runSelfTest()
	var rows [][]string
	for _, o := range outs {
		st := col("PASS", GRN+B)
		if !o.Pass {
			st = col("FAIL", R+B)
		}
		rows = append(rows, []string{trunc(o.Vector, 46), fmt.Sprintf("%.1f", o.Expect), fmt.Sprintf("%.1f", o.Got), st})
	}
	table([]string{"VECTOR", "EXPECT", "GOT", "RESULT"}, rows)
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("self-test: %d/%d passed", pass, pass+fail))
	} else {
		errMsg(fmt.Sprintf("self-test: %d passed, %d FAILED", pass, fail))
	}
	return fail
}

// ============================================================================
// SECTION: scoring guidance (long-form analyst guidance per metric group)
// ============================================================================

var scoringGuidance = []struct {
	Topic string
	Text  string
}{
	{"Attack Vector (AV)", "Score AV for the most remote path the attacker can realistically use. Prefer Network when the component is reachable over routed IP from an untrusted zone. Use Adjacent only when a shared broadcast/collision domain or limited-range protocol is genuinely required. Reserve Physical for attacks needing hands-on access."},
	{"Attack Complexity (AC)", "AC captures conditions outside the attacker's control that must hold for exploitation. A reliable, one-shot exploit is Low. If the attacker must win a race, defeat ASLR/stack canaries, or gather target-specific secrets first, AC is High."},
	{"Attack Requirements (AT, v4.0)", "New in v4.0, AT separates deployment/execution prerequisites from AC. Present means the target must be in a specific state (e.g. an active race window, a man-in-the-middle position already achieved) that the attacker cannot simply create at will."},
	{"Privileges Required (PR)", "Score PR by the privileges needed at the moment of exploitation, not after. Pre-authentication issues are None. Issues requiring an ordinary account are Low; issues requiring administrative/root or equivalent are High."},
	{"User Interaction (UI)", "If any human other than the attacker must act, UI is Required (v3.1) / Passive or Active (v4.0). v4.0 distinguishes incidental interaction (Passive, e.g. merely loading a page) from deliberate steps (Active, e.g. enabling macros)."},
	{"Scope (S, v3.1)", "Scope is Changed when the exploited component can impact resources governed by a different security authority (e.g. a hypervisor escape, or a sandbox breakout). Scope strongly amplifies the score and is removed in v4.0 in favour of Vulnerable vs Subsequent impact metrics."},
	{"Impact metrics (C/I/A or VC/VI/VA + SC/SI/SA)", "Rate each impact on the worst reasonable outcome. v4.0 splits impact into the Vulnerable system and any Subsequent systems. High means total loss; Low means partial/constrained loss; None means no effect. The v4.0 Safety value on subsequent integrity/availability marks life-safety consequences."},
	{"Threat metrics (E)", "Exploit maturity lowers the score when no exploitation is known. Default (Not Defined) is treated as the worst case. Move to Proof-of-Concept or Attacked only with evidence; this is the metric most likely to change over a vulnerability's lifetime."},
	{"Environmental metrics (CR/IR/AR, Modified*)", "Environmental metrics tailor the score to a specific deployment. Security Requirements weight each impact by how much the asset matters locally; Modified Base metrics override the base when the deployment differs from the general case (e.g. a component never exposed to the network)."},
	{"Qualitative severity", "Map the numeric score to None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9) or Critical (9.0-10.0). Remember the number is an aid to prioritisation, not an absolute measure of business risk."},
}

func printGuidance() {
	for _, g := range scoringGuidance {
		fmt.Println("  " + col("⬡  "+g.Topic, CY+B))
		for _, l := range wrapText(g.Text, 70) {
			fmt.Println("    " + col(l, GY))
		}
		fmt.Println()
	}
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ============================================================================
// SECTION: vulnerability-class templates
// ============================================================================
//
// Starting-point vectors for common vulnerability classes. Analysts copy the
// closest template and adjust. Each template carries both a v3.1 and a v4.0
// baseline plus a short rationale, so a scorer never begins from a blank vector.

type vulnTemplate struct {
	Class  string
	V31    string
	V40    string
	Reason string
}

var vulnTemplates = []vulnTemplate{
	{"Unauthenticated RCE (network)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Remote code execution reachable with no auth and no user action is the canonical 9.8/10 case."},
	{"Authenticated RCE (admin)", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Admin-only RCE still has full impact but far lower likelihood."},
	{"Reflected XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N", "Requires a victim to follow a crafted link; scope changes to the browser context."},
	{"Stored XSS", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N", "Persisted payload fires with only passive victim interaction."},
	{"SQL injection (data exfil)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", "Confidentiality dominates; integrity partial if writes possible."},
	{"Blind SQL injection", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "Inference-based extraction adds complexity/requirements."},
	{"Server-Side Request Forgery", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N", "Pivot to internal services changes scope / impacts subsequent systems."},
	{"Path traversal / LFI", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "Arbitrary file read; confidentiality only unless write/exec achieved."},
	{"Local privilege escalation", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Local user to root/SYSTEM; full impact, local vector."},
	{"Denial of service (network)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", "Availability-only impact with no confidentiality/integrity loss."},
	{"Sensitive data exposure", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "Information disclosure (e.g. Heartbleed-style memory leak)."},
	{"CSRF (state change)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", "Forces authenticated state change; integrity impact, needs victim action."},
	{"Insecure deserialization", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Often leads to RCE but reliability may vary (AC:H)."},
	{"Authentication bypass", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", "Gains privileged access; impact depends on the account obtained."},
	{"Hardcoded / leaked credential", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Treat as full compromise of the protected asset."},
	{"XXE (XML external entity)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:L/SI:N/SA:N", "File read / SSRF; availability impact via entity expansion."},
	{"Open redirect", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", "Low integrity impact; typically a phishing aid."},
	{"Hypervisor / sandbox escape", "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "Breaks the security boundary; scope changed / subsequent-system impact."},
	{"Physical/evil-maid", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", "Requires physical access; vector drives the score down."},
	{"Adjacent-network spoofing", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "Same L2 segment required; partial impacts."},
	{"Safety-impacting OT/ICS", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H", "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:S/SA:S", "v4.0 Safety values mark life-safety consequences on subsequent systems."},
}

func printTemplates() {
	for _, t := range vulnTemplates {
		fmt.Println("  " + col("⬡  "+t.Class, CY+B))
		r3 := scoreVector(t.V31)
		r4 := scoreVector(t.V40)
		fmt.Printf("    %s  %s (%.1f)\n", col("v3.1:", DIM), t.V31, r3.Score)
		fmt.Printf("    %s  %s (%.1f)\n", col("v4.0:", DIM), t.V40, r4.Score)
		for _, l := range wrapText(t.Reason, 68) {
			fmt.Println("    " + col(l, GY))
		}
		fmt.Println()
	}
}

// templateByClass finds the closest template by case-insensitive substring.
func templateByClass(q string) (vulnTemplate, bool) {
	q = strings.ToLower(strings.TrimSpace(q))
	for _, t := range vulnTemplates {
		if strings.Contains(strings.ToLower(t.Class), q) {
			return t, true
		}
	}
	return vulnTemplate{}, false
}

// ============================================================================
// SECTION: qualitative & nomenclature reference
// ============================================================================

func printNomenclature() {
	table([]string{"NOMENCLATURE", "MEANING"}, [][]string{
		{"CVSS-B", "Base metrics only"},
		{"CVSS-BE", "Base + Environmental metrics"},
		{"CVSS-BT", "Base + Threat metrics"},
		{"CVSS-BTE", "Base + Threat + Environmental metrics"},
	})
	fmt.Println()
	info("A complete v4.0 assessment should state which metric groups were supplied.")
}

// ============================================================================
// SECTION: full metric dictionary & remediation SLA mapping
// ============================================================================
//
// The dictionary prints every metric and every value for both CVSS versions,
// with the published meaning, giving analysts a single-screen reference.

func printDictionary() {
	fmt.Println("  " + col("CVSS v3.1 metric dictionary", CY+B))
	line(64)
	for _, m := range v3Metrics {
		fmt.Printf("  %s %s (%s)\n", col(m.Key, CY+B), col(m.Name, W), col(m.Group, GY))
		for _, v := range m.Values {
			meaning := m.ValNames[v]
			d := descV3(m.Key + ":" + v)
			if d == "" {
				fmt.Printf("      %s = %s\n", col(v, YLW), meaning)
			} else {
				fmt.Printf("      %s = %s — %s\n", col(v, YLW), meaning, col(d, GY))
			}
		}
	}
	fmt.Println()
	fmt.Println("  " + col("CVSS v4.0 metric dictionary", CY+B))
	line(64)
	for _, m := range v4Metrics {
		fmt.Printf("  %s %s (%s)\n", col(m.Key, CY+B), col(m.Name, W), col(m.Group, GY))
		for _, v := range m.Values {
			meaning := m.ValNames[v]
			d := descV4(m.Key + ":" + v)
			if d == "" {
				fmt.Printf("      %s = %s\n", col(v, YLW), meaning)
			} else {
				fmt.Printf("      %s = %s — %s\n", col(v, YLW), meaning, col(d, GY))
			}
		}
	}
}

// remediation SLA mapping suggests a response window from the severity band.
// These are illustrative, policy-aligned defaults (e.g. common CISA/FIRST and
// enterprise patch SLAs); organisations tune them to their risk appetite.

type slaRow struct {
	Band    string
	Range   string
	SLA     string
	Posture string
}

var slaTable = []slaRow{
	{"Critical", "9.0 - 10.0", "Patch within 24-72 hours; consider emergency change", "Treat as active incident; isolate if exploited in the wild."},
	{"High", "7.0 - 8.9", "Patch within 7 days", "Prioritise internet-facing and privileged systems first."},
	{"Medium", "4.0 - 6.9", "Patch within 30 days", "Batch into the standard maintenance cycle."},
	{"Low", "0.1 - 3.9", "Patch within 90 days or risk-accept", "Document and track; fix opportunistically."},
	{"None", "0.0", "No action required", "Informational only."},
}

func printSLA() {
	var rows [][]string
	for _, s := range slaTable {
		rows = append(rows, []string{s.Band, s.Range, s.SLA})
	}
	table([]string{"SEVERITY", "SCORE", "SUGGESTED SLA"}, rows)
	fmt.Println()
	for _, s := range slaTable {
		fmt.Printf("  %s %s\n", col(s.Band+":", sevColor(severityToSev(s.Band))), col(s.Posture, GY))
	}
	fmt.Println()
	warnMsg("SLAs are illustrative defaults; align them with your own risk policy.")
}

// slaForScore returns the suggested SLA string for a numeric score.
func slaForScore(score float64) string {
	sev := v3Severity(score)
	for _, s := range slaTable {
		if s.Band == sev {
			return s.SLA
		}
	}
	return "review"
}

// ============================================================================
// SECTION: additional verified cases & score interpretation reference
// ============================================================================

// moreVerified holds further vectors with authoritative scores; appended to the
// self-test suite at startup so the regression guard stays comprehensive.
var moreVerified = []testCase{
	{"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.4},
	{"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 6.1},
	{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8},
	{"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2},
	{"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5},
	{"CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.3},
}

func init() {
	selfTestCases = append(selfTestCases, moreVerified...)
}

// scoreInterpretation returns a short, human interpretation of a numeric score.
func scoreInterpretation(score float64) string {
	switch {
	case score == 0:
		return "No measurable impact — informational only."
	case score < 4.0:
		return "Low severity — limited impact or difficult to exploit; schedule a routine fix."
	case score < 7.0:
		return "Medium severity — meaningful impact under some conditions; fix in the normal cycle."
	case score < 9.0:
		return "High severity — significant impact and realistic exploitation; prioritise remediation."
	default:
		return "Critical severity — severe, readily exploitable impact; treat with urgency."
	}
}

// printScoreLegend prints the qualitative bands with their colour and meaning.
func printScoreLegend() {
	bands := []struct {
		Name  string
		Range string
	}{
		{"None", "0.0"},
		{"Low", "0.1 - 3.9"},
		{"Medium", "4.0 - 6.9"},
		{"High", "7.0 - 8.9"},
		{"Critical", "9.0 - 10.0"},
	}
	for _, b := range bands {
		fmt.Printf("  %s  %s\n", col(fmt.Sprintf("%-9s %-11s", b.Name, b.Range), sevColor(severityToSev(b.Name))), col(scoreInterpretation(bandMid(b.Name)), GY))
	}
}

func bandMid(name string) float64 {
	switch name {
	case "None":
		return 0
	case "Low":
		return 2
	case "Medium":
		return 5.5
	case "High":
		return 8
	default:
		return 9.5
	}
}

// ============================================================================
// SECTION: scoring facade, batch, explain, compare
// ============================================================================

type scoreResult struct {
	Vector   string
	Version  string
	Score    float64
	Severity string
	Macro    string
	Nomencl  string
	V3       *v3Result
	Err      string
}

func sevFromScore(s float64) string { return v3Severity(s) }

func scoreVector(vec string) scoreResult {
	vec = strings.TrimSpace(vec)
	up := strings.ToUpper(vec)
	res := scoreResult{Vector: vec}
	if strings.HasPrefix(up, "CVSS:4.0") {
		sel, err := parseV4(vec)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		res.Version = "4.0"
		res.Score = cvss4Score(sel)
		res.Severity = sevFromScore(res.Score)
		res.Macro = macroVectorV4(sel)
		res.Nomencl = v4Nomenclature(sel)
		return res
	}
	if strings.HasPrefix(up, "CVSS:3.1") || strings.HasPrefix(up, "CVSS:3.0") {
		sel, err := parseV3(vec)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		r := cvss3Compute(sel)
		res.Version = "3.1"
		res.Score = r.Overall
		res.Severity = v3Severity(r.Overall)
		res.V3 = &r
		return res
	}
	res.Err = "unrecognised CVSS version prefix (want CVSS:4.0, CVSS:3.1 or CVSS:3.0)"
	return res
}

func severityToSev(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low":
		return SevLow
	default:
		return SevInfo
	}
}

func scoreToFinding(idx int, res scoreResult) Finding {
	f := Finding{
		ID:       fmt.Sprintf("CVSS-%04d", idx),
		Title:    fmt.Sprintf("CVSS v%s %.1f (%s)", res.Version, res.Score, res.Severity),
		Severity: severityToSev(res.Severity),
		Category: "cvss",
		Detail:   fmt.Sprintf("Vector %s scores %.1f (%s).", res.Vector, res.Score, res.Severity),
		Evidence: res.Vector,
		Score:    res.Score,
		Meta:     map[string]string{"version": res.Version},
	}
	if res.Macro != "" {
		f.Meta["macrovector"] = res.Macro
		f.Meta["nomenclature"] = res.Nomencl
	}
	switch severityToSev(res.Severity) {
	case SevCritical, SevHigh:
		f.Attck = []string{"T1190", "T1068"}
	case SevMedium:
		f.Attck = []string{"T1203"}
	}
	return f
}

func explainVectorV4(sel map[string]string) {
	line(64)
	fmt.Println("  " + col("CVSS v4.0 metric breakdown", CY+B))
	var rows [][]string
	for _, m := range v4Metrics {
		v, ok := sel[m.Key]
		if !ok {
			continue
		}
		rows = append(rows, []string{m.Key, m.Name, v, m.ValNames[v]})
	}
	table([]string{"KEY", "METRIC", "VAL", "MEANING"}, rows)
	fmt.Println()
	for _, m := range v4Metrics {
		if v, ok := sel[m.Key]; ok {
			if d := descV4(m.Key + ":" + v); d != "" {
				fmt.Println("  " + col(m.Key+":"+v, CY+B) + "  " + col(d, GY))
			}
		}
	}
	fmt.Println()
	info("MacroVector: " + macroVectorV4(sel))
	info("Nomenclature: " + v4Nomenclature(sel))
	info(fmt.Sprintf("Score: %.1f (%s)", cvss4Score(sel), v3Severity(cvss4Score(sel))))
}

func explainVectorV3(sel map[string]string) {
	line(64)
	fmt.Println("  " + col("CVSS v3.1 metric breakdown", CY+B))
	var rows [][]string
	for _, m := range v3Metrics {
		v, ok := sel[m.Key]
		if !ok {
			continue
		}
		rows = append(rows, []string{m.Key, m.Name, v, m.ValNames[v]})
	}
	table([]string{"KEY", "METRIC", "VAL", "MEANING"}, rows)
	r := cvss3Compute(sel)
	fmt.Println()
	info(fmt.Sprintf("Impact subscore     : %.1f", r.ImpactSub))
	info(fmt.Sprintf("Exploitability sub  : %.1f", r.ExploitSub))
	info(fmt.Sprintf("Base / Temporal / Env : %.1f / %.1f / %.1f", r.Base, r.Temporal, r.Environmental))
	fmt.Println()
	for _, m := range v3Metrics {
		if v, ok := sel[m.Key]; ok {
			if d := descV3(m.Key + ":" + v); d != "" {
				fmt.Println("  " + col(m.Key+":"+v, CY+B) + "  " + col(d, GY))
			}
		}
	}
}

// batchScore scores many vectors (one per line) and returns findings.
func batchScore(lines []string) []scoreResult {
	var out []scoreResult
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, scoreVector(l))
	}
	return out
}

// ============================================================================
// SECTION: demo
// ============================================================================

var demoVectors = []string{
	"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
	"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
	"CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C",
	"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
}

func runDemo(format, output string) error {
	clear()
	banner()
	okMsg("Running self-contained CVSS demo (v3.1 + v4.0, synthetic data)")
	fmt.Println()
	rep := newReport("demo:synthetic-cvss")
	results := batchScore(demoVectors)
	var rows [][]string
	for i, r := range results {
		if r.Err != "" {
			rows = append(rows, []string{fmt.Sprintf("%d", i+1), r.Vector, "ERR", r.Err})
			continue
		}
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), "v" + r.Version, fmt.Sprintf("%.1f", r.Score), r.Severity})
		rep.add(scoreToFinding(i+1, r))
	}
	table([]string{"#", "VERSION", "SCORE", "SEVERITY"}, rows)
	rep.finalize()
	fmt.Println()
	printReportTUI(rep)
	if format != "" || output != "" {
		if format == "" {
			format = "txt"
		}
		s, err := exportReport(rep, format)
		if err != nil {
			return err
		}
		if err := writeOut(output, s); err != nil {
			return err
		}
		if output != "" {
			okMsg("Wrote " + output)
		}
	}
	return nil
}

// ============================================================================
// SECTION: interactive TUI
// ============================================================================

func interactive() {
	items := []menuItem{
		{"1", "Score Vector", "Score a single v3.1/v4.0 vector", GRN},
		{"2", "Guided v4.0", "Build & score a v4.0 vector step by step", CY},
		{"3", "Guided v3.1", "Build & score a v3.1 vector step by step", YLW},
		{"4", "Explain", "Full metric breakdown of a vector", MG},
		{"5", "Batch Score", "Score many vectors from a file", OR},
		{"6", "Compare", "Diff two vectors side by side", BL},
		{"7", "Reference v4.0", "v4.0 metric reference table", CY},
		{"8", "Reference v3.1", "v3.1 metric reference table", MG},
		{"9", "Severity Scale", "Qualitative score ranges", GRN},
		{"10", "Sensitivity", "Which metric moves the score most", OR},
		{"11", "CVE Library", "Built-in example CVE vectors", BL},
		{"12", "Guidance", "Analyst scoring guidance", CY},
		{"13", "Templates", "Vulnerability-class vector templates", MG},
		{"14", "Dictionary", "Full metric dictionary", YLW},
		{"15", "SLA Mapping", "Remediation SLA by score", GRN},
		{"16", "Nomenclature", "CVSS-B / BT / BE / BTE naming", BL},
		{"17", "Self-Test", "Engine regression self-test", CY},
		{"18", "Demo", "Run a synthetic demo", OR},
		{"19", "Export Report", "Save last results (txt/md/json/csv/sarif)", YLW},
	}
	for {
		choice := showMenu("CVSS 3.1 / 4.0 Calculator", items)
		switch choice {
		case "h", "H", "help", "?":
			tuiHelp()
		case "0", "00", "q", "Q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		case "1":
			uiScoreSingle()
		case "2":
			uiGuidedV4()
		case "3":
			uiGuidedV3()
		case "4":
			uiExplain()
		case "5":
			uiBatch()
		case "6":
			uiCompare()
		case "7":
			uiRefV4()
		case "8":
			uiRefV3()
		case "9":
			uiSeverityScale()
		case "10":
			uiSensitivity()
		case "11":
			printCVELibHold()
		case "12":
			clear()
			banner()
			printGuidance()
			pause()
		case "13":
			clear()
			banner()
			printTemplates()
			pause()
		case "14":
			clear()
			banner()
			printDictionary()
			pause()
		case "15":
			clear()
			banner()
			printSLA()
			pause()
		case "16":
			clear()
			banner()
			printNomenclature()
			pause()
		case "17":
			clear()
			banner()
			printSelfTest()
			pause()
		case "18":
			_ = runDemo("", "")
			pause()
		case "19":
			uiExportLast()
		default:
			errMsg("Unknown option")
			pause()
		}
	}
}

var lastBatch []scoreResult

func uiScoreSingle() {
	clear()
	banner()
	vec := prompt("CVSS vector")
	if vec == "" {
		return
	}
	r := scoreVector(vec)
	fmt.Println()
	if r.Err != "" {
		errMsg(r.Err)
		pause()
		return
	}
	okMsg(fmt.Sprintf("CVSS v%s score: %s (%s)", r.Version, col(fmt.Sprintf("%.1f", r.Score), gradeColor(scoreGrade(r.Score))), r.Severity))
	if r.Macro != "" {
		info("MacroVector: " + r.Macro + "   Nomenclature: " + r.Nomencl)
	}
	if r.V3 != nil {
		info(fmt.Sprintf("Base %.1f  Temporal %.1f  Env %.1f", r.V3.Base, r.V3.Temporal, r.V3.Environmental))
	}
	if n, err := normalizeVector(vec); err == nil && n != strings.TrimSpace(vec) {
		info("canonical: " + n)
	}
	if u := firstURL(vec); u != "" {
		info("calculator: " + u)
	}
	lastBatch = []scoreResult{r}
	pause()
}

func scoreGrade(s float64) string {
	switch {
	case s == 0:
		return "A+"
	case s < 4:
		return "B"
	case s < 7:
		return "C"
	case s < 9:
		return "D"
	default:
		return "F"
	}
}

func uiGuidedV4() {
	clear()
	banner()
	fmt.Println("  " + col("Guided CVSS v4.0 — enter the letter for each base metric", CY+B))
	fmt.Println()
	sel := map[string]string{}
	base := []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
	for _, k := range base {
		m, _ := v4MetricByKey(k)
		opts := []string{}
		for _, v := range m.Values {
			opts = append(opts, v+"="+m.ValNames[v])
		}
		ans := prompt(fmt.Sprintf("%s %s [%s]", k, m.Name, strings.Join(opts, " ")))
		ans = strings.ToUpper(strings.TrimSpace(ans))
		if ans == "" {
			ans = m.Values[0]
		}
		sel[k] = ans
	}
	vec := "CVSS:4.0"
	for _, k := range base {
		vec += "/" + k + ":" + sel[k]
	}
	fmt.Println()
	okMsg("Vector: " + vec)
	r := scoreVector(vec)
	if r.Err != "" {
		errMsg(r.Err)
	} else {
		okMsg(fmt.Sprintf("Score %.1f (%s)  macro=%s", r.Score, r.Severity, r.Macro))
	}
	pause()
}

func uiGuidedV3() {
	clear()
	banner()
	fmt.Println("  " + col("Guided CVSS v3.1 — enter the letter for each base metric", CY+B))
	fmt.Println()
	sel := map[string]string{}
	base := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, k := range base {
		m, _ := v3MetricByKey(k)
		opts := []string{}
		for _, v := range m.Values {
			opts = append(opts, v+"="+m.ValNames[v])
		}
		ans := prompt(fmt.Sprintf("%s %s [%s]", k, m.Name, strings.Join(opts, " ")))
		ans = strings.ToUpper(strings.TrimSpace(ans))
		if ans == "" {
			ans = m.Values[0]
		}
		sel[k] = ans
	}
	vec := "CVSS:3.1"
	for _, k := range base {
		vec += "/" + k + ":" + sel[k]
	}
	fmt.Println()
	okMsg("Vector: " + vec)
	r := scoreVector(vec)
	if r.Err != "" {
		errMsg(r.Err)
	} else {
		okMsg(fmt.Sprintf("Score %.1f (%s)", r.Score, r.Severity))
	}
	pause()
}

func uiExplain() {
	clear()
	banner()
	vec := prompt("CVSS vector to explain")
	if vec == "" {
		return
	}
	up := strings.ToUpper(vec)
	if strings.HasPrefix(up, "CVSS:4.0") {
		sel, err := parseV4(vec)
		if err != nil {
			errMsg(err.Error())
			pause()
			return
		}
		explainVectorV4(sel)
	} else {
		sel, err := parseV3(vec)
		if err != nil {
			errMsg(err.Error())
			pause()
			return
		}
		explainVectorV3(sel)
	}
	pause()
}

func uiBatch() {
	clear()
	banner()
	path := prompt("path to file with one vector per line")
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	lastBatch = batchScore(strings.Split(string(data), "\n"))
	var rows [][]string
	for i, r := range lastBatch {
		s := fmt.Sprintf("%.1f", r.Score)
		if r.Err != "" {
			s = "ERR"
		}
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), "v" + r.Version, s, r.Severity, trunc(r.Vector, 40)})
	}
	fmt.Println()
	table([]string{"#", "VER", "SCORE", "SEV", "VECTOR"}, rows)
	batchStats(lastBatch)
	pause()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func uiCompare() {
	clear()
	banner()
	a := prompt("vector A")
	b := prompt("vector B")
	ra := scoreVector(a)
	rb := scoreVector(b)
	fmt.Println()
	table([]string{"", "A", "B"}, [][]string{
		{"version", ra.Version, rb.Version},
		{"score", fmt.Sprintf("%.1f", ra.Score), fmt.Sprintf("%.1f", rb.Score)},
		{"severity", ra.Severity, rb.Severity},
	})
	fmt.Println()
	if ra.Err == "" && rb.Err == "" {
		d := rb.Score - ra.Score
		info(fmt.Sprintf("delta (B-A): %+.1f", d))
	}
	pause()
}

func uiRefV4() {
	clear()
	banner()
	var rows [][]string
	for _, m := range v4Metrics {
		rows = append(rows, []string{m.Key, m.Group, m.Name, strings.Join(m.Values, "/")})
	}
	table([]string{"KEY", "GROUP", "METRIC", "VALUES"}, rows)
	pause()
}

func uiRefV3() {
	clear()
	banner()
	var rows [][]string
	for _, m := range v3Metrics {
		rows = append(rows, []string{m.Key, m.Group, m.Name, strings.Join(m.Values, "/")})
	}
	table([]string{"KEY", "GROUP", "METRIC", "VALUES"}, rows)
	pause()
}

func uiSeverityScale() {
	clear()
	banner()
	table([]string{"RANGE", "SEVERITY"}, [][]string{
		{"0.0", "None"},
		{"0.1 - 3.9", "Low"},
		{"4.0 - 6.9", "Medium"},
		{"7.0 - 8.9", "High"},
		{"9.0 - 10.0", "Critical"},
	})
	pause()
}

func uiExportLast() {
	clear()
	banner()
	if len(lastBatch) == 0 {
		warnMsg("No results to export yet; run a score or batch first.")
		pause()
		return
	}
	fmtsel := prompt("format [txt|md|json|csv|sarif]")
	out := prompt("output file (blank=stdout)")
	rep := newReport("interactive")
	for i, r := range lastBatch {
		if r.Err == "" {
			rep.add(scoreToFinding(i+1, r))
		}
	}
	rep.finalize()
	s, err := exportReport(rep, fmtsel)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	if err := writeOut(out, s); err != nil {
		errMsg(err.Error())
	} else if out != "" {
		okMsg("Wrote " + out)
	}
	pause()
}

func uiSensitivity() {
	clear()
	banner()
	vec := prompt("CVSS vector for sensitivity analysis")
	if vec == "" {
		return
	}
	fmt.Println()
	printSensitivity(vec)
	pause()
}

func printCVELibHold() {
	clear()
	banner()
	printCVELibrary()
	pause()
}

// ============================================================================
// SECTION: vector utilities — FIRST.org link, canonical form, validation
// ============================================================================

// firstURL returns the official FIRST.org calculator link for a vector.
func firstURL(vec string) string {
	v := strings.TrimSpace(vec)
	up := strings.ToUpper(v)
	switch {
	case strings.HasPrefix(up, "CVSS:4.0"):
		return "https://www.first.org/cvss/calculator/4.0#" + v
	case strings.HasPrefix(up, "CVSS:3.1"):
		return "https://www.first.org/cvss/calculator/3.1#" + v
	case strings.HasPrefix(up, "CVSS:3.0"):
		return "https://www.first.org/cvss/calculator/3.0#" + v
	default:
		return ""
	}
}

// normalizeVector reparses a vector and rebuilds it in canonical specification
// order (metrics ordered as published, duplicates dropped).
func normalizeVector(vec string) (string, error) {
	up := strings.ToUpper(strings.TrimSpace(vec))
	if strings.HasPrefix(up, "CVSS:4.0") {
		sel, err := parseV4(vec)
		if err != nil {
			return "", err
		}
		out := "CVSS:4.0"
		for _, m := range v4Metrics {
			if v, ok := sel[m.Key]; ok {
				out += "/" + m.Key + ":" + v
			}
		}
		return out, nil
	}
	if strings.HasPrefix(up, "CVSS:3.1") || strings.HasPrefix(up, "CVSS:3.0") {
		sel, err := parseV3(vec)
		if err != nil {
			return "", err
		}
		ver := "3.1"
		if strings.HasPrefix(up, "CVSS:3.0") {
			ver = "3.0"
		}
		out := "CVSS:" + ver
		for _, m := range v3Metrics {
			if v, ok := sel[m.Key]; ok {
				out += "/" + m.Key + ":" + v
			}
		}
		return out, nil
	}
	return "", fmt.Errorf("unrecognised CVSS version prefix (want CVSS:4.0, CVSS:3.1 or CVSS:3.0)")
}

// validateVector reports whether a vector is well-formed (parses cleanly).
func validateVector(vec string) error {
	up := strings.ToUpper(strings.TrimSpace(vec))
	switch {
	case strings.HasPrefix(up, "CVSS:4.0"):
		_, err := parseV4(vec)
		return err
	case strings.HasPrefix(up, "CVSS:3.1"), strings.HasPrefix(up, "CVSS:3.0"):
		_, err := parseV3(vec)
		return err
	default:
		return fmt.Errorf("unrecognised CVSS version prefix (want CVSS:4.0, CVSS:3.1 or CVSS:3.0)")
	}
}

// ============================================================================
// SECTION: CLI
// ============================================================================

func usage() {
	banner()
	fmt.Println(`
USAGE:
  OCVSS [flags]

DESCRIPTION:
  Parse and compute CVSS v3.1 and CVSS v4.0 vectors. Supports base, temporal and
  environmental metrics, the full FIRST v4.0 MacroVector algorithm, batch scoring,
  metric explanation, comparison, A+..F grading and multi-format export.

FLAGS:
  --vector STRING     Score a single CVSS vector (CVSS:3.1/... or CVSS:4.0/...)
  --input FILE        Batch score vectors from FILE (one per line; - for stdin)
  --explain           Print a full metric breakdown for --vector
  --compare A,B       Compare two vectors (comma-separated)
  --format FORMAT     Export format: txt|md|json|csv|sarif (default txt)
  --output FILE       Write export to FILE (default stdout)
  --sensitivity VEC   Print per-metric sensitivity (what-if) analysis
  --normalize VEC     Print a vector in canonical metric order
  --validate VEC      Validate a vector; exit 0 if well-formed, 1 otherwise
  --url VEC           Print the FIRST.org calculator link for a vector
  --selftest          Run the engine regression self-test
  --examples          Print the built-in CVE example library
  --guidance | --templates | --dict | --sla | --legend
  --demo              Run a self-contained demo with synthetic vectors
  --no-color          Disable ANSI colours
  --version           Print version and exit
  -h, --help          Show this help

EXAMPLES:
  OCVSS --vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
  OCVSS --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --explain
  OCVSS --input vectors.txt --format sarif --output cvss.sarif
  OCVSS --compare "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"

With no flags OCVSS launches the interactive TUI.`)
}

func main() {
	var (
		fVector    = flag.String("vector", "", "single CVSS vector to score")
		fInput     = flag.String("input", "", "batch input file (one vector per line)")
		fExplain   = flag.Bool("explain", false, "explain --vector metric breakdown")
		fCompare   = flag.String("compare", "", "compare two vectors (A,B)")
		fFormat    = flag.String("format", "", "export format txt|md|json|csv|sarif")
		fOutput    = flag.String("output", "", "output file")
		fDemo      = flag.Bool("demo", false, "run demo")
		fNoColor   = flag.Bool("no-color", false, "disable colour")
		fVersion   = flag.Bool("version", false, "print version")
		fSens      = flag.String("sensitivity", "", "print sensitivity analysis for a vector")
		fExamples  = flag.Bool("examples", false, "print the built-in CVE example library")
		fSelfTest  = flag.Bool("selftest", false, "run the engine regression self-test")
		fGuidance  = flag.Bool("guidance", false, "print analyst scoring guidance")
		fTemplates = flag.Bool("templates", false, "print vulnerability-class templates")
		fDict      = flag.Bool("dict", false, "print the full metric dictionary")
		fSLA       = flag.Bool("sla", false, "print remediation SLA mapping")
		fLegend    = flag.Bool("legend", false, "print the qualitative score legend")
		fURL       = flag.String("url", "", "print the FIRST.org calculator link for a vector")
		fNormalize = flag.String("normalize", "", "print a vector in canonical metric order")
		fValidate  = flag.String("validate", "", "validate a vector and exit 0/1")
		fHelp      = flag.Bool("help", false, "show help")
	)
	flag.BoolVar(fHelp, "h", false, "show help")
	flag.Usage = usage
	flag.Parse()

	if *fNoColor {
		noColor = true
	}
	if *fHelp {
		usage()
		return
	}
	if *fVersion {
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, TAGLINE)
		fmt.Printf("Author: %s   Web: %s\n", AUTHOR, WEBSITE)
		return
	}
	if *fDemo {
		if err := runDemo(*fFormat, *fOutput); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		return
	}
	if *fExamples {
		printCVELibrary()
		return
	}
	if *fGuidance {
		printGuidance()
		return
	}
	if *fTemplates {
		printTemplates()
		return
	}
	if *fDict {
		printDictionary()
		return
	}
	if *fSLA {
		printSLA()
		return
	}
	if *fLegend {
		printScoreLegend()
		return
	}
	if *fSelfTest {
		if printSelfTest() != 0 {
			os.Exit(1)
		}
		return
	}
	if *fSens != "" {
		printSensitivity(*fSens)
		return
	}
	if *fURL != "" {
		u := firstURL(*fURL)
		if u == "" {
			errMsg("unrecognised CVSS version prefix")
			os.Exit(1)
		}
		fmt.Println(u)
		return
	}
	if *fNormalize != "" {
		n, err := normalizeVector(*fNormalize)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		fmt.Println(n)
		return
	}
	if *fValidate != "" {
		if err := validateVector(*fValidate); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		okMsg("valid vector")
		return
	}

	anyCLI := *fVector != "" || *fInput != "" || *fCompare != ""
	_ = fSens
	if !anyCLI {
		interactive()
		return
	}

	rep := newReport("cli")
	if *fCompare != "" {
		parts := strings.SplitN(*fCompare, ",", 2)
		if len(parts) != 2 {
			errMsg("--compare needs two comma-separated vectors")
			os.Exit(1)
		}
		ra := scoreVector(parts[0])
		rb := scoreVector(parts[1])
		fmt.Printf("A: v%s %.1f (%s)\n", ra.Version, ra.Score, ra.Severity)
		fmt.Printf("B: v%s %.1f (%s)\n", rb.Version, rb.Score, rb.Severity)
		if ra.Err == "" && rb.Err == "" {
			fmt.Printf("delta (B-A): %+.1f\n", rb.Score-ra.Score)
		}
		return
	}
	var results []scoreResult
	if *fVector != "" {
		r := scoreVector(*fVector)
		if r.Err != "" {
			errMsg(r.Err)
			os.Exit(1)
		}
		results = append(results, r)
		if *fExplain {
			if r.Version == "4.0" {
				sel, _ := parseV4(*fVector)
				explainVectorV4(sel)
			} else {
				sel, _ := parseV3(*fVector)
				explainVectorV3(sel)
			}
		} else {
			fmt.Printf("CVSS v%s score: %.1f (%s)\n", r.Version, r.Score, r.Severity)
			fmt.Printf("Suggested SLA: %s\n", slaForScore(r.Score))
			fmt.Printf("Interpretation: %s\n", scoreInterpretation(r.Score))
			if r.Macro != "" {
				fmt.Printf("MacroVector: %s  Nomenclature: %s\n", r.Macro, r.Nomencl)
			}
			if u := firstURL(r.Vector); u != "" {
				fmt.Printf("Calculator: %s\n", u)
			}
		}
	}
	if *fInput != "" {
		data, err := readFileOrStdin(*fInput)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		br := batchScore(strings.Split(string(data), "\n"))
		results = append(results, br...)
		if *fFormat == "" && *fOutput == "" {
			batchStats(br)
		}
	}
	for i, r := range results {
		if r.Err == "" {
			rep.add(scoreToFinding(i+1, r))
		}
	}
	rep.finalize()
	if *fFormat != "" || *fOutput != "" {
		if *fFormat == "" {
			*fFormat = "txt"
		}
		s, err := exportReport(rep, *fFormat)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if err := writeOut(*fOutput, s); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
	}
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OCVSS scores vulnerabilities with CVSS v3.1 and CVSS v4.0. It uses the official FIRST formulas, including the full v4.0 MacroVector lookup. It explains every metric, compares two vectors, scores whole files of vectors, shows which metric changes the score most, and exports results as txt / md / json / csv / sarif.",
	"A vector looks like  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  or  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N. The version is detected from the prefix.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Paste vectors exactly as written, with no spaces. Every screen ends with \"Press Enter to continue\" and returns here. [H] opens this help, [0] or q quits.",
	"Not sure what to enter? Use [2] or [3]. They ask one question per metric and build the vector for you.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Score Vector: paste one v3.1 or v4.0 vector. Shows the score, severity, grade and sub-scores."},
	{"2", "Guided v4.0: answers one letter per base metric (for example AV: N=Network, A=Adjacent, L=Local, P=Physical). Blank picks the first choice. Prints the finished vector and its score."},
	{"3", "Guided v3.1: the same step-by-step builder for CVSS v3.1."},
	{"4", "Explain: paste a vector to see each metric, its value and what it means."},
	{"5", "Batch Score: give the path of a text file with one vector per line. Shows a table and statistics for all of them; export it afterwards with [19]."},
	{"6", "Compare: paste vector A and vector B to see the metric differences and the score change."},
	{"7", "Reference v4.0: table of every v4.0 metric and its allowed values."},
	{"8", "Reference v3.1: the same table for v3.1."},
	{"9", "Severity Scale: score ranges for None / Low / Medium / High / Critical."},
	{"10", "Sensitivity: paste a vector; shows how far the score moves when each metric is changed (what-if analysis)."},
	{"11", "CVE Library: real CVEs with their published vectors, useful as examples."},
	{"12", "Guidance: practical advice for choosing metric values."},
	{"13", "Templates: ready-made vectors for common bug classes (SQLi, XSS, RCE ...)."},
	{"14", "Dictionary: full description of every metric and value."},
	{"15", "SLA Mapping: suggested fix deadlines for each severity."},
	{"16", "Nomenclature: what CVSS-B, CVSS-BT, CVSS-BE and CVSS-BTE mean."},
	{"17", "Self-Test: checks the scoring engine against known reference scores."},
	{"18", "Demo: scores a set of sample vectors so you can see every feature."},
	{"19", "Export Report: choose txt, md, json, csv or sarif and an output file (blank = print to screen) to save the last results."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "v3.1 and v4.0 scores are not directly comparable. Always state which version you used."},
	{"*", "Use --validate VEC in scripts: exit code 0 = valid, 1 = invalid."},
	{"*", "--url VEC prints the FIRST.org calculator link so you can double-check a score."},
}

func owlHelpCLI() { usage() }
