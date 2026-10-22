package main

// Subcomandos do binário usados dentro do Job de varredura (security.go). O Job não tem shell nem acesso ao storage:
//
//	scan-helper install <dir>          copia o próprio binário para o emptyDir (as imagens varridas não têm o agente)
//	scan-helper scan <digest> -- <cmd> roda o Trivy na imagem e imprime uma linha com o resultado resumido
//	scan-helper done                   container final do Job
//
// O "scan" sempre sai com 0: um container de init com erro pararia o pod e as imagens seguintes não seriam varridas.
// O erro vai na linha do resultado, que o agente lê pelo log do container.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const scanResultPrefix = "NANOBOT-SCAN-RESULT "

// Limites do resultado: a linha vai pelo log do container (o kubelet guarda alguns MiB por container)
const (
	maxTrivyOutput    = 256 << 20
	maxDescription    = 1000
	maxTitle          = 300
	maxStderrInResult = 2000
)

type scanOutput struct {
	Digest     string     `json:"digest"`
	Exit       int        `json:"exit"`
	Error      string     `json:"error,omitempty"`
	DurationMS int64      `json:"duration_ms"`
	OSFamily   string     `json:"os_family,omitempty"`
	OSName     string     `json:"os_name,omitempty"`
	OSEOSL     bool       `json:"os_eosl,omitempty"` // versão do SO fora de suporte (sem correções novas)
	Vulns      []scanVuln `json:"vulns"`
}

type scanVuln struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Score       *float64 `json:"score,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	URL         string   `json:"url,omitempty"`
	Pkg         string   `json:"pkg"`
	Installed   string   `json:"installed"`
	Fixed       string   `json:"fixed,omitempty"`
	Status      string   `json:"status,omitempty"`
	Target      string   `json:"target"`
	PkgPath     string   `json:"pkg_path,omitempty"`
	Type        string   `json:"type,omitempty"`
	Published   string   `json:"published,omitempty"`
}

// trivyReport tem só os campos usados do JSON do Trivy (--format json).
type trivyReport struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			EOSL   bool   `json:"EOSL"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Status           string `json:"Status"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			PrimaryURL       string `json:"PrimaryURL"`
			PublishedDate    string `json:"PublishedDate"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
				V2Score float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// runScanHelper trata os subcomandos; false: não é um subcomando do helper (o agente segue normalmente).
func runScanHelper(args []string) (bool, int) {
	if len(args) < 2 || args[1] != "scan-helper" {
		return false, 0
	}
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "uso: scan-helper install <dir> | scan <digest> -- <comando> | done")
		return true, 2
	}
	switch args[2] {
	case "install":
		if len(args) != 4 {
			fmt.Fprintln(os.Stderr, "uso: scan-helper install <dir>")
			return true, 2
		}
		if err := installHelper(args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "scan-helper install:", err)
			return true, 1
		}
		return true, 0
	case "scan":
		if len(args) < 6 || args[4] != "--" {
			fmt.Fprintln(os.Stderr, "uso: scan-helper scan <digest> -- <comando>")
			return true, 2
		}
		out := runScan(args[3], args[5:])
		line, err := encodeScanResult(out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan-helper scan:", err)
			return true, 0
		}
		fmt.Println(line)
		return true, 0
	case "done":
		fmt.Println("scan job done")
		return true, 0
	}
	fmt.Fprintln(os.Stderr, "scan-helper: subcomando desconhecido", args[2])
	return true, 2
}

func installHelper(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	for _, d := range []string{"tmp", "home", "cache"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o777); err != nil {
			return err
		}
		os.Chmod(filepath.Join(dir, d), 0o1777)
	}
	// Vazio: o Trivy recebe --ignorefile apontando para ele (um .trivyignore da imagem varrida não vale)
	if err := os.WriteFile(filepath.Join(dir, ".trivyignore"), nil, 0o644); err != nil {
		return err
	}
	return copyExecutable(self, filepath.Join(dir, "scan-helper"))
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// limitedBuffer guarda até max bytes e descarta o resto (o Trivy não deveria passar disso com --list-all-pkgs=false).
type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room < len(p) {
		l.truncated = true
		if room > 0 {
			l.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return l.buf.Write(p)
}

func runScan(digest string, cmdline []string) scanOutput {
	out := scanOutput{Digest: digest, Vulns: []scanVuln{}}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		os.MkdirAll(tmp, 0o1777)
	}
	start := time.Now()
	stdout := &limitedBuffer{max: maxTrivyOutput}
	stderr := &limitedBuffer{max: 64 << 10}
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Ambiente limpo e diretório vazio: o container é a imagem varrida, e as variáveis dela (TRIVY_*, um .trivyignore
	// no WORKDIR) poderiam mudar o resultado
	cmd.Env = scanEnv()
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		cmd.Dir = tmp
	}
	err := cmd.Run()
	out.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			out.Exit = exit.ExitCode()
		} else {
			out.Exit = -1
		}
		out.Error = lastLines(strings.TrimSpace(stderr.buf.String()+"\n"+err.Error()), maxStderrInResult)
		return out
	}
	if stdout.truncated {
		out.Exit, out.Error = -1, fmt.Sprintf("trivy output larger than %d MiB", maxTrivyOutput>>20)
		return out
	}
	if err := parseTrivy(stdout.buf.Bytes(), &out); err != nil {
		out.Exit, out.Error = -1, "invalid trivy output: "+err.Error()
	}
	return out
}

// scanEnv: só o que o Trivy precisa (diretórios do emptyDir, certificados copiados da imagem do Trivy e proxy).
func scanEnv() []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	for _, k := range []string{"TMPDIR", "HOME", "SSL_CERT_FILE", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
		"https_proxy", "http_proxy", "no_proxy"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func parseTrivy(raw []byte, out *scanOutput) error {
	var r trivyReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.Metadata.OS != nil {
		out.OSFamily, out.OSName, out.OSEOSL = r.Metadata.OS.Family, r.Metadata.OS.Name, r.Metadata.OS.EOSL
	}
	for _, res := range r.Results {
		// Pacotes do SO: o Trivy usa o hostname (o pod do Job) como nome do alvo do rootfs
		if res.Class == "os-pkgs" && out.OSFamily != "" {
			res.Target = strings.TrimSpace(out.OSFamily+" "+out.OSName) + " (OS packages)"
		}
		for _, v := range res.Vulnerabilities {
			sv := scanVuln{ID: v.VulnerabilityID, Severity: v.Severity, Title: truncateRunes(v.Title, maxTitle),
				Description: truncateRunes(v.Description, maxDescription), URL: v.PrimaryURL, Pkg: v.PkgName,
				Installed: v.InstalledVersion, Fixed: v.FixedVersion, Status: v.Status, Target: res.Target,
				PkgPath: v.PkgPath, Type: res.Type, Published: v.PublishedDate}
			best := 0.0
			for _, c := range v.CVSS {
				best = max(best, c.V3Score)
			}
			if best == 0 {
				for _, c := range v.CVSS {
					best = max(best, c.V2Score)
				}
			}
			if best > 0 {
				sv.Score = &best
			}
			out.Vulns = append(out.Vulns, sv)
		}
	}
	return nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func lastLines(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// encodeScanResult: JSON comprimido em base64 numa linha só (o log do container é texto).
func encodeScanResult(out scanOutput) (string, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if err := json.NewEncoder(zw).Encode(out); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return scanResultPrefix + base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// decodeScanResult acha a linha do resultado no log do container.
func decodeScanResult(log []byte) (*scanOutput, error) {
	for _, line := range bytes.Split(log, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte(scanResultPrefix)) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(string(line[len(scanResultPrefix):]))
		if err != nil {
			return nil, err
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		var out scanOutput
		if err := json.NewDecoder(io.LimitReader(zr, maxTrivyOutput)).Decode(&out); err != nil {
			return nil, err
		}
		return &out, nil
	}
	return nil, errors.New("no scan result in the container log")
}
