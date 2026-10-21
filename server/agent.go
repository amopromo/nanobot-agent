package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/kardianos/service"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/crypto/ssh"
)

// --- CUSTOM TYPE FOR MULTIPLE FLAGS ---

type stringSlice []string

func (i *stringSlice) String() string {
	return fmt.Sprint(*i)
}

func (i *stringSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// --- STRUCTS ---

type ContainerStat struct {
	Name   string  `json:"name"`
	Image  string  `json:"image"`
	CPU    float64 `json:"cpu_percent"`
	Memory uint64  `json:"memory_bytes"`
	NetRx  uint64  `json:"net_rx_bytes"`
	NetTx  uint64  `json:"net_tx_bytes"`
}

type Metrics struct {
	ID           string          `json:"id"`
	Timestamp    int64           `json:"ts"`
	Uptime       uint64          `json:"uptime"`
	Hostname     string          `json:"hostname"`
	OS           OSInfo          `json:"os"`
	CPU          CPUInfo         `json:"cpu_info"`
	Load         LoadStats       `json:"load"`
	Memory       MemoryStats     `json:"memory"`
	Swap         SwapStats       `json:"swap"`
	Disks        []DiskStats     `json:"disks"`
	Network      NetworkStats    `json:"network"`
	TopProcesses []ProcessInfo   `json:"top_processes"`
	Containers   []ContainerStat `json:"containers"`

	SSHKey  string `json:"ssh_key"`
	SSHPort int    `json:"ssh_port"`
}

type OSInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	KernelArch    string `json:"kernel_arch"`
	KernelVersion string `json:"kernel_version"`
}

type CPUInfo struct {
	Usage       float64 `json:"usage_percent"`
	NumCPUs     int     `json:"num_cpus"`
	ModelName   string  `json:"model_name"`
	MHz         float64 `json:"mhz"`
}

type LoadStats struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type MemoryStats struct {
	UsedPercent float64 `json:"used_percent"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	Available   uint64  `json:"available"`
	Buffers     uint64  `json:"buffers"`
	Cached      uint64  `json:"cached"`
}

type SwapStats struct {
	UsedPercent float64 `json:"used_percent"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	Sin         uint64  `json:"sin_bytes"`
	Sout        uint64  `json:"sout_bytes"`
}

type DiskStats struct {
	MountPoint  string  `json:"mount"`
	Device      string  `json:"device"`
	FSType      string  `json:"fs_type"`
	UsedPercent float64 `json:"used_percent"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	IORead      uint64  `json:"io_read_bytes"`
	IOWrite     uint64  `json:"io_write_bytes"`
}

type NetworkStats struct {
	Upload   uint64 `json:"upload_bytes"`
	Download uint64 `json:"download_bytes"`
}

type ProcessInfo struct {
	PID          int32   `json:"pid"`
	Name         string  `json:"name"`
	CPU          float64 `json:"cpu_percent"`
	Memory       float32 `json:"memory_percent"`
	IOReadBytes  uint64  `json:"io_read_bytes"`
	IOWriteBytes uint64  `json:"io_write_bytes"`
}

type RegistrationPayload struct {
	Variables struct {
		Server          string   `json:"SERVER"`
		OS              string   `json:"OS"`
		IP              string   `json:"IP"`
		Port            string   `json:"PORT"`
		Frequency       int      `json:"FREQUENCY_MINUTES,omitempty"`
		FailScripts     string   `json:"FAIL_SCRIPTS,omitempty"`
		RecoveryScripts string   `json:"RECOVERY_SCRIPTS,omitempty"`
		CustomVars      []string `json:"CUSTOM_VARS,omitempty"`
		AgentApiKey     string   `json:"AGENT_API_KEY,omitempty"`
	} `json:"variables"`
}

type RegistrationResponse struct {
	ID int `json:"id"`
}

// --- GLOBAL VARIABLES ---

var (
	cachedMetrics        Metrics
	cacheMutex           sync.RWMutex
	staticOSInfo         OSInfo
	staticHost           string
	staticCPU            string
	staticCPUMHz         float64
	collectionInterval   int
	expectedApiKey       string
	registrationKey      string
	agentID              string
	serverPort           int
	sshPort              int
	agentPublicIP        string
	agentFrequency       int
	agentFailScripts     string
	agentRecoveryScripts string
	disableSSH           bool
	agentVars            stringSlice

	dynamicSSHPrivPEM string
	dynamicSSHPublic  ssh.PublicKey
	previousSSHPublic ssh.PublicKey
	dynamicSSHExpiry  time.Time
	credMutex         sync.Mutex

	setupUserOnce sync.Once

	// Controle de Limite de Sessões SSH simultâneas (MAX: 5)
	sshSessionSem = make(chan struct{}, 5)

	sshBlockMap = make(map[string]*sshBlockInfo)
	sshBlockMut sync.Mutex
)

type sshBlockInfo struct {
	Attempts   int
	BlockUntil time.Time
}

// --- SSH E BLOQUEIO DE ACESSO ---

func checkIPBlocked(ip string) bool {
	sshBlockMut.Lock()
	defer sshBlockMut.Unlock()
	info, exists := sshBlockMap[ip]
	if !exists {
		return false
	}
	if time.Now().Before(info.BlockUntil) {
		return true
	}
	info.Attempts = 0
	return false
}

func recordFailedAttempt(ip string) {
	sshBlockMut.Lock()
	defer sshBlockMut.Unlock()

	info, exists := sshBlockMap[ip]
	if !exists {
		info = &sshBlockInfo{Attempts: 0}
		sshBlockMap[ip] = info
	}

	info.Attempts++

	switch info.Attempts {
		case 1:
			info.BlockUntil = time.Now().Add(10 * time.Minute)
		case 2:
			info.BlockUntil = time.Now().Add(2 * time.Hour)
		default:
			info.BlockUntil = time.Now().Add(24 * time.Hour)
	}
}

func rotateCredentials() {
	credMutex.Lock()
	defer credMutex.Unlock()

	setupUserOnce.Do(func() {
		exec.Command("useradd", "-M", "-s", "/bin/bash", "nanobot").Run()
		sudoersRule := "nanobot ALL=(ALL) NOPASSWD:ALL\n"
		os.WriteFile("/etc/sudoers.d/nanobot", []byte(sudoersRule), 0440)
	})

	now := time.Now()
	if now.After(dynamicSSHExpiry) {
		previousSSHPublic = dynamicSSHPublic

		// Geração de chave RSA para garantir 100% de compatibilidade com clientes SSH Linux
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			privBytes := x509.MarshalPKCS1PrivateKey(priv)
			dynamicSSHPrivPEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privBytes,
			}))

			signer, _ := ssh.NewSignerFromKey(priv)
			dynamicSSHPublic = signer.PublicKey()
			dynamicSSHExpiry = now.Add(1 * time.Hour)
		}
	}
}

func startSSHServer() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			ip := strings.Split(c.RemoteAddr().String(), ":")[0]

			if checkIPBlocked(ip) {
				return nil, fmt.Errorf("incorrect key")
			}

			credMutex.Lock()
			isValid := false
			if dynamicSSHPublic != nil && bytes.Equal(pubKey.Marshal(), dynamicSSHPublic.Marshal()) {
				isValid = true
			} else if previousSSHPublic != nil && bytes.Equal(pubKey.Marshal(), previousSSHPublic.Marshal()) {
				isValid = true
			}
			credMutex.Unlock()

			if !isValid {
				recordFailedAttempt(ip)
				return nil, fmt.Errorf("incorrect key")
			}

			sshBlockMut.Lock()
			delete(sshBlockMap, ip)
			sshBlockMut.Unlock()

			return nil, nil
		},
	}

	privateBytes, err := os.ReadFile("key.pem")
		if err == nil {
			private, errParse := ssh.ParsePrivateKey(privateBytes)
				if errParse == nil {
					config.AddHostKey(private)
				} else {
					log.Printf("⚠️ Erro ao fazer parse da chave ssh: %v", errParse)
				}
		} else {
			log.Printf("⚠️ Erro lendo key.pem: %v", err)
		}

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", sshPort))
		if err != nil {
			log.Fatalf("❌ Falha ao iniciar listener SSH: %v", err)
		}
		log.Printf("🛡️  Servidor SSH Seguro iniciado na porta %d\n", sshPort)

		for {
			nConn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn) {
				select {
					case sshSessionSem <- struct{}{}:
						defer func() { <-sshSessionSem }()
					default:
						log.Println("⚠️ Conexão rejeitada: limite de 5 sessões SSH simultâneas atingido.")
						conn.Close()
						return
				}

				// OTIMIZAÇÃO 1: SetDeadline previne que um bot prenda o semáforo eternamente sem concluir handshake
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				conn.SetDeadline(time.Time{}) // Handshake bem-sucedido, libera timeout da conexão

				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}

					go func(in <-chan *ssh.Request) {
						var execCmd string
						var ptmx *os.File
						var cols, rows uint16 = 80, 24

						for req := range in {
							switch req.Type {

								case "pty-req":
									req.Reply(true, nil)
									var ptyReq struct {
										Term     string
										Columns  uint32
										Rows     uint32
										Width    uint32
										Height   uint32
										ModeList []byte
									}
									if err := ssh.Unmarshal(req.Payload, &ptyReq); err == nil {
										cols, rows = uint16(ptyReq.Columns), uint16(ptyReq.Rows)
										if ptmx != nil {
											pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})
										}
									}

								case "window-change":
									req.Reply(true, nil)
									var win struct {
										Columns uint32
										Rows    uint32
										Width   uint32
										Height  uint32
									}
									if err := ssh.Unmarshal(req.Payload, &win); err == nil {
										cols, rows = uint16(win.Columns), uint16(win.Rows)
										if ptmx != nil {
											pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})
										}
									}

								case "shell":
									req.Reply(true, nil)

									cmd := exec.Command("su", "nanobot")
									cmd.Dir = "/"
									cmd.Env = append(os.Environ(), "HOME=/", "TERM=xterm-256color")

									var errPty error
									ptmx, errPty = pty.Start(cmd)
									if errPty != nil {
										channel.Close()
										return
									}

									pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})

									// OTIMIZAÇÃO 2: WaitGroup assegura I/O e evita truncamento/vazamentos
									var wg sync.WaitGroup
									wg.Add(1)

									go func() {
										io.Copy(ptmx, channel) // STDIN
									}()
									go func() {
										defer wg.Done()
										io.Copy(channel, ptmx) // STDOUT
									}()

									go func() {
										cmd.Wait()
										ptmx.Close()    // Libera o copy pendente do STDOUT
										wg.Wait()       // Garante que todo dado residual foi enviado pro cliente
										channel.Close()
									}()

								case "exec":
									req.Reply(true, nil)

									var payload struct {
										Command string
									}
									ssh.Unmarshal(req.Payload, &payload)
									execCmd = payload.Command

									cmd := exec.Command("su", "nanobot", "-c", execCmd)
									cmd.Dir = "/"
									cmd.Env = append(os.Environ(), "HOME=/", "TERM=xterm-256color")

									var errPty error
									ptmx, errPty = pty.Start(cmd)
									if errPty != nil {
										channel.Close()
										return
									}

									pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})

									// OTIMIZAÇÃO 2 (Exec): WaitGroup
									var wg sync.WaitGroup
									wg.Add(1)

									go func() {
										io.Copy(ptmx, channel)
									}()
									go func() {
										defer wg.Done()
										io.Copy(channel, ptmx)
									}()

									go func() {
										cmd.Wait()
										ptmx.Close()
										wg.Wait()
										channel.Close()
									}()
							}
						}
					}(requests)
				}
			}(nConn)
		}
}

// --- SERVICE MANAGEMENT STRUCTURE (kardianos/service) ---

type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	if !disableSSH {
		go startSSHServer()
	} else {
		log.Println("🛑 Internal SSH Server is DISABLED.")
	}

	addr := fmt.Sprintf(":%d", serverPort)
	log.Printf("🚀 Monitoring agent started (ID: %s)\n", agentID)
	log.Printf("📡 Serving secure metrics on https://0.0.0.0%s/metrics\n", addr)

	if err := http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil); err != nil {
		log.Fatalf("❌ Error starting HTTPS server: %v\n", err)
	}
}

func (p *program) Stop(s service.Service) error {
	log.Println("🛑 Agent service stopping...")
	return nil
}

// --- HELPER FUNCTIONS ---

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getOSInfo() OSInfo {
	hostInfo, err := host.Info()
	if err != nil {
		return OSInfo{
			Name:          runtime.GOOS,
			Version:       "unknown",
			Arch:          runtime.GOARCH,
			KernelVersion: "unknown",
		}
	}
	return OSInfo{
		Name:          hostInfo.Platform,
		Version:       hostInfo.PlatformVersion,
		Arch:          hostInfo.KernelArch,
		KernelArch:    hostInfo.KernelArch,
		KernelVersion: hostInfo.KernelVersion,
	}
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func initStaticData(customName string) {
	if customName != "" {
		staticHost = customName
	} else {
		staticHost = getHostname()
	}
	staticOSInfo = getOSInfo()

	cpuInfos, err := cpu.Info()
	if err == nil && len(cpuInfos) > 0 {
		staticCPU = cpuInfos[0].ModelName
		staticCPUMHz = cpuInfos[0].Mhz
	}
}

func getSwapInfo() SwapStats {
	swapInfo, err := mem.SwapMemory()
	if err != nil {
		return SwapStats{}
	}
	return SwapStats{
		UsedPercent: swapInfo.UsedPercent,
		Total:       swapInfo.Total,
		Used:        swapInfo.Used,
		Free:        swapInfo.Free,
		Sin:         swapInfo.Sin,
		Sout:        swapInfo.Sout,
	}
}

func parseDockerBytes(s string) uint64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "-" {
		return 0
	}

	multiplier := float64(1)
	if strings.HasSuffix(s, "B") {
		s = strings.TrimSuffix(s, "B")
	}
	if strings.HasSuffix(s, "I") {
		s = strings.TrimSuffix(s, "I")
	}

	if strings.HasSuffix(s, "K") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	} else if strings.HasSuffix(s, "M") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	} else if strings.HasSuffix(s, "G") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	} else if strings.HasSuffix(s, "T") {
		multiplier = 1024 * 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "T")
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return uint64(val * multiplier)
}

func getContainerStats() []ContainerStat {
	var stats []ContainerStat

	imageMap := make(map[string]string)
	psOut, err := exec.Command("docker", "ps", "--format", "{{.Names}}|{{.Image}}").Output()
	if err == nil {
		lines := strings.Split(string(psOut), "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 {
				imageMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}").Output()
	if err != nil {
		return stats
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			name := parts[0]

			cpuStr := strings.TrimSpace(strings.ReplaceAll(parts[1], "%", ""))
			cpuVal, _ := strconv.ParseFloat(cpuStr, 64)

			memParts := strings.Split(parts[2], "/")
			var memVal uint64
			if len(memParts) > 0 {
				memVal = parseDockerBytes(memParts[0])
			}

			netParts := strings.Split(parts[3], "/")
			var rxVal, txVal uint64
			if len(netParts) >= 2 {
				rxVal = parseDockerBytes(netParts[0])
				txVal = parseDockerBytes(netParts[1])
			}

			img := imageMap[name]
			if img == "" {
				img = "unknown"
			}

			stats = append(stats, ContainerStat{
				Name:   name,
				Image:  img,
				CPU:    cpuVal,
				Memory: memVal,
				NetRx:  rxVal,
				NetTx:  txVal,
			})
		}
	}
	return stats
}

func generateCerts() error {
	log.Println("🔑 Generating TLS certificates (cert.pem and key.pem)...")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Agent Monitor"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create("cert.pem")
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return nil
}

func registerAgent(serverURL, regKey, metricsApiKey string, port int) (string, error) {
	payload := RegistrationPayload{}
	payload.Variables.Server = staticHost
	payload.Variables.OS = fmt.Sprintf("%s %s (%s)", staticOSInfo.Name, staticOSInfo.Version, staticOSInfo.Arch)

	if agentPublicIP != "" {
		payload.Variables.IP = agentPublicIP
	} else {
		payload.Variables.IP = getOutboundIP()
	}

	payload.Variables.Port = strconv.Itoa(port)
	payload.Variables.Frequency = agentFrequency
	payload.Variables.FailScripts = agentFailScripts
	payload.Variables.RecoveryScripts = agentRecoveryScripts
	payload.Variables.CustomVars = agentVars
	payload.Variables.AgentApiKey = metricsApiKey // Envia a chave única da máquina para o servidor Flask

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	// Usa a chave de registro (ex: a do admin que copiou o comando) para ter permissão de acessar a rota API
	req.Header.Set("Authorization", "Bearer "+regKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("the server returned HTTP status %d", resp.StatusCode)
	}

	var regResponse RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResponse); err != nil {
		return "", fmt.Errorf("error decoding ID from response: %v", err)
	}

	if regResponse.ID == 0 {
		return "", fmt.Errorf("server response did not contain a valid ID")
	}

	return strconv.Itoa(regResponse.ID), nil
}

func copyFile(src, dst string) error {
	return copyFileMode(src, dst, 0644)
}

// copyFileMode cria o destino já com a permissão informada (ex.: 0600 para a chave privada do TLS)
func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Sync()
}

// --- API KEY FILE ---

const apiKeyFileName = "apikey"

var apiKeyArgRegexp = regexp.MustCompile(`\s*-apikey=("[^"]*"|\S+)`)

// writeApiKeyFile grava a chave com acesso só do root/SYSTEM, para ela não ficar na linha de comando do serviço
func writeApiKeyFile(dir, apiKey string) error {
	path := filepath.Join(dir, apiKeyFileName)
	if err := os.WriteFile(path, []byte(apiKey), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %v", path, err)
	}
	os.Chmod(path, 0600)
	if runtime.GOOS == "windows" {
		// No Windows a permissão Unix é ignorada: remove a herança e libera só SYSTEM e Administradores
		out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F").CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to restrict %s: %v, output: %s", path, err, string(out))
		}
	}
	return nil
}

// extractApiKeyArg remove o -apikey=... de uma linha de comando, devolvendo a chave e a linha sem ela
func extractApiKeyArg(cmdline string) (string, string) {
	m := apiKeyArgRegexp.FindStringSubmatch(cmdline)
	if m == nil {
		return "", cmdline
	}
	return strings.Trim(m[1], `"`), apiKeyArgRegexp.ReplaceAllString(cmdline, "")
}

func migrateSystemdApiKey() error {
	servicePath := "/etc/systemd/system/nanobot-agent.service"
	data, err := os.ReadFile(servicePath)
	if err != nil {
		return err
	}
	apiKey, content := extractApiKeyArg(string(data))
	if apiKey == "" {
		return nil
	}
	log.Println("🔒 Moving the API key from the service file to /opt/nanobot-agent/apikey...")
	if err := writeApiKeyFile("/opt/nanobot-agent", apiKey); err != nil {
		return err
	}
	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return err
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}

func migrateWindowsApiKey() error {
	out, err := exec.Command("sc", "qc", "nanobot-agent").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc qc failed: %v", err)
	}
	var binPath string
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "BINARY_PATH_NAME"); idx >= 0 {
			if colon := strings.Index(line[idx:], ":"); colon >= 0 {
				binPath = strings.TrimSpace(line[idx+colon+1:])
			}
		}
	}
	apiKey, newBinPath := extractApiKeyArg(binPath)
	if apiKey == "" {
		return nil
	}
	log.Println("🔒 Moving the API key from the service command line to a protected file...")
	if err := writeApiKeyFile(`C:\ProgramData\nanobot-agent`, apiKey); err != nil {
		return err
	}
	if out, err := exec.Command("sc", "config", "nanobot-agent", "binPath=", newBinPath).CombinedOutput(); err != nil {
		return fmt.Errorf("sc config failed: %v, output: %s", err, string(out))
	}
	return nil
}

// --- UPDATE FUNCTION (-update) ---

func updateAgent() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %v", err)
	}

	if runtime.GOOS == "windows" {
		log.Println("🛑 Stopping Windows service...")
		exec.Command("sc", "stop", "nanobot-agent").Run()

		target := `C:\ProgramData\nanobot-agent\nanobot-agent.exe`
		log.Printf("📦 Copying new binary to %s...\n", target)

		var copyErr error
		for i := 0; i < 5; i++ {
			time.Sleep(2 * time.Second)
			os.Remove(target)
			copyErr = copyFile(execPath, target)
			if copyErr == nil {
				break
			}
		}
		if copyErr != nil {
			return fmt.Errorf("failed to overwrite binary: %v", copyErr)
		}

		if err := migrateWindowsApiKey(); err != nil {
			log.Printf("⚠️ Could not move the API key out of the service command line: %v\n", err)
		}

		log.Println("🔄 Starting Windows service...")
		exec.Command("sc", "start", "nanobot-agent").Run()

	} else {
		log.Println("🛑 Stopping systemd service...")
		exec.Command("systemctl", "stop", "nanobot-agent").Run()

		target := "/opt/nanobot-agent/nanobot-agent"
		log.Printf("📦 Copying new binary to %s...\n", target)
		os.Remove(target)
		if err := copyFile(execPath, target); err != nil {
			return err
		}
		os.Chmod(target, 0755)
		// Instalações antigas: a chave privada do TLS foi gravada legível por todos
		os.Chmod("/opt/nanobot-agent/key.pem", 0600)

		if err := migrateSystemdApiKey(); err != nil {
			log.Printf("⚠️ Could not move the API key out of the service file: %v\n", err)
		}

		log.Println("🔄 Starting systemd service...")
		exec.Command("systemctl", "start", "nanobot-agent").Run()
	}
	return nil
}

// --- INSTALLATION FUNCTIONS (WINDOWS / LINUX) ---

func setupWindowsService(id, apiKey, sName string, port, sshPort, interval int) error {
	dir := `C:\ProgramData\nanobot-agent`
	log.Printf("📂 Creating installation directory at %s...\n", dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %v", err)
	}

	targetExec := filepath.Join(dir, "nanobot-agent.exe")
	log.Println("📦 Copying agent binary...")
	if err := copyFile(execPath, targetExec); err != nil {
		return fmt.Errorf("failed to copy executable: %v", err)
	}

	log.Println("🔒 Moving TLS certificates...")
	if err := copyFile("cert.pem", filepath.Join(dir, "cert.pem")); err != nil {
		return fmt.Errorf("failed to copy cert.pem: %v", err)
	}
	if err := copyFileMode("key.pem", filepath.Join(dir, "key.pem"), 0600); err != nil {
		return fmt.Errorf("failed to copy key.pem: %v", err)
	}
	os.Remove("cert.pem")
	os.Remove("key.pem")

	if err := writeApiKeyFile(dir, apiKey); err != nil {
		return err
	}

	log.Println("⚙️ Registering service in Windows SCM...")
	binPath := fmt.Sprintf(`"%s" -start -id=%s -port=%d -ssh-port=%d -interval=%d`, targetExec, id, port, sshPort, interval)
	if sName != "" {
		binPath += fmt.Sprintf(` -server-name="%s"`, sName)
	}
	if disableSSH {
		binPath += " -disable-ssh"
	}

	cmdCreate := exec.Command("sc", "create", "nanobot-agent",
				  "binPath=", binPath,
			   "start=", "auto",
			   "DisplayName=", "Nanobot Monitoring Agent")

	if output, err := cmdCreate.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create service: %v, output: %s", err, string(output))
	}

	log.Println("🔄 Starting the service (sc start)...")
	cmdStart := exec.Command("sc", "start", "nanobot-agent")
	if output, err := cmdStart.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start the service: %v, output: %s", err, string(output))
	}

	return nil
}

func setupSystemd(id, apiKey, sName string, port, sshPort, interval int) error {
	dir := "/opt/nanobot-agent"
	log.Printf("📂 Creating installation directory at %s...\n", dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %v", err)
	}

	targetExec := filepath.Join(dir, "nanobot-agent")
	log.Println("📦 Copying agent binary...")
	if err := copyFile(execPath, targetExec); err != nil {
		return fmt.Errorf("failed to copy executable: %v", err)
	}
	os.Chmod(targetExec, 0755)

	log.Println("🔒 Moving TLS certificates...")
	if err := copyFile("cert.pem", filepath.Join(dir, "cert.pem")); err != nil {
		return fmt.Errorf("failed to copy cert.pem: %v", err)
	}
	if err := copyFileMode("key.pem", filepath.Join(dir, "key.pem"), 0600); err != nil {
		return fmt.Errorf("failed to copy key.pem: %v", err)
	}

	os.Remove("cert.pem")
	os.Remove("key.pem")

	if err := writeApiKeyFile(dir, apiKey); err != nil {
		return err
	}

	servicePath := "/etc/systemd/system/nanobot-agent.service"
	log.Printf("⚙️ Creating service file at %s...\n", servicePath)

	execStartCmd := fmt.Sprintf("%s -start -id=%s -port=%d -ssh-port=%d -interval=%d", targetExec, id, port, sshPort, interval)
	if sName != "" {
		execStartCmd += fmt.Sprintf(" -server-name=%s", sName)
	}
	if disableSSH {
		execStartCmd += " -disable-ssh"
	}

	serviceContent := fmt.Sprintf(`[Unit]
	Description=Nanobot Monitoring Agent
	After=network.target

	[Service]
	Type=simple
	WorkingDirectory=%s
	ExecStart=%s
	Restart=always
	RestartSec=5

	[Install]
	WantedBy=multi-user.target
	`, dir, execStartCmd)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd file: %v", err)
	}

	log.Println("🔄 Reloading systemd and starting the service...")
	commands := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "nanobot-agent"},
		{"systemctl", "start", "nanobot-agent"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run %v: %v", cmdArgs, err)
		}
	}

	return nil
}

// --- COLLECTION FUNCTION ---

func collect() Metrics {
	if !disableSSH {
		rotateCredentials()
	}

	uptime, _ := host.Uptime()

	metrics := Metrics{
		ID:        agentID,
		Timestamp: time.Now().Unix(),
		Uptime:    uptime,
		Hostname:  staticHost,
		OS:        staticOSInfo,
		Swap:      getSwapInfo(),
	}

	if !disableSSH {
		metrics.SSHKey = dynamicSSHPrivPEM
		metrics.SSHPort = sshPort
	} else {
		metrics.SSHKey = ""
		metrics.SSHPort = 0
	}

	metrics.Containers = getContainerStats()

	cpuInfo := CPUInfo{
		NumCPUs:   runtime.NumCPU(),
		ModelName: staticCPU,
		MHz:       staticCPUMHz,
	}
	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		cpuInfo.Usage = cpuPercent[0]
	}
	metrics.CPU = cpuInfo

	if loadAvg, err := load.Avg(); err == nil {
		metrics.Load = LoadStats{
			Load1:  loadAvg.Load1,
			Load5:  loadAvg.Load5,
			Load15: loadAvg.Load15,
		}
	}

	memInfo, err := mem.VirtualMemory()
	if err == nil {
		metrics.Memory = MemoryStats{
			UsedPercent: memInfo.UsedPercent,
			Total:       memInfo.Total,
			Used:        memInfo.Used,
			Free:        memInfo.Free,
			Available:   memInfo.Available,
			Buffers:     memInfo.Buffers,
			Cached:      memInfo.Cached,
		}
	}

	ioCountersMap, _ := disk.IOCounters()

	partitions, _ := disk.Partitions(false)
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}

		var ioRead, ioWrite uint64
		if ioCountersMap != nil {
			devBaseName := filepath.Base(p.Device)
			if io, ok := ioCountersMap[devBaseName]; ok {
				ioRead = io.ReadBytes
				ioWrite = io.WriteBytes
			} else if io, ok := ioCountersMap[p.Device]; ok {
				ioRead = io.ReadBytes
				ioWrite = io.WriteBytes
			}
		}

		metrics.Disks = append(metrics.Disks, DiskStats{
			MountPoint:  p.Mountpoint,
			Device:      p.Device,
			FSType:      p.Fstype,
			UsedPercent: usage.UsedPercent,
			Total:       usage.Total,
			Used:        usage.Used,
			Free:        usage.Free,
			IORead:      ioRead,
			IOWrite:     ioWrite,
		})
	}

	netIO, err := psnet.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		metrics.Network = NetworkStats{
			Upload:   netIO[0].BytesSent,
			Download: netIO[0].BytesRecv,
		}
	}

	procs, _ := process.Processes()
	type procTemp struct {
		p   *process.Process
		cpu float64
	}
	var tempProcs []procTemp
	for _, p := range procs {
		cpuPerc, _ := p.CPUPercent()
		if cpuPerc > 0.1 {
			tempProcs = append(tempProcs, procTemp{p: p, cpu: cpuPerc})
		}
	}

	sort.Slice(tempProcs, func(i, j int) bool {
		return tempProcs[i].cpu > tempProcs[j].cpu
	})

	limit := 5
	if len(tempProcs) < limit {
		limit = len(tempProcs)
	}

	for i := 0; i < limit; i++ {
		p := tempProcs[i].p
		name, _ := p.Name()
		memPerc, _ := p.MemoryPercent()

		var ioRead, ioWrite uint64
		ioCounters, err := p.IOCounters()
		if err == nil && ioCounters != nil {
			ioRead = ioCounters.ReadBytes
			ioWrite = ioCounters.WriteBytes
		}

		metrics.TopProcesses = append(metrics.TopProcesses, ProcessInfo{
			PID:          p.Pid,
			Name:         name,
			CPU:          tempProcs[i].cpu,
			Memory:       memPerc,
			IOReadBytes:  ioRead,
			IOWriteBytes: ioWrite,
		})
	}

	return metrics
}

func backgroundCollector() {
	type diskIO struct{ read, write uint64 }
	lastDiskIO := make(map[string]diskIO)
	var lastTime time.Time

	for {
		now := time.Now()
		m := collect()

		deltaSeconds := now.Sub(lastTime).Seconds()
		isFirstRun := lastTime.IsZero()

		for i, d := range m.Disks {
			rawRead := d.IORead
			rawWrite := d.IOWrite

			if !isFirstRun && deltaSeconds > 0 {
				if last, ok := lastDiskIO[d.Device]; ok {
					m.Disks[i].IORead = uint64(float64(rawRead-last.read) / deltaSeconds)
					m.Disks[i].IOWrite = uint64(float64(rawWrite-last.write) / deltaSeconds)
				} else {
					m.Disks[i].IORead = 0
					m.Disks[i].IOWrite = 0
				}
			} else {
				m.Disks[i].IORead = 0
				m.Disks[i].IOWrite = 0
			}

			lastDiskIO[d.Device] = diskIO{read: rawRead, write: rawWrite}
		}

		lastTime = now

		cacheMutex.Lock()
		cachedMetrics = m
		cacheMutex.Unlock()

		time.Sleep(time.Duration(collectionInterval) * time.Second)
		debug.FreeOSMemory()
	}
}

// --- MIDDLEWARES AND HANDLERS ---

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("📥 [%s] %s %s - Origin: %s", r.Method, r.Host, r.URL.Path, r.RemoteAddr)
		next(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte("Bearer "+expectedApiKey)) != 1 {
			log.Printf("❌ Access Denied: Invalid Token. IP: %s", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"Access denied. Invalid Token."}`)
			return
		}
		next(w, r)
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	cacheMutex.RLock()
	metrics := cachedMetrics
	cacheMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.URL.Query().Has("pretty") {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.Encode(metrics)
	} else {
		json.NewEncoder(w).Encode(metrics)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","hostname":"%s","timestamp":%d}`, hostname, time.Now().Unix())
}

// --- MAIN ---

func main() {
	var (
		modeInstall bool
		modeStart   bool
		modeUpdate  bool
		serverURL   string
		serverName  string
	)

	flag.BoolVar(&modeInstall, "install", false, "Run in automated installation and registration mode")
	flag.BoolVar(&modeStart, "start", false, "Start the agent in production mode (HTTPS)")
	flag.BoolVar(&modeUpdate, "update", false, "Update the existing agent binary without changing configuration")
	flag.BoolVar(&disableSSH, "disable-ssh", false, "Disable the internal SSH server")
	flag.StringVar(&serverURL, "server", "", "API URL to register the agent (used with -install)")
	flag.StringVar(&serverName, "server-name", "", "Custom name to identify this server (optional)")
	flag.StringVar(&registrationKey, "reg-key", "", "API Key for server registration (if different from apikey)")
	flag.StringVar(&expectedApiKey, "apikey", "", "API Key for authorization (required by -install; -start reads it from the 'apikey' file)")
	flag.StringVar(&agentID, "id", "", "Machine identifier ID (used in -start)")
	flag.IntVar(&serverPort, "port", 9101, "Local port for the HTTPS metrics server")
	flag.IntVar(&sshPort, "ssh-port", 4433, "Local port for the internal SSH server")
	flag.IntVar(&collectionInterval, "interval", 30, "Interval time between collections in seconds")

	flag.StringVar(&agentPublicIP, "public-ip", "", "Internet/public IP to force on registration (optional)")
	flag.IntVar(&agentFrequency, "frequency", 5, "Monitoring frequency in minutes for the APM server (default: 5)")
	flag.StringVar(&agentFailScripts, "fail-scripts", "", "Comma-separated fail script IDs (Ex: 1,4,5)")
	flag.StringVar(&agentRecoveryScripts, "recovery-scripts", "", "Comma-separated recovery script IDs (Ex: 2)")

	flag.Var(&agentVars, "var", "Custom variables (can be repeated multiple times. Ex: -var=\"KEY=VAL\")")

	flag.Parse()

	if modeUpdate {
		log.Println("🚀 Starting automated update...")
		if err := updateAgent(); err != nil {
			log.Fatalf("❌ Update failed: %v\n", err)
		}
		log.Println("✅ Update completed successfully! Service restarted.")
		os.Exit(0)
	}

	initStaticData(serverName)

	if modeInstall {
		if serverURL == "" || expectedApiKey == "" {
			log.Fatal("❌ Error: The -install mode requires the -server and -apikey parameters.")
		}

		log.Println("🚀 Starting automated installation...")
		if err := generateCerts(); err != nil {
			log.Fatalf("❌ Error generating TLS keys: %v\n", err)
		}

		regAuth := expectedApiKey
		if registrationKey != "" {
			regAuth = registrationKey
		}

		log.Println("📡 Registering with the remote API...")
		serverId, err := registerAgent(serverURL, regAuth, expectedApiKey, serverPort)
		if err != nil {
			log.Fatalf("❌ Registration failed: %v\n", err)
		}
		log.Printf("✅ Registration successful! Received ID: %s\n", serverId)

		log.Println("📦 Configuring system service...")

		var setupErr error
		if runtime.GOOS == "windows" {
			setupErr = setupWindowsService(serverId, expectedApiKey, serverName, serverPort, sshPort, collectionInterval)
		} else {
			setupErr = setupSystemd(serverId, expectedApiKey, serverName, serverPort, sshPort, collectionInterval)
		}

		if setupErr != nil {
			log.Fatalf("❌ Failed to configure the service: %v\n", setupErr)
		}

		log.Println("\n🎉 Installation completed successfully! Service started in the background.")
		os.Exit(0)
	}

	if modeStart {
		exePath, err := os.Executable()
		if err == nil {
			os.Chdir(filepath.Dir(exePath))
		}

		// Sem -apikey a chave vem do arquivo 'apikey' (0600) ao lado do binário: fora da linha de comando (ps)
		if expectedApiKey == "" {
			if data, err := os.ReadFile(apiKeyFileName); err == nil {
				expectedApiKey = strings.TrimSpace(string(data))
			}
		}
		if expectedApiKey == "" || agentID == "" {
			log.Fatal("❌ Error: The -start mode requires the -id parameter and the API key (file 'apikey' next to the binary or -apikey).")
		}

		if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
			log.Fatal("❌ Error: TLS certificates not found in the current directory.")
		}

		runtime.GOMAXPROCS(1)
		debug.SetGCPercent(20)
		debug.SetMemoryLimit(30 * 1024 * 1024)

		cachedMetrics = collect()
		go backgroundCollector()

		http.HandleFunc("/metrics", loggingMiddleware(authMiddleware(metricsHandler)))
		http.HandleFunc("/health", loggingMiddleware(authMiddleware(healthHandler)))
		http.HandleFunc("/", loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("⚠️ 404 Not Found requested: %s", r.URL.Path)
			http.NotFound(w, r)
		}))

		svcConfig := &service.Config{
			Name:        "nanobot-agent",
			DisplayName: "Nanobot Monitoring Agent",
			Description: "Metrics and resources collection service.",
		}

		prg := &program{}
		s, err := service.New(prg, svcConfig)
		if err != nil {
			log.Fatalf("❌ Failed to initialize the service manager: %v\n", err)
		}

		if err = s.Run(); err != nil {
			log.Fatalf("❌ The service failed to run: %v\n", err)
		}
		return
	}

	fmt.Println("ℹ️  Specify -install, -update or -start to use the agent. Use -h for help.")
}
