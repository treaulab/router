package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	startupTimeout   = 90 * time.Second
	bootstrapTimeout = 60 * time.Second
)

type app struct {
	opts        options
	country     string
	tun         bool
	singBox     string
	torBinary   string
	geoip       string
	geoip6      string
	dir         string
	configPath  string
	logPath     string
	torDataDir  string
	realIP      string
	engine      *engine
	exitInfo    *exitInfo
	stopped     []string
	cleanupOnce sync.Once
}

type exitInfo struct {
	IP          string
	Country     string
	CountryCode string
	City        string
	ISP         string
}

type engine struct {
	cmd     *exec.Cmd
	logFile *os.File
	done    chan struct{}

	mu      sync.Mutex
	exited  bool
	exitErr error
}

func run(opts options) error {
	country, err := resolveCountry(opts.country)
	if err != nil {
		return err
	}
	a := &app{
		opts:    opts,
		country: country,
		tun:     os.Geteuid() == 0 && !opts.proxyOnly,
	}
	if err := a.init(); err != nil {
		return err
	}
	defer a.cleanup()

	if err := a.start(); err != nil {
		a.printLogTail(30)
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if !opts.noInteractive && isTerminal(os.Stdin) {
		return a.interactive(sigCh)
	}
	return a.wait(sigCh)
}

func (a *app) init() error {
	var err error
	a.singBox, err = findSingBoxBinary()
	if err != nil {
		return err
	}
	a.torBinary, err = findTorBinary()
	if err != nil {
		return err
	}
	a.geoip, a.geoip6 = findGeoIP()
	if a.geoip == "" {
		fmt.Fprintln(os.Stderr, "warning: Tor GeoIP database not found; country exits may fail")
	}

	a.dir = filepath.Join(os.TempDir(), "router-"+strconv.Itoa(os.Geteuid()))
	a.configPath = filepath.Join(a.dir, "sing-box-tor.json")
	a.logPath = filepath.Join(a.dir, "sing-box.log")
	a.torDataDir = filepath.Join(a.dir, "tor")

	if a.opts.clean {
		fmt.Println("Clearing cached Tor data...")
		if err := os.RemoveAll(a.torDataDir); err != nil {
			return fmt.Errorf("clear Tor data: %w", err)
		}
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.MkdirAll(a.torDataDir, 0o700); err != nil {
		return fmt.Errorf("create Tor data directory: %w", err)
	}

	if a.tun {
		a.stopped = stopConflictingServices()
	}
	a.realIP = detectRealIP()
	return nil
}

func (a *app) start() error {
	a.exitInfo = nil
	if portOpen(a.opts.listenPort) {
		return fmt.Errorf("local port %d is already in use", a.opts.listenPort)
	}
	if a.tun && interfaceExists(a.opts.interfaceName) {
		return fmt.Errorf("interface %s already exists; remove it or use --interface", a.opts.interfaceName)
	}
	config := buildConfig(configOptions{
		Country:       a.country,
		ListenPort:    a.opts.listenPort,
		TUN:           a.tun,
		InterfaceName: a.opts.interfaceName,
		TorBinary:     a.torBinary,
		TorDataDir:    a.torDataDir,
		GeoIP:         a.geoip,
		GeoIP6:        a.geoip6,
		LogPath:       a.logPath,
	})
	if err := writeConfig(a.configPath, config); err != nil {
		return err
	}

	mode := "Mixed proxy"
	if a.tun {
		mode = "TUN (whole system)"
	}
	fmt.Printf("Starting sing-box Tor engine (%s, %s)...\n", mode, countryName(a.country))

	e, err := startEngine(a.singBox, a.configPath, a.logPath)
	if err != nil {
		return err
	}
	a.engine = e

	if err := a.waitForReady(); err != nil {
		e.stop()
		return err
	}

	if !a.opts.noVerify {
		info, err := waitForExit(a.opts.listenPort, a.realIP, bootstrapTimeout, e)
		if err != nil {
			e.stop()
			return err
		}
		a.exitInfo = info
		if a.tun {
			if tunInfo, err := fetchExitDirect(); err == nil && tunInfo.IP != "" {
				if a.realIP != "" && tunInfo.IP == a.realIP {
					fmt.Fprintf(os.Stderr, "warning: system traffic appears to use the real IP (%s), not Tor\n", a.realIP)
				} else {
					a.exitInfo = tunInfo
				}
			}
		}
	}
	a.printStatus()
	return nil
}

func (a *app) waitForReady() error {
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		if err, exited := a.engine.status(); exited {
			if err == nil {
				err = fmt.Errorf("sing-box exited during startup")
			}
			return err
		}
		ready := portOpen(a.opts.listenPort)
		if a.tun && !interfaceExists(a.opts.interfaceName) {
			ready = false
		}
		if ready {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("sing-box did not become ready within %s", startupTimeout)
}

func (a *app) wait(sigCh <-chan os.Signal) error {
	for {
		select {
		case <-sigCh:
			fmt.Println("\nDisconnecting...")
			return nil
		case <-time.After(time.Second):
			if err, exited := a.engine.status(); exited {
				a.printLogTail(30)
				if err == nil {
					err = fmt.Errorf("sing-box exited")
				}
				return err
			}
		}
	}
}

func (a *app) interactive(sigCh <-chan os.Signal) error {
	lines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()

	fmt.Println()
	fmt.Println("Switch: <code>, n(ext), r(andom), l(ist), s(tatus), q(uit)")
	for {
		fmt.Printf("[%s] > ", a.country)
		select {
		case <-sigCh:
			fmt.Println("\nDisconnecting...")
			return nil
		case line, ok := <-lines:
			if !ok {
				fmt.Println("\nDisconnecting...")
				return nil
			}
			command := strings.ToLower(strings.TrimSpace(line))
			switch command {
			case "":
				continue
			case "q", "quit", "exit":
				fmt.Println("Disconnecting...")
				return nil
			case "l", "list":
				printCountryList()
			case "s", "status":
				a.printStatus()
			case "n", "next":
				if err := a.switchCountry(nextCountry(a.country)); err != nil {
					fmt.Fprintln(os.Stderr, "switch failed:", err)
				}
			case "r", "random":
				if err := a.switchCountry(randomCountry()); err != nil {
					fmt.Fprintln(os.Stderr, "switch failed:", err)
				}
			default:
				code, err := parseCountryChoice(command)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					continue
				}
				if err := a.switchCountry(code); err != nil {
					fmt.Fprintln(os.Stderr, "switch failed:", err)
				}
			}
		case <-time.After(time.Second):
			if err, exited := a.engine.status(); exited {
				a.printLogTail(30)
				if err == nil {
					err = fmt.Errorf("sing-box exited")
				}
				return err
			}
		}
	}
}

func parseCountryChoice(value string) (string, error) {
	if n, err := strconv.Atoi(value); err == nil {
		if n == 0 {
			return "any", nil
		}
		if n >= 1 && n <= len(commonCountries) {
			return commonCountries[n-1].Code, nil
		}
		return "", fmt.Errorf("number out of range (0 = any, 1-%d = country)", len(commonCountries))
	}
	return resolveCountry(value)
}

func (a *app) switchCountry(country string) error {
	country, err := resolveCountry(country)
	if err != nil || country == a.country {
		return err
	}

	fmt.Printf("Switching %s -> %s (restarting engine)...\n", countryName(a.country), countryName(country))
	oldCountry := a.country
	a.engine.stop()
	waitForShutdown(a.opts.interfaceName, a.opts.listenPort, a.tun, 10*time.Second)

	a.country = country
	if err := a.start(); err != nil {
		fmt.Fprintf(os.Stderr, "could not start %s, restoring %s: %v\n", countryName(country), countryName(oldCountry), err)
		a.country = oldCountry
		if restoreErr := a.start(); restoreErr != nil {
			return fmt.Errorf("switch failed and restore failed: %v (restore: %v)", err, restoreErr)
		}
		return fmt.Errorf("switch to %s failed: %w", countryName(country), err)
	}
	return nil
}

func (a *app) printStatus() {
	fmt.Println()
	fmt.Println("=== Tor Router ===")
	if a.tun {
		fmt.Println("Mode:      TUN (whole system)")
		fmt.Println("Interface:", a.opts.interfaceName)
	} else {
		fmt.Println("Mode:      Mixed proxy")
	}
	fmt.Printf("Proxy:     http://127.0.0.1:%d  socks5://127.0.0.1:%d\n", a.opts.listenPort, a.opts.listenPort)
	fmt.Printf("Country:   %s (%s)\n", countryName(a.country), a.country)
	if a.exitInfo != nil {
		location := strings.Trim(strings.Join([]string{a.exitInfo.City, a.exitInfo.Country}, ", "), ", ")
		if location != "" {
			fmt.Println("Exit:     ", location)
		}
		if a.exitInfo.IP != "" {
			fmt.Println("Exit IP:  ", a.exitInfo.IP)
		}
		if a.exitInfo.ISP != "" {
			fmt.Println("ISP:      ", a.exitInfo.ISP)
		}
	}
	fmt.Println()
}

func (a *app) printLogTail(n int) {
	data, err := os.ReadFile(a.logPath)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	fmt.Fprintln(os.Stderr, "--- sing-box log tail ---")
	for _, line := range lines {
		fmt.Fprintln(os.Stderr, " ", stripANSI(line))
	}
}

func stripANSI(value string) string {
	var out strings.Builder
	inEscape := false
	for i := 0; i < len(value); i++ {
		char := value[i]
		if inEscape {
			if char >= 0x40 && char <= 0x7e {
				inEscape = false
			}
			continue
		}
		if char == 0x1b {
			inEscape = true
			continue
		}
		out.WriteByte(char)
	}
	return out.String()
}

func (a *app) cleanup() {
	a.cleanupOnce.Do(func() {
		if a.engine != nil {
			a.engine.stop()
			waitForShutdown(a.opts.interfaceName, a.opts.listenPort, a.tun, 5*time.Second)
		}
		for i := len(a.stopped) - 1; i >= 0; i-- {
			fmt.Println("Restarting service:", a.stopped[i])
			_ = exec.Command("systemctl", "start", a.stopped[i]).Run()
		}
	})
}

func findSingBoxBinary() (string, error) {
	if path := os.Getenv("ROUTER_SINGBOX_BINARY"); path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("ROUTER_SINGBOX_BINARY: %w", err)
		}
		return path, nil
	}
	if path, err := exec.LookPath("sing-box"); err == nil {
		return path, nil
	}
	for _, path := range []string{
		"/run/current-system/sw/bin/sing-box",
		"/usr/local/bin/sing-box",
		"/usr/bin/sing-box",
	} {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("sing-box executable not found; install sing-box or set ROUTER_SINGBOX_BINARY")
}

func startEngine(singBox, configPath, logPath string) (*engine, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	cmd := exec.Command(singBox, "run", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start sing-box: %w", err)
	}
	e := &engine{cmd: cmd, logFile: logFile, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		e.mu.Lock()
		e.exited = true
		e.exitErr = err
		e.mu.Unlock()
		close(e.done)
	}()
	return e, nil
}

func (e *engine) status() (error, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exitErr, e.exited
}

func (e *engine) stop() {
	if e == nil || e.cmd == nil || e.cmd.Process == nil {
		return
	}
	// Ask sing-box to shut down cleanly so it can stop its Tor child itself.
	_ = e.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
		<-e.done
	}
	if e.logFile != nil {
		e.logFile.Close()
	}
}

func stopConflictingServices() []string {
	var stopped []string
	for _, svc := range []string{"sing-box", "zapret"} {
		if err := exec.Command("systemctl", "is-active", "--quiet", svc).Run(); err == nil {
			fmt.Println("Stopping conflicting service:", svc)
			if err := exec.Command("systemctl", "stop", svc).Run(); err == nil {
				stopped = append(stopped, svc)
			}
		}
	}
	return stopped
}

func waitForShutdown(iface string, port int, tun bool, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if portOpen(port) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if tun && interfaceExists(iface) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return
	}
}

func portOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func directClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   timeout,
	}
}

func proxyClient(port int, timeout time.Duration) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   timeout,
	}
}

type ipAPIResponse struct {
	Status      string `json:"status"`
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

func detectRealIP() string {
	if info, err := fetchIPAPI(directClient(5 * time.Second)); err == nil {
		return info.IP
	}
	if info, err := fetchTrace(directClient(5 * time.Second)); err == nil {
		return info.IP
	}
	return ""
}

func fetchExitDirect() (*exitInfo, error) {
	info, err := fetchTrace(directClient(8 * time.Second))
	if err == nil {
		return info, nil
	}
	return fetchIPAPI(directClient(8 * time.Second))
}

func waitForExit(port int, realIP string, timeout time.Duration, e *engine) (*exitInfo, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err, exited := e.status(); exited {
			if err == nil {
				err = fmt.Errorf("sing-box exited")
			}
			return nil, err
		}
		client := proxyClient(port, 8*time.Second)
		info, err := fetchIPAPI(client)
		if err != nil {
			info, err = fetchTrace(client)
		}
		if err == nil && info.IP != "" {
			if realIP == "" || info.IP != realIP {
				return info, nil
			}
			lastErr = fmt.Errorf("traffic still exits from real IP %s", realIP)
		} else if err != nil {
			lastErr = err
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("Tor did not become ready: %w", lastErr)
	}
	return nil, fmt.Errorf("Tor did not become ready within %s", timeout)
}

func fetchIPAPI(client *http.Client) (*exitInfo, error) {
	resp, err := client.Get("http://ip-api.com/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api returned %s", resp.Status)
	}
	var data ipAPIResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
		return nil, err
	}
	if data.Status != "success" || data.Query == "" {
		return nil, fmt.Errorf("ip-api did not return an address")
	}
	return &exitInfo{
		IP:          data.Query,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		City:        data.City,
		ISP:         data.ISP,
	}, nil
}

func fetchTrace(client *http.Client) (*exitInfo, error) {
	resp, err := client.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trace returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	if values["ip"] == "" {
		return nil, fmt.Errorf("trace did not return an address")
	}
	return &exitInfo{
		IP:          values["ip"],
		Country:     values["loc"],
		CountryCode: values["loc"],
		City:        values["colo"],
		ISP:         "Tor Network",
	}, nil
}
