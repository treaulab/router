package main

import (
	"context"
	"encoding/json"
	"errors"
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

var errInterrupted = errors.New("interrupted")

type app struct {
	opts              options
	country           string
	tun               bool
	singBox           string
	torBinary         string
	geoip             string
	geoip6            string
	dir               string
	configPath        string
	logPath           string
	torDataDir        string
	warpAccount       *warpAccount
	warpEndpoint      string
	warpInner         *warpAccount
	warpInnerEndpoint string
	protonServers     []protonServer
	protonServer      *protonServer
	protonKey         string
	protonAddress     string
	protonDNS         string
	protonMTU         int
	realIP            string
	engine            *engine
	exitInfo          *exitInfo
	stopped           []string
	sigCh             chan os.Signal
	cleanupOnce       sync.Once
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
	a := &app{
		opts:  opts,
		tun:   os.Geteuid() == 0 && !opts.proxyOnly,
		sigCh: make(chan os.Signal, 1),
	}
	// Proton choices need the free server list, which init loads. Other
	// backends can validate before any network work or service changes.
	if !isProtonBackend(opts.backend) {
		country, err := resolveCountryForBackend(opts.backend, opts.country)
		if err != nil {
			return err
		}
		a.country = country
	}
	signal.Notify(a.sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(a.sigCh)

	if err := a.init(); err != nil {
		return err
	}
	defer a.cleanup()

	if isProtonBackend(opts.backend) {
		country, err := resolveProtonChoice(opts.country, a.protonServers)
		if err != nil {
			return err
		}
		a.country = country
	}

	if err := a.start(); err != nil {
		if errors.Is(err, errInterrupted) {
			fmt.Fprintln(stdout, "\nDisconnecting...")
			return nil
		}
		a.printLogTail(30)
		return err
	}

	if !opts.noInteractive && isTerminal(os.Stdin) {
		return a.interactive(a.sigCh)
	}
	return a.wait(a.sigCh)
}

func (a *app) init() error {
	var err error
	a.singBox, err = findSingBoxBinary()
	if err != nil {
		return err
	}

	a.dir = filepath.Join(os.TempDir(), "router-"+strconv.Itoa(os.Geteuid()))
	a.logPath = filepath.Join(a.dir, "sing-box.log")

	switch a.opts.backend {
	case backendWarp:
		a.configPath = filepath.Join(a.dir, "sing-box-warp.json")
		if err := os.MkdirAll(a.dir, 0o700); err != nil {
			return fmt.Errorf("create state directory: %w", err)
		}
		a.warpAccount, err = loadOrRegisterWarp(context.Background(), warpAccountPath())
		if err != nil {
			return fmt.Errorf("initialize WARP: %w", err)
		}
	case backendProton, backendProtonWarp:
		name := "sing-box-proton.json"
		if a.opts.backend == backendProtonWarp {
			name = "sing-box-proton-warp.json"
		}
		a.configPath = filepath.Join(a.dir, name)
		if err := os.MkdirAll(a.dir, 0o700); err != nil {
			return fmt.Errorf("create state directory: %w", err)
		}
		a.protonKey, err = protonPrivateKey()
		if err != nil {
			return err
		}
		a.protonAddress, a.protonDNS, a.protonMTU, err = protonConfigSettings()
		if err != nil {
			return err
		}
		a.protonServers, err = loadProtonServers(context.Background())
		if err != nil {
			return fmt.Errorf("load Proton servers: %w", err)
		}
		if a.opts.backend == backendProtonWarp {
			a.warpInner, err = loadOrRegisterWarpInner(context.Background())
			if err != nil {
				return fmt.Errorf("initialize inner WARP: %w", err)
			}
		}
	default:
		a.configPath = filepath.Join(a.dir, "sing-box-tor.json")
		a.torDataDir = filepath.Join(a.dir, "tor")
		a.torBinary, err = findTorBinary()
		if err != nil {
			return err
		}
		a.geoip, a.geoip6 = findGeoIP()
		if a.geoip == "" {
			fmt.Fprintln(stderr, "warning: Tor GeoIP database not found; country exits may fail")
		}

		if a.opts.clean {
			fmt.Fprintln(stdout, "Clearing cached Tor data...")
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

	configOpts := configOptions{
		Backend:       a.opts.backend,
		Country:       a.country,
		ListenPort:    a.opts.listenPort,
		TUN:           a.tun,
		InterfaceName: a.opts.interfaceName,
		TorBinary:     a.torBinary,
		TorDataDir:    a.torDataDir,
		GeoIP:         a.geoip,
		GeoIP6:        a.geoip6,
		LogPath:       a.logPath,
	}
	switch a.opts.backend {
	case backendWarp:
		outerEndpoint, err := warpPeerEndpoint("any", a.warpAccount)
		if err != nil {
			return err
		}
		a.warpEndpoint = outerEndpoint
		configOpts.WarpAccount = a.warpAccount
		configOpts.WarpEndpoint = outerEndpoint

		if a.country == "us" {
			if a.warpInner == nil {
				inner, err := loadOrRegisterWarpInner(context.Background())
				if err != nil {
					return fmt.Errorf("initialize inner WARP: %w", err)
				}
				a.warpInner = inner
			}
			innerEndpoint, err := warpPeerEndpoint("us", a.warpInner)
			if err != nil {
				return err
			}
			a.warpInnerEndpoint = innerEndpoint
			configOpts.WarpInner = a.warpInner
			configOpts.WarpInnerEndpoint = innerEndpoint
		} else {
			a.warpInnerEndpoint = ""
		}
	case backendProton, backendProtonWarp:
		server, err := selectProtonServer(a.protonServers, a.country)
		if err != nil {
			return err
		}
		endpoint, err := server.endpoint()
		if err != nil {
			return err
		}
		a.protonServer = &server
		configOpts.ProtonPrivateKey = a.protonKey
		configOpts.ProtonServer = &server
		configOpts.ProtonEndpoint = endpoint
		configOpts.ProtonAddress = a.protonAddress
		configOpts.ProtonDNS = a.protonDNS
		configOpts.ProtonMTU = a.protonMTU

		if a.opts.backend == backendProtonWarp {
			if a.warpInner == nil {
				inner, err := loadOrRegisterWarpInner(context.Background())
				if err != nil {
					return fmt.Errorf("initialize inner WARP: %w", err)
				}
				a.warpInner = inner
			}
			innerEndpoint, err := warpPeerEndpoint("any", a.warpInner)
			if err != nil {
				return err
			}
			a.warpInnerEndpoint = innerEndpoint
			configOpts.WarpInner = a.warpInner
			configOpts.WarpInnerEndpoint = innerEndpoint
		}
	}
	config := buildConfig(configOpts)
	if err := writeConfig(a.configPath, config); err != nil {
		return err
	}

	mode := "Mixed proxy"
	if a.tun {
		mode = "TUN (whole system)"
	}
	fmt.Fprintf(stdout, "Starting sing-box %s engine (%s, %s)...\n", backendName(a.opts.backend), mode, a.countryLabel(a.country))

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
		info, err := a.waitForExit(a.opts.listenPort, a.realIP, bootstrapTimeout, e)
		if err != nil {
			e.stop()
			return err
		}
		a.exitInfo = info
		if a.tun {
			if tunInfo, err := fetchExitDirect(a.opts.backend); err == nil && tunInfo.IP != "" {
				if a.realIP != "" && tunInfo.IP == a.realIP {
					fmt.Fprintf(stderr, "warning: system traffic appears to use the real IP (%s), not %s\n", a.realIP, backendName(a.opts.backend))
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
		select {
		case <-a.sigCh:
			return errInterrupted
		default:
		}
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
			fmt.Fprintln(stdout, "\nDisconnecting...")
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

func parseCountryChoice(backend, value string) (string, error) {
	codes := countryCodes(backend)
	if n, err := strconv.Atoi(value); err == nil {
		if n == 0 {
			return "any", nil
		}
		if n >= 1 && n <= len(codes) {
			return codes[n-1], nil
		}
		return "", fmt.Errorf("number out of range (0 = any, 1-%d = country)", len(codes))
	}
	return resolveCountryForBackend(backend, value)
}

func (a *app) resolveCountry(value string) (string, error) {
	if isProtonBackend(a.opts.backend) {
		return resolveProtonChoice(value, a.protonServers)
	}
	return resolveCountryForBackend(a.opts.backend, value)
}

func (a *app) switchCountry(country string) error {
	country, err := a.resolveCountry(country)
	if err != nil || country == a.country {
		return err
	}

	fmt.Fprintf(stdout, "Switching %s -> %s (restarting engine)...\n", a.countryLabel(a.country), a.countryLabel(country))
	oldCountry := a.country
	a.engine.stop()
	waitForShutdown(a.opts.interfaceName, a.opts.listenPort, a.tun, 10*time.Second)

	a.country = country
	if err := a.start(); err != nil {
		if errors.Is(err, errInterrupted) {
			return err
		}
		fmt.Fprintf(stderr, "could not start %s, restoring %s: %v\n", a.countryLabel(country), a.countryLabel(oldCountry), err)
		a.country = oldCountry
		if restoreErr := a.start(); restoreErr != nil {
			return fmt.Errorf("switch failed and restore failed: %v (restore: %v)", err, restoreErr)
		}
		return fmt.Errorf("switch to %s failed: %w", a.countryLabel(country), err)
	}
	return nil
}

func (a *app) countryLabel(code string) string {
	return countryLabel(a.opts.backend, code, a.protonServers)
}

func (a *app) statusLines() []string {
	var lines []string
	if a.tun {
		lines = append(lines, "Mode:      TUN (whole system)")
		lines = append(lines, "Interface: "+a.opts.interfaceName)
	} else {
		lines = append(lines, "Mode:      Mixed proxy")
	}
	lines = append(lines, fmt.Sprintf("Proxy:     http://127.0.0.1:%d  socks5://127.0.0.1:%d", a.opts.listenPort, a.opts.listenPort))
	if isProtonBackend(a.opts.backend) {
		lines = append(lines, "Country:   "+a.countryLabel(a.country))
	} else {
		lines = append(lines, fmt.Sprintf("Country:   %s (%s)", a.countryLabel(a.country), a.country))
	}
	if a.opts.backend == backendWarp && a.warpEndpoint != "" {
		if a.warpInnerEndpoint != "" {
			lines = append(lines, "Outer:     "+a.warpEndpoint)
			lines = append(lines, "Inner:     "+a.warpInnerEndpoint+" (Double WARP)")
		} else {
			lines = append(lines, "Endpoint:  "+a.warpEndpoint)
		}
	}
	if isProtonBackend(a.opts.backend) && a.protonServer != nil {
		lines = append(lines, "Server:    "+a.protonServer.ServerName)
		if endpoint, err := a.protonServer.endpoint(); err == nil {
			lines = append(lines, fmt.Sprintf("Endpoint:  %s:%d (Proton)", endpoint, protonEndpointPort))
		}
	}
	if a.opts.backend == backendProtonWarp && a.warpInnerEndpoint != "" {
		lines = append(lines, "WARP:      "+a.warpInnerEndpoint+" (inner)")
	}
	if a.exitInfo != nil {
		location := strings.Trim(strings.Join([]string{a.exitInfo.City, a.exitInfo.Country}, ", "), ", ")
		if location != "" {
			lines = append(lines, "Exit:      "+location)
		}
		if a.exitInfo.IP != "" {
			lines = append(lines, "Exit IP:   "+a.exitInfo.IP)
		}
		if a.exitInfo.ISP != "" {
			lines = append(lines, "ISP:       "+a.exitInfo.ISP)
		}
	}
	return lines
}

func (a *app) printStatus() {
	fmt.Fprintln(stdout)
	switch a.opts.backend {
	case backendWarp:
		fmt.Fprintln(stdout, "=== WARP Router ===")
	case backendProton:
		fmt.Fprintln(stdout, "=== Proton VPN Router ===")
	case backendProtonWarp:
		fmt.Fprintln(stdout, "=== Proton -> WARP Router ===")
	default:
		fmt.Fprintln(stdout, "=== Tor Router ===")
	}
	for _, line := range a.statusLines() {
		fmt.Fprintln(stdout, line)
	}
	fmt.Fprintln(stdout)
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
	fmt.Fprintln(stderr, "--- sing-box log tail ---")
	for _, line := range lines {
		fmt.Fprintln(stderr, " ", stripANSI(line))
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
			fmt.Fprintln(stdout, "Restarting service:", a.stopped[i])
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
			fmt.Fprintln(stdout, "Stopping conflicting service:", svc)
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
	if info, err := fetchTrace(directClient(5*time.Second), ""); err == nil {
		return info.IP
	}
	return ""
}

func fetchExitDirect(backend string) (*exitInfo, error) {
	info, err := fetchTrace(directClient(8*time.Second), traceISP(backend))
	if err == nil {
		return info, nil
	}
	return fetchIPAPI(directClient(8 * time.Second))
}

func traceISP(backend string) string {
	switch backend {
	case backendTor:
		return "Tor Network"
	case backendProton:
		return "Proton VPN"
	default:
		return ""
	}
}

func (a *app) waitForExit(port int, realIP string, timeout time.Duration, e *engine) (*exitInfo, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-a.sigCh:
			return nil, errInterrupted
		default:
		}
		if err, exited := e.status(); exited {
			if err == nil {
				err = fmt.Errorf("sing-box exited")
			}
			return nil, err
		}
		client := proxyClient(port, 8*time.Second)
		info, err := fetchIPAPI(client)
		if err != nil {
			info, err = fetchTrace(client, traceISP(a.opts.backend))
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
		return nil, fmt.Errorf("%s did not become ready: %w", backendName(a.opts.backend), lastErr)
	}
	return nil, fmt.Errorf("%s did not become ready within %s", backendName(a.opts.backend), timeout)
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

func fetchTrace(client *http.Client, defaultISP string) (*exitInfo, error) {
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
	isp := "Tor Network"
	if values["warp"] == "on" {
		isp = "Cloudflare WARP"
	}
	return &exitInfo{
		IP:          values["ip"],
		Country:     values["loc"],
		CountryCode: values["loc"],
		City:        values["colo"],
		ISP:         isp,
	}, nil
}
