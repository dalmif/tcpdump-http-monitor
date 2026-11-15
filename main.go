// httpmonitor: a realtime HTTP/HTTPS traffic dashboard.
//
// It combines two capture sources into one web UI:
//   - a passive sniffer that streams pcap from a gateway over SSH
//     (e.g. a Linux router or single-board computer) and extracts plain
//     HTTP + TLS metadata;
//   - an intercepting proxy (with your own or a generated CA) that
//     decrypts HTTPS for devices configured to use it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"httpmonitor/internal/flow"
	"httpmonitor/internal/proxy"
	"httpmonitor/internal/server"
	"httpmonitor/internal/sniff"
	"httpmonitor/web"
)

// settings are the defaults for the command-line flags. They can be
// overridden by a JSON config file (see configPath) and then by flags.
type settings struct {
	UI        string `json:"ui"`
	Proxy     string `json:"proxy"`
	SSH       string `json:"ssh"`
	RemoteCmd string `json:"remoteCmd"`
	Filter    string `json:"filter"`
	Capture   bool   `json:"capture"`
	CADir     string `json:"caDir"`
	MaxFlows  int    `json:"maxFlows"`
}

func configPath(cfgDir string) string {
	if p := os.Getenv("HTTPMONITOR_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(cfgDir, "httpmonitor", "config.json")
}

func main() {
	cfgDir, _ := os.UserConfigDir()
	def := settings{
		UI:        "127.0.0.1:8899",
		Proxy:     ":8080",
		RemoteCmd: "tcpdump -U -s0 -w - {qfilter}",
		Filter:    "tcp",
		CADir:     filepath.Join(cfgDir, "httpmonitor"),
		MaxFlows:  20000,
	}
	cfgFile := configPath(cfgDir)
	if b, err := os.ReadFile(cfgFile); err == nil {
		if err := json.Unmarshal(b, &def); err != nil {
			log.Fatalf("config %s: %v", cfgFile, err)
		}
		log.Printf("config: loaded %s", cfgFile)
	}

	var (
		uiAddr    = flag.String("ui", def.UI, "address for the web dashboard")
		proxyAddr = flag.String("proxy", def.Proxy, "address for the HTTP/HTTPS proxy (empty to disable)")
		sshHost   = flag.String("ssh", def.SSH, "ssh destination to capture from (a host alias from ~/.ssh/config or user@host)")
		remoteCmd = flag.String("remote-cmd", def.RemoteCmd, "command run over ssh; {filter}/{qfilter} = BPF filter (raw/shell-quoted). Use \"{filter}\" for a forced-command account that runs tcpdump itself")
		filter    = flag.String("filter", def.Filter, "default BPF filter")
		autostart = flag.Bool("capture", def.Capture, "start capturing from the ssh host immediately")
		caDir     = flag.String("ca-dir", def.CADir, "directory holding ca.pem / ca-key.pem (generated if missing)")
		maxFlows  = flag.Int("max-flows", def.MaxFlows, "maximum flows kept in memory")
		openUI    = flag.Bool("open", false, "open the dashboard in a browser")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: httpmonitor [flags]\n\nDefaults can be set in %s (JSON keys: ui, proxy, ssh, remoteCmd, filter, capture, caDir, maxFlows).\n\n", cfgFile)
		flag.PrintDefaults()
	}
	flag.Parse()

	store := flow.NewStore(*maxFlows)
	ca, err := proxy.LoadOrCreateCA(*caDir)
	if err != nil {
		log.Fatalf("CA: %v", err)
	}
	log.Printf("CA: %s (from %s)", ca.Info().Subject, *caDir)

	sniffCfg := sniff.Config{SSHHost: *sshHost, RemoteCmd: *remoteCmd, Filter: *filter, ExcludeSSH: true, Dedup: true}
	sn := sniff.New(store, sniffCfg)
	px := proxy.New(store, ca, proxy.Config{Addr: *proxyAddr, MITM: true})
	if *proxyAddr != "" {
		if err := px.Start(); err != nil {
			log.Printf("proxy: %v", err)
		}
	}
	if *autostart && *sshHost == "" {
		log.Printf("sniff: -capture given but no ssh host configured (use -ssh or the config file)")
	} else if *autostart {
		if err := sn.Start(sniffCfg); err != nil {
			log.Printf("sniff: %v", err)
		}
	}

	srv := &server.Server{Store: store, Sniffer: sn, Proxy: px, UI: web.FS(), DefaultSniff: sniffCfg}
	if srv.UI == nil {
		log.Printf("warning: web UI not built (run `make` or `cd web && npm run build`); API only")
	}
	ln, err := net.Listen("tcp", *uiAddr)
	if err != nil {
		log.Fatal(err)
	}
	url := "http://" + strings.Replace(ln.Addr().String(), "0.0.0.0", "127.0.0.1", 1)
	log.Printf("dashboard: %s", url)
	if *openUI {
		openBrowser(url)
	}
	log.Fatal(http.Serve(ln, srv.Handler()))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}
