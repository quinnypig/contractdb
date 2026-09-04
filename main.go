package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/miekg/dns"
)

const defaultConfigPath = "contractdb.toml"

// FileConfig mirrors contractdb.toml.
type FileConfig struct {
	Server struct {
		Listen      string `toml:"listen"`
		Zone        string `toml:"zone"`
		TTL         uint32 `toml:"ttl"`
		AdvertiseIP string `toml:"advertise_ip"`
		Pidfile     string `toml:"pidfile"`
	} `toml:"server"`
	DynamoDB struct {
		Table      string            `toml:"table"`
		PKAttr     string            `toml:"pk_attr"`
		Endpoint   string            `toml:"endpoint"`
		Consistent bool              `toml:"consistent"`
		GSIs       map[string]string `toml:"gsis"`
	} `toml:"dynamodb"`
	Demo struct {
		Enabled bool `toml:"enabled"`
	} `toml:"demo"`
	Auth struct {
		Mode         string `toml:"mode"` // "open" | "tsig-required"
		TSIGKeysFile string `toml:"tsig_keys_file"`
	} `toml:"auth"`
	Notify struct {
		Notifiees []string `toml:"notifiees"`
	} `toml:"notify"`
	DNSSEC struct {
		Enabled bool   `toml:"enabled"`
		KeyDir  string `toml:"key_dir"` // empty = ephemeral keys
	} `toml:"dnssec"`
	DoH struct {
		Listen string `toml:"listen"`
		Cert   string `toml:"cert"`
		Key    string `toml:"key"`
	} `toml:"doh"`
}

const sampleConfig = `# ContractDB configuration.
# A DynamoDB table you can query over DNS. Yes, really.

[server]
listen = ":53"                  # UDP+TCP listen address
zone = "contractdb.internal."   # authoritative zone
ttl = 5                         # record TTL; resolvers WILL cache your DB queries
advertise_ip = "127.0.0.1"      # served at ns1.<zone>
pidfile = ""                    # written by serve, read by stop/status

[dynamodb]
table = ""                      # CONTRACTDB_TABLE
pk_attr = "pk"                  # partition key attribute
endpoint = ""                   # e.g. http://localhost:4566 for localstack
consistent = false              # strongly consistent reads cost 2x, even here
gsis = {}                       # e.g. { "gsi-email" = "email" } -> <value>.gsi-email.<zone>

[demo]
enabled = false                 # in-memory sample data instead of DynamoDB

[auth]
mode = "open"                   # "open" reads for everyone, "tsig-required" gates everything
tsig_keys_file = ""             # lines of "keyname base64-secret", or inline name:secret,name2:secret2

[notify]
notifiees = []                  # NOTIFY targets after writes, e.g. ["10.0.0.7:53"]

[dnssec]
enabled = false                 # online-signing; answers DO-bit queries with RRSIG/NSEC
key_dir = ""                    # persist signing key here (empty = ephemeral)

[doh]
listen = ""                     # DNS-over-HTTPS listener, e.g. ":8443"; empty disables
cert = ""                       # TLS cert (self-signed generated if both cert+key empty and listen set)
key = ""
`

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatalUsage(msg string) {
	fmt.Fprintln(os.Stderr, "contractdb:", msg)
	fmt.Fprintln(os.Stderr, `
usage: contractdb <command> [flags]

commands:
  init         write a sample contractdb.toml
  serve        start the server (default)
  status       is it running?
  stop         SIGTERM via pidfile
  healthcheck  query the health record (exit 0 = UP)`)
	os.Exit(2)
}

func main() {
	log.SetFlags(log.LstdFlags)

	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "init":
		cmdInit()
	case "serve":
		cmdServe(args)
	case "status":
		cmdStatus(args)
	case "stop":
		cmdStop(args)
	case "healthcheck":
		cmdHealthcheck(args)
	default:
		fatalUsage(fmt.Sprintf("unknown command %q", cmd))
	}
}

// loadFileConfig reads the TOML file if present. Missing file is fine.
func loadFileConfig(path string) FileConfig {
	var fc FileConfig
	if path == "" || !fileExists(path) {
		return fc
	}
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		log.Fatalf("parse config %s: %v", path, err)
	}
	return fc
}

func cmdInit() {
	if fileExists(defaultConfigPath) {
		log.Fatalf("%s already exists", defaultConfigPath)
	}
	if err := os.WriteFile(defaultConfigPath, []byte(sampleConfig), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s — edit, then run: contractdb serve\n", defaultConfigPath)
}

type commonFlags struct {
	configPath string
}

func addCommonFlags(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.StringVar(&c.configPath, "config", defaultConfigPath, "path to contractdb.toml")
	return c
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	common := addCommonFlags(fs)

	var (
		addr       = fs.String("addr", "", "listen address (CONTRACTDB_ADDR)")
		zone       = fs.String("zone", "", "authoritative zone (CONTRACTDB_ZONE)")
		table      = fs.String("table", "", "DynamoDB table (CONTRACTDB_TABLE)")
		pkAttr     = fs.String("pk", "", "partition key attribute (CONTRACTDB_PK)")
		ttl        = fs.Uint("ttl", 0, "record TTL seconds (CONTRACTDB_TTL)")
		endpoint   = fs.String("endpoint", "", "DynamoDB endpoint override (CONTRACTDB_ENDPOINT)")
		consistent = fs.Bool("consistent", false, "strongly consistent reads")
		demo       = fs.Bool("demo", false, "serve built-in sample data")
		gsiList    = fs.String("gsi", "", "GSIs as idx=attr[,idx2=attr2]")
		authMode   = fs.String("auth", "", "\"open\" or \"tsig-required\" (CONTRACTDB_AUTH)")
		tsigKeys   = fs.String("tsig-keys", "", "TSIG keys file or inline name:secret,... (CONTRACTDB_TSIG_KEYS)")
		notifyList = fs.String("notify", "", "NOTIFY targets host:port,...")
		dnssecDir  = fs.String("dnssec-dir", "", "enable DNSSEC online signing, persisting keys here")
		dohAddr    = fs.String("doh", "", "DNS-over-HTTPS listen address (CONTRACTDB_DOH)")
		tlsCert    = fs.String("tls-cert", "", "DoH TLS certificate")
		tlsKey     = fs.String("tls-key", "", "DoH TLS key")
		pidfile    = fs.String("pidfile", "", "write PID here")
	)
	fs.Parse(args)

	fc := loadFileConfig(common.configPath)

	pick := func(flagVal, envVal, fileVal, def string) string {
		if flagVal != "" {
			return flagVal
		}
		if envVal != "" {
			return envVal
		}
		if fileVal != "" {
			return fileVal
		}
		return def
	}

	finalAddr := pick(*addr, os.Getenv("CONTRACTDB_ADDR"), fc.Server.Listen, ":53")
	finalZone := strings.ToLower(dns.Fqdn(pick(*zone, os.Getenv("CONTRACTDB_ZONE"), fc.Server.Zone, "contractdb.internal.")))
	if _, ok := dns.IsDomainName(finalZone); !ok || finalZone == "." {
		fatalUsage(fmt.Sprintf("invalid authoritative zone %q", finalZone))
	}
	finalPK := pick(*pkAttr, os.Getenv("CONTRACTDB_PK"), fc.DynamoDB.PKAttr, "pk")
	finalTable := pick(*table, os.Getenv("CONTRACTDB_TABLE"), fc.DynamoDB.Table, "")
	finalEndpoint := pick(*endpoint, os.Getenv("CONTRACTDB_ENDPOINT"), fc.DynamoDB.Endpoint, "")
	finalAuth := pick(*authMode, os.Getenv("CONTRACTDB_AUTH"), fc.Auth.Mode, "open")
	finalTsig := pick(*tsigKeys, os.Getenv("CONTRACTDB_TSIG_KEYS"), fc.Auth.TSIGKeysFile, "")
	finalDoh := pick(*dohAddr, os.Getenv("CONTRACTDB_DOH"), fc.DoH.Listen, "")
	finalTLSCert := pick(*tlsCert, os.Getenv("CONTRACTDB_TLS_CERT"), fc.DoH.Cert, "")
	finalTLSKey := pick(*tlsKey, os.Getenv("CONTRACTDB_TLS_KEY"), fc.DoH.Key, "")
	finalConsistent := *consistent || envOr("CONTRACTDB_CONSISTENT", "") == "1" || fc.DynamoDB.Consistent
	useDemo := *demo || envOr("CONTRACTDB_DEMO", "") == "1" || fc.Demo.Enabled

	if finalAuth != "open" && finalAuth != "tsig-required" {
		fatalUsage(fmt.Sprintf("invalid auth mode %q (want open or tsig-required)", finalAuth))
	}
	if finalAuth == "tsig-required" && finalTsig == "" {
		fatalUsage("auth mode tsig-required needs -tsig-keys / CONTRACTDB_TSIG_KEYS")
	}
	if (finalTLSCert == "") != (finalTLSKey == "") {
		fatalUsage("DoH TLS certificate and key must be configured together")
	}
	finalAdvertiseIP := pick("", os.Getenv("CONTRACTDB_ADVERTISE_IP"), fc.Server.AdvertiseIP, "127.0.0.1")
	if net.ParseIP(finalAdvertiseIP) == nil {
		fatalUsage(fmt.Sprintf("invalid advertise IP %q", finalAdvertiseIP))
	}

	cfgTTL := fc.Server.TTL
	if v := os.Getenv("CONTRACTDB_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfgTTL = uint32(n)
		}
	}
	if *ttl > 0 {
		cfgTTL = uint32(*ttl)
	}
	if cfgTTL == 0 {
		cfgTTL = 5
	}

	gsis := map[string]string{}
	for k, v := range fc.DynamoDB.GSIs {
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if strings.Contains(k, ".") || k == "" || v == "" {
			fatalUsage(fmt.Sprintf("invalid GSI mapping %q=%q", k, v))
		}
		gsis[k] = v
	}
	if *gsiList != "" {
		for _, pair := range strings.Split(*gsiList, ",") {
			idx, attr, found := strings.Cut(pair, "=")
			if !found {
				fatalUsage("-gsi expects idx=attr pairs")
			}
			idx, attr = strings.ToLower(strings.TrimSpace(idx)), strings.TrimSpace(attr)
			if idx == "" || attr == "" || strings.Contains(idx, ".") {
				fatalUsage(fmt.Sprintf("invalid GSI mapping %q", pair))
			}
			gsis[idx] = attr
		}
	}

	if !useDemo && finalTable == "" {
		fatalUsage("no -table / CONTRACTDB_TABLE configured (or use -demo)")
	}

	// Storage.
	var store Store
	if useDemo {
		store = NewFullSampleStore(gsis)
		log.Printf("demo mode: serving built-in sample data")
	} else {
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalf("load aws config: %v", err)
		}
		opts := []func(*dynamodb.Options){}
		if finalEndpoint != "" {
			opts = append(opts, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(finalEndpoint) })
		}
		store = NewFullDynamoStore(dynamodb.NewFromConfig(awsCfg, opts...), finalTable, finalPK, finalConsistent, gsis)
	}

	handlerCfg := Config{
		Zone:        finalZone,
		Table:       finalTable,
		PKAttr:      finalPK,
		TTL:         cfgTTL,
		AdvertiseIP: finalAdvertiseIP,
		Serial:      uint32(time.Now().Unix()),
		GSIs:        gsis,
	}

	h := NewHandler(store, handlerCfg)

	// Authentication.
	tsigProvider, err := buildTSIG(finalTsig)
	if err != nil {
		log.Fatalf("tsig: %v", err)
	}
	if tsigProvider != nil {
		h.tsigProvider = tsigProvider
	}
	h.authRequired = finalAuth == "tsig-required"
	if h.authRequired && h.tsigProvider == nil {
		log.Fatal("tsig-required mode needs at least one valid TSIG key")
	}

	// IXFR history: always journal so incremental transfers serve real deltas.
	h.changelog = NewMemChangeLog(handlerCfg.Serial)

	// NOTIFY targets.
	h.notifiees = append(h.notifiees, fc.Notify.Notifiees...)
	if *notifyList != "" {
		for _, n := range strings.Split(*notifyList, ",") {
			h.notifiees = append(h.notifiees, strings.TrimSpace(n))
		}
	}

	// DNSSEC online signing.
	if *dnssecDir != "" || fc.DNSSEC.Enabled {
		finalDNSSECDir := *dnssecDir
		if finalDNSSECDir == "" {
			finalDNSSECDir = fc.DNSSEC.KeyDir
		}
		signer, err := NewOnlineSigner(finalZone, finalDNSSECDir)
		if err != nil {
			log.Fatalf("dnssec: %v", err)
		}
		h.signer = signer
		log.Printf("dnssec: online signing enabled (key dir %q)", finalDNSSECDir)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// DoH sidecar. TLS material is prepared synchronously so a bad
	// configuration fails before the DNS listeners come up.
	if finalDoh != "" {
		cert, key := finalTLSCert, finalTLSKey
		if cert == "" && key == "" {
			dir := envOr("CONTRACTDB_TLS_DIR", ".contractdb-tls")
			cert, key = dir+"/cert.pem", dir+"/key.pem"
			if err := EnsureTLSCert(cert, key); err != nil {
				log.Fatalf("doh tls: %v", err)
			}
		}
		go func() {
			if err := ServeDoH(ctx, finalDoh, cert, key, h); err != nil {
				log.Printf("doh: %v", err)
			}
		}()
	}

	writePidfile(pick(*pidfile, os.Getenv("CONTRACTDB_PIDFILE"), fc.Server.Pidfile, ""))
	defer removePidfile()

	if err := h.Serve(ctx, finalAddr); err != nil {
		removePidfile()
		log.Fatal(err)
	}
}

func buildTSIG(spec string) (*hmacProvider, error) {
	if spec == "" {
		return nil, nil
	}
	keys, err := LoadTSIGKeys(spec)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	log.Printf("tsig: %d key(s) loaded", len(keys))
	return newHMACProvider(keys)
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	common := addCommonFlags(fs)
	fs.Parse(args)
	fc := loadFileConfig(common.configPath)
	addr := firstNonEmpty(fc.Server.Listen, ":53")

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Println("stopped")
		os.Exit(1)
	}
	conn.Close()
	fmt.Println("running on", addr)
}

func cmdStop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	common := addCommonFlags(fs)
	fs.Parse(args)
	fc := loadFileConfig(common.configPath)

	pidStr, err := os.ReadFile(firstNonEmpty(fc.Server.Pidfile, "contractdb.pid"))
	if err != nil {
		log.Fatalf("no pidfile: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidStr)))
	if err != nil {
		log.Fatalf("bad pidfile: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		log.Fatalf("signal %d: %v", pid, err)
	}
	fmt.Println("sent SIGTERM to", pid)
}

func cmdHealthcheck(args []string) {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	common := addCommonFlags(fs)
	target := fs.String("target", "", "host:port to probe")
	zoneFlag := fs.String("zone", "", "zone to query")
	tsigKeys := fs.String("tsig-keys", "", "TSIG keys file or inline name:secret,...")
	fs.Parse(args)
	fc := loadFileConfig(common.configPath)

	addr := firstNonEmpty(*target, fc.Server.Listen, "127.0.0.1:53")
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	zone := strings.ToLower(dns.Fqdn(firstNonEmpty(*zoneFlag, fc.Server.Zone, "contractdb.internal.")))

	m := new(dns.Msg)
	m.SetQuestion("_contractdb.health."+zone, dns.TypeTXT)
	client := new(dns.Client)
	if spec := firstNonEmpty(*tsigKeys, os.Getenv("CONTRACTDB_TSIG_KEYS"), fc.Auth.TSIGKeysFile); spec != "" {
		provider, err := buildTSIG(spec)
		if err != nil {
			log.Fatalf("tsig: %v", err)
		}
		if provider != nil {
			names := make([]string, 0, len(provider.keys))
			for name := range provider.keys {
				names = append(names, name)
			}
			sort.Strings(names)
			m.SetTsig(names[0], dns.HmacSHA256, 300, time.Now().Unix())
			client.TsigProvider = provider
		}
	}
	resp, _, err := client.Exchange(m, addr)
	if err != nil {
		fmt.Println("unhealthy:", err)
		os.Exit(1)
	}
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == "UP" {
			fmt.Println("healthy")
			return
		}
	}
	fmt.Println("unhealthy: no UP record")
	os.Exit(1)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var pidfilePath string

func writePidfile(path string) {
	if path == "" {
		return
	}
	pidfilePath = path
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		log.Printf("pidfile: %v", err)
	}
}

func removePidfile() {
	if pidfilePath == "" {
		return
	}
	_ = os.Remove(pidfilePath)
	pidfilePath = ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
