//go:build linux

// Command probe is the network test tool inside the stand-in app image of
// scripts/docker-checks. Every check prints one line that starts with
// "result=<word>" and exits 0, so run.sh decides PASS or FAIL from the word.
// Usage errors exit 64.
//
//	probe serve [addr]                      HTTP 200 on every path (stand-in app)
//	probe http [-noproxy|-proxy URL] [-body] URL   GET, through the proxy environment by default
//	probe tcp [-timeout d] host:port        direct TCP connect, no proxy
//	probe dns [-server ip:port] [-type A|AAAA|TXT] name
//	probe rawsock                           try AF_INET/SOCK_RAW and AF_PACKET sockets
//	probe transparent                       try IP_TRANSPARENT on a UDP socket
//	probe freebind-dns SRC DST:PORT name    UDP DNS query from a foreign source via IP_FREEBIND
//	probe spoof-dns SRC DST:PORT name       UDP DNS query with a forged IPv4 header (raw socket)
//
// "{rand}" in a name or URL is replaced by 12 random hex characters.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ipFreebind    = 15 // IP_FREEBIND
	ipTransparent = 19 // IP_TRANSPARENT
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "serve":
		serve(args)
	case "http":
		httpCmd(args)
	case "tcp":
		tcpCmd(args)
	case "dns":
		dnsCmd(args)
	case "rawsock":
		rawsockCmd()
	case "transparent":
		transparentCmd()
	case "freebind-dns":
		freebindCmd(args)
	case "spoof-dns":
		spoofCmd(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: probe serve|http|tcp|dns|rawsock|transparent|freebind-dns|spoof-dns ...")
	os.Exit(64)
}

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func expand(s string) string {
	for strings.Contains(s, "{rand}") {
		s = strings.Replace(s, "{rand}", randHex(12), 1)
	}
	return s
}

func serve(args []string) {
	addr := ":8080"
	if len(args) > 0 {
		addr = args[0]
	}
	host, _ := os.Hostname()
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "ok %s\n", host)
		}),
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; os.Exit(0) }()
	fmt.Fprintln(os.Stderr, "probe serving on", addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func short(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func classify(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return "dns-error"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "error"
}

func errName(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		switch en {
		case syscall.EPERM:
			return "EPERM"
		case syscall.EACCES:
			return "EACCES"
		case syscall.EINVAL:
			return "EINVAL"
		case syscall.EADDRNOTAVAIL:
			return "EADDRNOTAVAIL"
		case syscall.ENETUNREACH:
			return "ENETUNREACH"
		}
		return "errno" + strconv.Itoa(int(en))
	}
	return strings.ReplaceAll(short(err), " ", "_")
}

func httpCmd(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	noProxy := fs.Bool("noproxy", false, "ignore HTTP_PROXY and friends")
	timeout := fs.Duration("timeout", 12*time.Second, "request timeout")
	body := fs.Bool("body", false, "print the response body after the result line")
	proxy := fs.String("proxy", "", "use this proxy URL for every request (ignores NO_PROXY)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	target := expand(fs.Arg(0))
	var connectStatus int
	var connectEgress string
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
			connectStatus = res.StatusCode
			connectEgress = res.Header.Get("X-Sealed-Egress")
			return nil
		},
	}
	switch {
	case *noProxy:
		tr.Proxy = nil
	case *proxy != "":
		pu, err := url.Parse(*proxy)
		if err != nil {
			usage()
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	c := &http.Client{
		Transport:     tr,
		Timeout:       *timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := c.Get(target)
	if err != nil {
		if connectStatus != 0 && connectStatus != 200 {
			word := "status"
			if connectStatus == 403 && connectEgress == "blocked" {
				word = "blocked"
			}
			fmt.Printf("result=%s status=%d egress=%s via=connect\n", word, connectStatus, connectEgress)
			return
		}
		fmt.Printf("result=%s err=%q\n", classify(err), short(err))
		return
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	eg := res.Header.Get("X-Sealed-Egress")
	word := "ok"
	switch {
	case res.StatusCode == 403 && eg == "blocked":
		word = "blocked"
	case res.StatusCode >= 400:
		word = "status"
	}
	fmt.Printf("result=%s status=%d egress=%s\n", word, res.StatusCode, eg)
	if *body {
		_, _ = os.Stdout.Write(b)
		fmt.Println()
	}
}

func tcpCmd(args []string) {
	fs := flag.NewFlagSet("tcp", flag.ExitOnError)
	timeout := fs.Duration("timeout", 4*time.Second, "connect timeout")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	c, err := net.DialTimeout("tcp", fs.Arg(0), *timeout)
	if err == nil {
		c.Close()
		fmt.Println("result=connected")
		return
	}
	fmt.Printf("result=%s err=%q\n", classify(err), short(err))
}

func resolvConfServer() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				return net.JoinHostPort(f[1], "53")
			}
		}
	}
	return "127.0.0.11:53"
}

func buildQuery(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

var errShort = errors.New("short DNS message")

func skipName(m []byte, off int) (int, error) {
	for {
		if off >= len(m) {
			return 0, errShort
		}
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}

func parseResponse(m []byte, id uint16) (rcode int, tc bool, records []string, err error) {
	if len(m) < 12 {
		return 0, false, nil, errShort
	}
	if binary.BigEndian.Uint16(m) != id {
		return 0, false, nil, errors.New("DNS id mismatch")
	}
	flags := binary.BigEndian.Uint16(m[2:])
	rcode = int(flags & 0xF)
	tc = flags&0x0200 != 0
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		if off, err = skipName(m, off); err != nil {
			return
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off, err = skipName(m, off); err != nil {
			return
		}
		if off+10 > len(m) {
			return rcode, tc, records, errShort
		}
		typ := binary.BigEndian.Uint16(m[off:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return rcode, tc, records, errShort
		}
		rd := m[off : off+rdlen]
		switch {
		case typ == 1 && rdlen == 4, typ == 28 && rdlen == 16:
			records = append(records, net.IP(rd).String())
		case typ == 16:
			records = append(records, "txt:"+strconv.Itoa(rdlen))
		case typ == 5:
			records = append(records, "cname")
		}
		off += rdlen
	}
	return rcode, tc, records, nil
}

var rcodeNames = map[int]string{0: "noerror", 1: "formerr", 2: "servfail", 3: "nxdomain", 4: "notimp", 5: "refused"}

func dnsCmd(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	server := fs.String("server", "", "ip:port (default: first nameserver in /etc/resolv.conf)")
	timeout := fs.Duration("timeout", 4*time.Second, "reply timeout")
	qtypeName := fs.String("type", "A", "A, AAAA or TXT")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	qtypes := map[string]uint16{"A": 1, "AAAA": 28, "TXT": 16}
	qtype, ok := qtypes[*qtypeName]
	if !ok {
		usage()
	}
	name := expand(fs.Arg(0))
	srv := *server
	if srv == "" {
		srv = resolvConfServer()
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	conn, err := net.Dial("udp", srv)
	if err != nil {
		fmt.Printf("result=%s server=%s err=%q\n", classify(err), srv, short(err))
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))
	if _, err := conn.Write(buildQuery(id, name, qtype)); err != nil {
		fmt.Printf("result=%s server=%s err=%q\n", classify(err), srv, short(err))
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Printf("result=%s server=%s err=%q\n", classify(err), srv, short(err))
			return
		}
		rcode, tc, recs, perr := parseResponse(buf[:n], id)
		if perr != nil && perr.Error() == "DNS id mismatch" {
			continue
		}
		if perr != nil {
			fmt.Printf("result=error server=%s err=%q\n", srv, short(perr))
			return
		}
		word, ok := rcodeNames[rcode]
		if !ok {
			word = "rcode-" + strconv.Itoa(rcode)
		}
		if rcode == 0 {
			word = "noanswer"
			if len(recs) > 0 {
				word = "answer"
			}
		}
		fmt.Printf("result=%s server=%s name=%s tc=%t records=%s\n", word, srv, name, tc, strings.Join(recs, ","))
		return
	}
}

func trySocket(domain, typ, proto int) string {
	fd, err := syscall.Socket(domain, typ, proto)
	if err != nil {
		return errName(err)
	}
	syscall.Close(fd)
	return "ok"
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func rawsockCmd() {
	raw := trySocket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	rawUDP := trySocket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	pkt := trySocket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	word := "denied"
	if raw == "ok" || rawUDP == "ok" || pkt == "ok" {
		word = "allowed"
	}
	fmt.Printf("result=%s inet_raw=%s inet_raw_udp=%s packet=%s\n", word, raw, rawUDP, pkt)
}

func transparentCmd() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Printf("result=error err=%s\n", errName(err))
		return
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, ipTransparent, 1); err != nil {
		fmt.Printf("result=denied err=%s\n", errName(err))
		return
	}
	fmt.Println("result=allowed")
}

func parseSpoofArgs(args []string) (src, dst net.IP, port int, name string) {
	if len(args) != 3 {
		usage()
	}
	src = net.ParseIP(args[0]).To4()
	h, p, err := net.SplitHostPort(args[1])
	if err != nil || src == nil {
		usage()
	}
	dst = net.ParseIP(h).To4()
	port, err = strconv.Atoi(p)
	if err != nil || dst == nil {
		usage()
	}
	return src, dst, port, expand(args[2])
}

func freebindCmd(args []string) {
	src, dst, port, name := parseSpoofArgs(args)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Printf("result=error err=%s\n", errName(err))
		return
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, ipFreebind, 1); err != nil {
		fmt.Printf("result=denied stage=setsockopt err=%s\n", errName(err))
		return
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], src)
	if err := syscall.Bind(fd, &sa); err != nil {
		fmt.Printf("result=denied stage=bind err=%s\n", errName(err))
		return
	}
	var da syscall.SockaddrInet4
	copy(da.Addr[:], dst)
	da.Port = port
	if err := syscall.Sendto(fd, buildQuery(0x5151, name, 1), 0, &da); err != nil {
		fmt.Printf("result=denied stage=send err=%s\n", errName(err))
		return
	}
	fmt.Printf("result=sent name=%s\n", name)
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func spoofCmd(args []string) {
	src, dst, port, name := parseSpoofArgs(args)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Printf("result=denied stage=socket err=%s\n", errName(err))
		return
	}
	defer syscall.Close(fd)
	payload := buildQuery(0x5252, name, 1)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 40000+uint16(time.Now().UnixNano()%20000))
	binary.BigEndian.PutUint16(udp[2:], uint16(port))
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	pseudo := make([]byte, 0, 12+len(udp))
	pseudo = append(pseudo, src...)
	pseudo = append(pseudo, dst...)
	pseudo = append(pseudo, 0, 17)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(udp)))
	pseudo = append(pseudo, udp...)
	cs := checksum(pseudo)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], cs)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	var da syscall.SockaddrInet4
	copy(da.Addr[:], dst)
	if err := syscall.Sendto(fd, append(ip, udp...), 0, &da); err != nil {
		fmt.Printf("result=denied stage=send err=%s\n", errName(err))
		return
	}
	fmt.Printf("result=sent name=%s\n", name)
}
