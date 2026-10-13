// Package probes proves a target is genuinely in its declared state.
//
// HTTP is spoken over a raw socket so traversal paths survive verbatim
// (high-level clients normalise the path and destroy the payload). Probes are
// independent of any scanner.
package probes

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// MaxBody caps how much of a response body is read.
const MaxBody = 256 * 1024

// UserAgent is sent with every HTTP probe.
const UserAgent = "vulnsuite-verify/1.0"

// ExecFunc runs a shell command inside a container and returns (exit code, output).
type ExecFunc func(ctx context.Context, container, command string, timeout time.Duration) (int, string, error)

// Target is where probes are sent.
type Target struct {
	Host      string
	Port      int
	Scheme    string // http | https; anything else is treated as http for http probes
	Container string
	Exec      ExecFunc
}

// Result is the outcome of one probe.
type Result struct {
	Kind    string        `json:"kind"`
	OK      bool          `json:"ok"`
	Detail  string        `json:"detail"`
	Elapsed time.Duration `json:"elapsed"`
}

// HTTPResponse is a parsed raw HTTP response.
type HTTPResponse struct {
	Status  int
	Headers map[string]string // lower-cased names
	Body    string
}

// RawHTTP sends a request verbatim and parses the response.
func RawHTTP(ctx context.Context, host string, port int, method, path string, headers map[string]string,
	body string, timeout time.Duration, useTLS bool) (*HTTPResponse, error) {
	if method == "" {
		method = "GET"
	}
	if path == "" {
		path = "/"
	}
	hostHdr := host
	if port != 80 && port != 443 {
		hostHdr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	hdrs := []string{"Host: " + hostHdr, "User-Agent: " + UserAgent, "Accept: */*", "Connection: close"}
	seen := map[string]bool{"host": true, "user-agent": true, "accept": true, "connection": true}
	for k, v := range headers {
		lk := strings.ToLower(k)
		if seen[lk] {
			// explicit header overrides the default of the same name
			for i, h := range hdrs {
				if strings.HasPrefix(strings.ToLower(h), lk+":") {
					hdrs[i] = k + ": " + v
				}
			}
			continue
		}
		seen[lk] = true
		hdrs = append(hdrs, k+": "+v)
	}
	if body != "" && !seen["content-length"] {
		hdrs = append(hdrs, "Content-Length: "+strconv.Itoa(len(body)))
	}
	head := method + " " + path + " HTTP/1.1\r\n" + strings.Join(hdrs, "\r\n") + "\r\n\r\n"

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if useTLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec // knowingly-vulnerable targets have junk certs
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tc
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, head+body); err != nil {
		return nil, err
	}
	blob, _ := io.ReadAll(io.LimitReader(conn, MaxBody+64*1024)) // a timeout mid-read still yields what arrived
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return parseHTTP(blob)
}

var statusRe = regexp.MustCompile(`^HTTP/\d(?:\.\d)?\s+(\d{3})`)

func parseHTTP(blob []byte) (*HTTPResponse, error) {
	text := string(blob)
	headEnd := strings.Index(text, "\r\n\r\n")
	sep := 4
	if headEnd < 0 {
		headEnd = strings.Index(text, "\n\n")
		sep = 2
	}
	var head, body string
	if headEnd < 0 {
		head, body = text, ""
	} else {
		head, body = text[:headEnd], text[headEnd+sep:]
	}
	sc := bufio.NewScanner(strings.NewReader(head))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	if !sc.Scan() {
		return nil, fmt.Errorf("bad status line")
	}
	line := sc.Text()
	m := statusRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("bad status line %q", line)
	}
	status, _ := strconv.Atoi(m[1])
	resp := &HTTPResponse{Status: status, Headers: map[string]string{}}
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok {
			resp.Headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if strings.EqualFold(resp.Headers["transfer-encoding"], "chunked") {
		body = dechunk(body)
	}
	if len(body) > MaxBody {
		body = body[:MaxBody]
	}
	resp.Body = body
	return resp, nil
}

// dechunk decodes a chunked body best-effort (a partial read still yields text).
func dechunk(s string) string {
	var out strings.Builder
	for {
		nl := strings.Index(s, "\r\n")
		if nl < 0 {
			out.WriteString(s)
			break
		}
		sizeStr := strings.TrimSpace(s[:nl])
		if i := strings.Index(sizeStr, ";"); i >= 0 {
			sizeStr = sizeStr[:i]
		}
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			out.WriteString(s)
			break
		}
		if size == 0 {
			break
		}
		s = s[nl+2:]
		if int64(len(s)) < size {
			out.WriteString(s)
			break
		}
		out.WriteString(s[:size])
		s = strings.TrimPrefix(s[size:], "\r\n")
	}
	return out.String()
}

func secs(f float64, def time.Duration) time.Duration {
	if f <= 0 {
		return def
	}
	return time.Duration(f * float64(time.Second))
}

// Run executes one probe against the target.
func Run(ctx context.Context, p contract.Probe, t Target) Result {
	started := time.Now()
	var ok bool
	var detail string
	var err error
	switch p.Kind() {
	case "http":
		ok, detail, err = runHTTP(ctx, p.HTTP, t)
	case "exec":
		ok, detail, err = runExec(ctx, p.Exec, t)
	case "tcp":
		ok, detail, err = runTCP(ctx, p.TCP, t)
	default:
		err = fmt.Errorf("unknown probe kind %q", p.Kind())
	}
	if err != nil {
		ok, detail = false, err.Error()
	}
	return Result{Kind: p.Kind(), OK: ok, Detail: detail, Elapsed: time.Since(started)}
}

func runHTTP(ctx context.Context, s *contract.HTTPProbe, t Target) (bool, string, error) {
	path := s.RawPath
	if path == "" {
		path = s.Path
	}
	if path == "" {
		path = "/"
	}
	resp, err := RawHTTP(ctx, t.Host, t.Port, s.Method, path, s.Headers, s.Body, secs(s.Timeout, 10*time.Second), t.Scheme == "https")
	if err != nil {
		return false, "", fmt.Errorf("%s -> %v", path, err)
	}
	var problems []string
	if s.Status != nil && resp.Status != *s.Status {
		problems = append(problems, fmt.Sprintf("status %d != %d", resp.Status, *s.Status))
	}
	if len(s.StatusIn) > 0 && !containsInt(s.StatusIn, resp.Status) {
		problems = append(problems, fmt.Sprintf("status %d not in %v", resp.Status, s.StatusIn))
	}
	if s.BodyMatches != "" && !matchDotAll(s.BodyMatches, resp.Body) {
		problems = append(problems, fmt.Sprintf("body !~ /%s/", s.BodyMatches))
	}
	if s.BodyAbsent != "" && matchDotAll(s.BodyAbsent, resp.Body) {
		problems = append(problems, fmt.Sprintf("body unexpectedly ~ /%s/", s.BodyAbsent))
	}
	for name, pat := range s.HeaderMatches {
		val, present := resp.Headers[strings.ToLower(name)]
		switch {
		case !present:
			problems = append(problems, fmt.Sprintf("header %s absent", name))
		case !matchDotAll(pat, val):
			problems = append(problems, fmt.Sprintf("header %s: %q !~ /%s/", name, val, pat))
		}
	}
	for _, name := range s.HeaderAbsent {
		if val, present := resp.Headers[strings.ToLower(name)]; present {
			problems = append(problems, fmt.Sprintf("header %s unexpectedly present: %q", name, val))
		}
	}
	if len(problems) > 0 {
		return false, fmt.Sprintf("%s -> %s", path, strings.Join(problems, "; ")), nil
	}
	return true, fmt.Sprintf("%s -> %d, ok", path, resp.Status), nil
}

func runExec(ctx context.Context, s *contract.ExecProbe, t Target) (bool, string, error) {
	if t.Exec == nil || t.Container == "" {
		return false, "", fmt.Errorf("exec probe: no exec backend / container")
	}
	code, out, err := t.Exec(ctx, t.Container, s.Run, secs(s.Timeout, 30*time.Second))
	if err != nil {
		return false, "", fmt.Errorf("exec %q -> %v", s.Run, err)
	}
	want := 0
	if s.ExpectExit != nil {
		want = *s.ExpectExit
	}
	var problems []string
	if code != want {
		problems = append(problems, fmt.Sprintf("exit %d != %d", code, want))
	}
	if s.StdoutMatches != "" && !matchDotAll(s.StdoutMatches, out) {
		problems = append(problems, fmt.Sprintf("stdout !~ /%s/", s.StdoutMatches))
	}
	if len(problems) > 0 {
		return false, fmt.Sprintf("exec %q -> %s", s.Run, strings.Join(problems, "; ")), nil
	}
	return true, fmt.Sprintf("exec %q -> ok", s.Run), nil
}

func runTCP(ctx context.Context, s *contract.TCPProbe, t Target) (bool, string, error) {
	port := s.Port
	if port == 0 {
		port = t.Port
	}
	timeout := secs(s.Timeout, 10*time.Second)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(port)))
	if err != nil {
		return false, "", fmt.Errorf("tcp %d -> %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if s.Send != "" {
		if _, err := io.WriteString(conn, s.Send); err != nil {
			return false, "", fmt.Errorf("tcp %d send -> %v", port, err)
		}
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf) // a timeout yields an empty banner, which may be the expected result
	banner := string(buf[:n])
	if s.BannerMatches != "" && !matchDotAll(s.BannerMatches, banner) {
		return false, fmt.Sprintf("tcp %d banner %q !~ /%s/", port, trunc(banner, 60), s.BannerMatches), nil
	}
	return true, fmt.Sprintf("tcp %d -> %q", port, trunc(banner, 60)), nil
}

// RunAll executes every probe; it reports overall success and a line per probe.
func RunAll(ctx context.Context, ps []contract.Probe, t Target) (bool, []Result) {
	ok := true
	results := make([]Result, 0, len(ps))
	for _, p := range ps {
		r := Run(ctx, p, t)
		results = append(results, r)
		ok = ok && r.OK
	}
	return ok, results
}

// FormatResults renders results one per line.
func FormatResults(rs []Result) string {
	var b strings.Builder
	for i, r := range rs {
		if i > 0 {
			b.WriteByte('\n')
		}
		if r.OK {
			b.WriteString("ok   ")
		} else {
			b.WriteString("FAIL ")
		}
		b.WriteString(r.Detail)
	}
	return b.String()
}

// Reach classifies a TCP connection attempt.
type Reach int

// Reachability outcomes.
const (
	Open        Reach = iota // connected
	Refused                  // the host answered, nothing listens yet
	Unreachable              // timeout / no route: not reachable from here
)

// Reachability tells whether host:port is open, refused, or unreachable.
func Reachability(host string, port int, timeout time.Duration) Reach {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err == nil {
		conn.Close()
		return Open
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Refused
	}
	return Unreachable
}

// WaitForPort polls until host:port accepts a TCP connection or the deadline passes.
func WaitForPort(ctx context.Context, host string, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// WaitForHTTP polls an HTTP path until it answers with the wanted status (0 = any).
func WaitForHTTP(ctx context.Context, host string, port int, scheme, path string, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		resp, err := RawHTTP(ctx, host, port, "GET", path, nil, "", 5*time.Second, scheme == "https")
		if err == nil && (want == 0 || resp.Status == want) {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func matchDotAll(pat, text string) bool {
	re, err := regexp.Compile("(?s)" + pat)
	if err != nil {
		return false
	}
	return re.MatchString(text)
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
