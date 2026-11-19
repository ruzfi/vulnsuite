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
	"maps"
	"net"
	"regexp"
	"slices"
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
	Host   string
	Port   int
	Scheme string // http | https; anything else is treated as http for http probes
	// Schemes, when non-nil, is the scheme of each declared container port
	// ("http", "https", or "" for raw TCP). A probe that names a port speaks
	// that port's scheme, not the primary port's: an https primary must not
	// make a probe of a plain-HTTP or SMTP port handshake TLS, nor a plain
	// primary send cleartext to a TLS port. A probe on the default port, or on
	// a port missing from Schemes, uses Scheme.
	Schemes   map[int]string
	Container string
	Exec      ExecFunc
	// PortMap, when non-nil, translates a container port named by a probe
	// (`port:`) to the port to dial from here: in host exposure mode a probe's
	// port is a container port, published on a different host port. A port
	// missing from a non-nil map is not reachable from here. Port (the default
	// when a probe names none) is already the address to dial.
	PortMap map[int]int
}

// dialPort resolves the port a probe dials: 0 means the target's own Port; a
// named port goes through PortMap when one is set.
func (t Target) dialPort(p int) (int, error) {
	if p == 0 {
		return t.Port, nil
	}
	if t.PortMap == nil {
		return p, nil
	}
	if hp, ok := t.PortMap[p]; ok {
		return hp, nil
	}
	return 0, fmt.Errorf("container port %d is not published to the host, so it cannot be probed from here", p)
}

// portScheme is the scheme of the port a probe names (0 = the default port).
func (t Target) portScheme(p int) string {
	if p != 0 && t.Schemes != nil {
		if s, ok := t.Schemes[p]; ok {
			return s
		}
	}
	return t.Scheme
}

// Result is the outcome of one probe.
type Result struct {
	Kind    string        `json:"kind"`
	OK      bool          `json:"ok"`
	Detail  string        `json:"detail"`
	Elapsed time.Duration `json:"elapsed"`
	// Transport is set when the probe could not reach the target at all (dial
	// failure), as opposed to reaching it and finding an assertion unmet. It
	// lets a caller tell "I can't get to this address from here" from "the
	// service answered but is in the wrong state".
	Transport bool `json:"transport,omitempty"`
}

// connError marks a probe failure as a transport failure: the target could not
// be reached (dial error). Its message is the wrapped error's, so probe detail
// text is unchanged; only Run inspects the type.
type connError struct{ err error }

func (e *connError) Error() string { return e.err.Error() }
func (e *connError) Unwrap() error { return e.err }

// HTTPResponse is a parsed raw HTTP response.
type HTTPResponse struct {
	Status  int
	Headers map[string]string // lower-cased names; repeated headers are joined with ", "
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
	defer closeOnDone(ctx, conn)()
	// The deadline covers the TLS handshake too: a peer that accepts and then
	// stalls must not outlive the probe timeout.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if useTLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec // knowingly-vulnerable targets have junk certs
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tc
	}
	if _, err := io.WriteString(conn, head+body); err != nil {
		return nil, err
	}
	blob := readResponse(conn, method) // a timeout mid-read still yields what arrived
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return parseHTTP(blob)
}

// maxResponse caps how much of a response is read (the body cap plus room for
// the head).
const maxResponse = MaxBody + 64*1024

// readResponse reads one HTTP response from conn. It stops as soon as the
// response is complete by its own framing (Content-Length, the final chunk, or
// a status that has no body) instead of waiting for the server to close the
// connection: a keep-alive server that ignores Connection: close would
// otherwise hold every probe for its full timeout. Without framing it reads
// until EOF, the deadline, or maxResponse.
func readResponse(conn io.Reader, method string) []byte {
	var blob []byte
	buf := make([]byte, 32*1024)
	for len(blob) < maxResponse {
		n, err := conn.Read(buf)
		blob = append(blob, buf[:n]...)
		if n > 0 && responseComplete(blob, method) {
			break
		}
		if err != nil {
			break
		}
	}
	if len(blob) > maxResponse {
		blob = blob[:maxResponse]
	}
	return blob
}

// responseComplete reports whether blob holds a whole response by its framing.
// It is conservative: anything it cannot frame is read to EOF as before.
func responseComplete(blob []byte, method string) bool {
	text := string(blob)
	headEnd, sep := strings.Index(text, "\r\n\r\n"), 4
	if headEnd < 0 {
		if headEnd, sep = strings.Index(text, "\n\n"), 2; headEnd < 0 {
			return false // the head is not complete yet
		}
	}
	head, body := text[:headEnd], text[headEnd+sep:]
	m := statusRe.FindStringSubmatch(head)
	if m == nil {
		return false
	}
	status, _ := strconv.Atoi(m[1])
	if status >= 100 && status < 200 {
		// An interim response (100 Continue): the final one follows it.
		return responseComplete([]byte(body), method)
	}
	if strings.EqualFold(method, "HEAD") || status == 204 || status == 304 {
		return true
	}
	var te, cl string
	haveCL := false
	for _, line := range strings.Split(head, "\n")[1:] {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "transfer-encoding":
			te = strings.TrimSpace(v)
		case "content-length":
			cl, haveCL = strings.TrimSpace(v), true
		}
	}
	switch {
	case te != "":
		return strings.EqualFold(te, "chunked") && chunkedComplete(body)
	case haveCL:
		n, err := strconv.Atoi(cl)
		return err == nil && n >= 0 && len(body) >= n
	}
	return false // delimited by close
}

// chunkedComplete reports whether a chunked body has reached its last chunk
// and the (possibly empty) trailer section after it.
func chunkedComplete(s string) bool {
	for {
		nl := strings.Index(s, "\r\n")
		if nl < 0 {
			return false
		}
		sizeStr, _, _ := strings.Cut(s[:nl], ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil || size < 0 {
			return false
		}
		s = s[nl+2:]
		if size == 0 {
			// Trailers, if any, end with an empty line.
			return strings.HasPrefix(s, "\r\n") || strings.Contains(s, "\r\n\r\n")
		}
		if int64(len(s)) < size+2 {
			return false
		}
		s = s[size+2:]
	}
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
	if status >= 100 && status < 200 && statusRe.MatchString(body) {
		// Skip an interim response (100 Continue) to the final one.
		return parseHTTP([]byte(body))
	}
	resp := &HTTPResponse{Status: status, Headers: map[string]string{}}
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name, val := strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if prev, dup := resp.Headers[name]; dup {
			// RFC 9110 5.3: repeated fields combine as a comma-separated list,
			// so every Set-Cookie (etc.) stays visible to header_matches/absent.
			val = prev + ", " + val
		}
		resp.Headers[name] = val
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
		// Cut a chunk extension first, then trim: RFC 9112 7.1.1 allows
		// whitespace before the ';' ("5 ;x=y"), as chunkedComplete does.
		sizeStr, _, _ := strings.Cut(s[:nl], ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
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
	// A pattern that does not compile must fail the probe: an *_absent check
	// would otherwise "not match" and pass, verifying a state that may be
	// wrong.
	if err := checkPatterns(p); err != nil {
		return Result{Kind: p.Kind(), Detail: err.Error(), Elapsed: time.Since(started)}
	}
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
	case "net":
		ok, detail, err = runNet(ctx, p.Net, t)
	default:
		err = fmt.Errorf("unknown probe kind %q", p.Kind())
	}
	transport := false
	if err != nil {
		ok, detail = false, err.Error()
		var ce *connError
		transport = errors.As(err, &ce)
	}
	return Result{Kind: p.Kind(), OK: ok, Detail: detail, Transport: transport, Elapsed: time.Since(started)}
}

func runHTTP(ctx context.Context, s *contract.HTTPProbe, t Target) (bool, string, error) {
	path := s.RawPath
	if path == "" {
		path = s.Path
	}
	if path == "" {
		path = "/"
	}
	port, err := t.dialPort(s.Port)
	if err != nil {
		return false, "", fmt.Errorf("%s -> %v", path, err)
	}
	resp, err := RawHTTP(ctx, t.Host, port, s.Method, path, s.Headers, s.Body, secs(s.Timeout, 10*time.Second), t.portScheme(s.Port) == "https")
	if err != nil {
		return false, "", &connError{fmt.Errorf("%s -> %v", path, err)}
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
	dport, err := t.dialPort(s.Port)
	if err != nil {
		// Not reachable from here at all: neither "open" nor "closed" can be
		// asserted, so a closed: probe must not pass by default.
		return false, "", fmt.Errorf("tcp %d -> %v", port, err)
	}
	timeout := secs(s.Timeout, 10*time.Second)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(dport)))
	if err == nil {
		defer conn.Close()
	}
	// A port proxy accepts for a port nothing listens on, then closes: that
	// connection does not make the port open.
	var early []byte
	listening := err == nil
	if listening {
		early, listening = checkListener(conn, min(ListenerGrace, timeout))
	}
	if s.Closed {
		// Asserting the port is NOT open: a dial error (refused/unreachable) is
		// the expected result; a successful connection is the failure.
		if err != nil {
			return true, fmt.Sprintf("tcp %d closed as expected (%v)", port, err), nil
		}
		if !listening {
			return true, fmt.Sprintf("tcp %d closed as expected (%s)", port, errNotListening), nil
		}
		return false, fmt.Sprintf("tcp %d is open but was expected to be closed", port), nil
	}
	if err != nil {
		return false, "", &connError{fmt.Errorf("tcp %d -> %v", port, err)}
	}
	if !listening {
		return false, "", &connError{fmt.Errorf("tcp %d -> %v", port, errNotListening)}
	}
	defer closeOnDone(ctx, conn)()
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	banner := string(early)
	if s.Send != "" {
		if _, err := io.WriteString(conn, s.Send); err != nil {
			return false, "", fmt.Errorf("tcp %d send -> %v", port, err)
		}
	}
	// The listener check may already hold the greeting. Read on when a reply
	// to send is due, when nothing arrived yet, or when the greeting so far
	// does not match banner_matches (it may continue in later segments). A
	// timeout yields an empty banner, which may be the expected result.
	if s.Send != "" || len(early) == 0 || (s.BannerMatches != "" && !matchDotAll(s.BannerMatches, banner)) {
		banner = readUntilFrom(conn, early, 4096, s.BannerMatches, deadline)
	}
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if s.BannerMatches != "" && !matchDotAll(s.BannerMatches, banner) {
		return false, fmt.Sprintf("tcp %d banner %q !~ /%s/", port, trunc(banner, 60), s.BannerMatches), nil
	}
	return true, fmt.Sprintf("tcp %d -> %q", port, trunc(banner, 60)), nil
}

func runNet(ctx context.Context, s *contract.NetProbe, t Target) (bool, string, error) {
	port := s.Port
	if port == 0 {
		port = t.Port
	}
	dport, err := t.dialPort(s.Port)
	if err != nil {
		return false, "", fmt.Errorf("net %d -> %v", port, err)
	}
	timeout := secs(s.Timeout, 15*time.Second)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(dport)))
	if err != nil {
		return false, "", &connError{fmt.Errorf("net %d -> %v", port, err)}
	}
	defer conn.Close()
	defer closeOnDone(ctx, conn)()
	// Set before the handshake so a stalled TLS peer is bounded by the timeout.
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	// tls: true forces TLS; otherwise the probed port's own scheme decides, so a
	// dialogue with a plain port (SMTP, FTP) of an https target stays plain.
	if s.TLS || t.portScheme(s.Port) == "https" {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: t.Host}) //nolint:gosec // knowingly-vulnerable targets
		if err := tc.HandshakeContext(ctx); err != nil {
			return false, "", fmt.Errorf("net %d tls -> %v", port, err)
		}
		conn = tc
	}
	var log strings.Builder
	for i, step := range s.Steps {
		if step.Send != "" {
			if _, err := io.WriteString(conn, step.Send); err != nil {
				return false, "", fmt.Errorf("net step %d send -> %v", i+1, err)
			}
			log.WriteString("> " + oneline(step.Send) + "\n")
		}
		if step.NoRead {
			continue
		}
		readN := step.Read
		if readN <= 0 {
			readN = 4096
		}
		// A timeout yields what arrived, which the expect then judges.
		resp := readUntil(conn, readN, step.Expect, deadline)
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		log.WriteString("< " + oneline(resp) + "\n")
		if step.Expect != "" && !matchDotAll(step.Expect, resp) {
			return false, fmt.Sprintf("net step %d: %q !~ /%s/\n%s", i+1, trunc(resp, 80), step.Expect, log.String()), nil
		}
		if step.ExpectAbsent != "" && matchDotAll(step.ExpectAbsent, resp) {
			return false, fmt.Sprintf("net step %d: %q unexpectedly ~ /%s/\n%s", i+1, trunc(resp, 80), step.ExpectAbsent, log.String()), nil
		}
	}
	return true, "net dialogue ok (" + strconv.Itoa(len(s.Steps)) + " steps)", nil
}

// quietGap is how long readUntil waits for more data once some has arrived. A
// server that sends its reply in several segments (an FTP "220-" multi-line
// banner) sends them back to back; a gap this long means the reply is over.
var quietGap = 500 * time.Millisecond

// readUntil reads from conn until expect (a probe regex, dot matches newline)
// matches what arrived, max bytes have arrived, the connection ends, or
// deadline passes. Once something has arrived it also stops after quietGap
// without more data. Without expect it reads to the same limits, so a reply
// sent in several segments is judged whole and its tail is not left for the
// next step's read. The quiet gap never extends past deadline.
func readUntil(conn net.Conn, max int, expect string, deadline time.Time) string {
	return readUntilFrom(conn, nil, max, expect, deadline)
}

// readUntilFrom is readUntil continuing from bytes already read (got), which
// count toward max and toward matching expect.
func readUntilFrom(conn net.Conn, got []byte, max int, expect string, deadline time.Time) string {
	defer func() { _ = conn.SetReadDeadline(deadline) }()
	_ = conn.SetReadDeadline(deadline)
	got = append([]byte(nil), got...)
	buf := make([]byte, max)
	for len(got) < max {
		n, err := conn.Read(buf[:max-len(got)])
		got = append(got, buf[:n]...)
		if n > 0 && expect != "" && matchDotAll(expect, string(got)) {
			break
		}
		if err != nil {
			break // EOF, reset, the quiet gap or the deadline
		}
		if n > 0 {
			gap := time.Now().Add(quietGap)
			if gap.After(deadline) {
				gap = deadline
			}
			_ = conn.SetReadDeadline(gap)
		}
	}
	return string(got)
}

// closeOnDone closes conn when ctx ends, so a cancelled probe (Ctrl-C) stops at
// once instead of waiting out its own read deadline. Call the returned
// function to stop watching.
func closeOnDone(ctx context.Context, conn net.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return func() { stop() }
}

func oneline(s string) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return trunc(s, 120)
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

// ListenerGrace is how long a new connection is watched for the immediate close
// that means nothing is listening behind a port proxy (see checkListener).
// Docker's proxy closes within a few milliseconds of the backend refusing.
var ListenerGrace = 300 * time.Millisecond

var errNotListening = errors.New("connection accepted, then closed with no data: nothing is listening yet (the host port is held by a port proxy)")

// checkListener tells whether something listens behind a fresh connection. In
// host exposure mode the published port is held by Docker's port proxy, which
// accepts a connection whether or not anything listens in the container and
// closes it as soon as its own connection to the container is refused. So a
// connection that ends (EOF or reset) within grace without sending a byte
// means nothing is listening yet. Data means something listens, and so does
// silence until grace passes: many servers (HTTP, redis, databases) wait for
// the client to speak first. The bytes read are returned so a banner is kept.
// The read deadline is cleared on return.
func checkListener(conn net.Conn, grace time.Duration) ([]byte, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(grace))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil, true
	}
	return nil, false
}

// Reachability tells whether host:port is open, refused, or unreachable. A
// connection a port proxy accepts and then closes at once counts as refused:
// the address answers, but nothing listens yet.
func Reachability(host string, port int, timeout time.Duration) Reach {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err == nil {
		defer conn.Close()
		if _, ok := checkListener(conn, min(ListenerGrace, timeout)); !ok {
			return Refused
		}
		return Open
	}
	if isConnRefused(err) {
		return Refused
	}
	return Unreachable
}

// wsaeConnRefused is Windows' WSAECONNREFUSED. On Windows a refused TCP dial
// reports this value, which differs from syscall.ECONNREFUSED there, so
// errors.Is(err, syscall.ECONNREFUSED) misses it. It is harmless on other
// platforms, where a refused dial never carries errno 10061.
const wsaeConnRefused = syscall.Errno(10061)

// isConnRefused reports whether err is a TCP "connection refused", portably
// across Unix and Windows.
func isConnRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaeConnRefused
}

// WaitForPort polls until something listens on host:port or the deadline
// passes. A connection that a port proxy accepts and closes at once does not
// count (see checkListener).
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
			_, ok := checkListener(conn, ListenerGrace)
			conn.Close()
			if ok {
				return true
			}
		}
		if !pause(ctx, 500*time.Millisecond) {
			return false
		}
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
		if !pause(ctx, time.Second) {
			return false
		}
	}
	return false
}

// pause sleeps for d, returning false early when ctx ends.
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// checkPatterns compiles every regex a probe uses, as matchDotAll will.
func checkPatterns(p contract.Probe) error {
	type field struct{ name, pat string }
	var fs []field
	switch {
	case p.HTTP != nil:
		fs = append(fs, field{"body_matches", p.HTTP.BodyMatches}, field{"body_absent", p.HTTP.BodyAbsent})
		for _, name := range slices.Sorted(maps.Keys(p.HTTP.HeaderMatches)) {
			fs = append(fs, field{"header_matches." + name, p.HTTP.HeaderMatches[name]})
		}
	case p.Exec != nil:
		fs = append(fs, field{"stdout_matches", p.Exec.StdoutMatches})
	case p.TCP != nil:
		fs = append(fs, field{"banner_matches", p.TCP.BannerMatches})
	case p.Net != nil:
		for i, st := range p.Net.Steps {
			fs = append(fs, field{fmt.Sprintf("steps[%d].expect", i), st.Expect},
				field{fmt.Sprintf("steps[%d].expect_absent", i), st.ExpectAbsent})
		}
	}
	for _, f := range fs {
		if f.pat == "" {
			continue
		}
		if _, err := regexp.Compile("(?s)" + f.pat); err != nil {
			return fmt.Errorf("invalid regex in %s probe %s: %v", p.Kind(), f.name, err)
		}
	}
	return nil
}

// matchDotAll matches pat in dot-all mode. Run rejects patterns that do not
// compile before any probe runs, so the error branch is unreachable there.
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
