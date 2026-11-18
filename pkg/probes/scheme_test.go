package probes

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// hostPort splits a test server's 127.0.0.1:port address.
func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a.IP.String(), a.Port
}

// lineServer greets every connection with banner, like an SMTP or FTP server.
func lineServer(t *testing.T, banner string) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(banner))
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// A probe that names a port speaks that port's scheme, not the primary
// port's: a plain-HTTP or SMTP port of an https target is not handshaked as
// TLS, and a TLS port of an http target is.
func TestProbeUsesProbedPortScheme(t *testing.T) {
	handler := func(body string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
	}
	tlsSrv := httptest.NewUnstartedServer(handler("over-tls"))
	tlsSrv.Config.ErrorLog = log.New(io.Discard, "", 0) // the old code sent it cleartext
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(handler("in-clear"))
	defer plainSrv.Close()
	host, tlsPort := hostPort(t, tlsSrv.Listener.Addr().String())
	_, plainPort := hostPort(t, plainSrv.Listener.Addr().String())
	smtpPort := lineServer(t, "220 mail ESMTP ready\r\n")
	ctx := context.Background()
	// container 8443/https, 8080/http, 25/smtp, published on the test ports.
	pm := map[int]int{8443: tlsPort, 8080: plainPort, 25: smtpPort}
	schemes := map[int]string{8443: "https", 8080: "http", 25: ""}

	httpsPrimary := Target{Host: host, Port: tlsPort, Scheme: "https", PortMap: pm, Schemes: schemes}
	httpPrimary := Target{Host: host, Port: plainPort, Scheme: "http", PortMap: pm, Schemes: schemes}

	cases := []struct {
		name string
		p    contract.Probe
		tgt  Target
	}{
		{"https primary, default port", contract.Probe{HTTP: &contract.HTTPProbe{BodyMatches: "over-tls"}}, httpsPrimary},
		{"https primary, http port", contract.Probe{HTTP: &contract.HTTPProbe{Port: 8080, BodyMatches: "in-clear"}}, httpsPrimary},
		{"http primary, https port", contract.Probe{HTTP: &contract.HTTPProbe{Port: 8443, BodyMatches: "over-tls"}}, httpPrimary},
		{"https primary, net on smtp port", contract.Probe{Net: &contract.NetProbe{Port: 25, Steps: []contract.NetStep{{Expect: "^220"}}}}, httpsPrimary},
		{"https primary, net on default port", contract.Probe{Net: &contract.NetProbe{Steps: []contract.NetStep{
			{Send: "GET / HTTP/1.0\r\n\r\n", Expect: "over-tls"}}}}, httpsPrimary},
		{"http primary, net on https port", contract.Probe{Net: &contract.NetProbe{Port: 8443, Steps: []contract.NetStep{
			{Send: "GET / HTTP/1.0\r\n\r\n", Expect: "over-tls"}}}}, httpPrimary},
		{"http primary, net tls: true", contract.Probe{Net: &contract.NetProbe{TLS: true, Port: 8443, Steps: []contract.NetStep{
			{Send: "GET / HTTP/1.0\r\n\r\n", Expect: "over-tls"}}}}, Target{Host: host, Port: plainPort, Scheme: "http", PortMap: pm}},
	}
	for _, tc := range cases {
		if r := Run(ctx, tc.p, tc.tgt); !r.OK {
			t.Errorf("%s: %s (transport=%v)", tc.name, r.Detail, r.Transport)
		}
	}
}
