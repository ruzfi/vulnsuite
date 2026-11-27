package docker

import (
	"net/http"
	"testing"
)

// #153: connecting and the TLS handshake are bounded, so an unreachable
// tcp:// daemon fails instead of hanging; there is no response-header
// timeout (builds, pulls, logs and waits stream through the same transport).
func TestTransportTimeouts(t *testing.T) {
	for _, host := range []string{"tcp://10.255.255.1:2375", "unix:///nonexistent.sock"} {
		c, err := NewEndpoint(Endpoint{Host: host})
		if err != nil {
			t.Fatal(err)
		}
		tr := c.http.Transport.(*http.Transport)
		if tr.DialContext == nil || tr.TLSHandshakeTimeout != DialTimeout || tr.ResponseHeaderTimeout != 0 {
			t.Errorf("%s: transport dial=%v tls=%v header=%v", host, tr.DialContext != nil, tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout)
		}
		if c.http.Timeout != 0 {
			t.Errorf("%s: client-wide timeout %v would cut streams", host, c.http.Timeout)
		}
	}
}
