package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type probeDialer struct {
	address string
	calls   int
	fail    bool
}

func (d *probeDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	d.calls++
	if d.fail {
		return nil, errors.New("selected VPN unavailable")
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}
func (*probeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func TestRouteProbeUsesOnlySelectedDialer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	d := &probeDialer{address: target.Host}
	result := probeRoute(context.Background(), &RouteProbeRequest{OutboundTag: "VPN", TargetURL: server.URL}, target, d, roots)
	if !result.Reachable || result.HttpStatus != 403 || result.CheckedAt == 0 || d.calls != 1 {
		t.Fatalf("unexpected probe: %+v, calls %d", result, d.calls)
	}
	d.fail = true
	result = probeRoute(context.Background(), &RouteProbeRequest{OutboundTag: "VPN", TargetURL: server.URL}, target, d, roots)
	if result.Reachable || d.calls != 2 {
		t.Fatal("failed VPN fell back to system dialer")
	}
}

func TestRouteProbeRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("sent HTTP before certificate verification") }))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	result := probeRoute(context.Background(), &RouteProbeRequest{OutboundTag: "VPN", TargetURL: server.URL}, target, &probeDialer{address: target.Host}, x509.NewCertPool())
	if result.Reachable || result.Stage != "tls" {
		t.Fatalf("unverified TLS accepted: %+v", result)
	}
}

func TestRouteProbeTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := probeRoute(ctx, &RouteProbeRequest{OutboundTag: "VPN", TargetURL: server.URL}, target, &probeDialer{address: target.Host}, roots)
	if result.Reachable || time.Since(started) > time.Second {
		t.Fatal("unbounded probe")
	}
}

func TestRouteProbeValidation(t *testing.T) {
	for _, target := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/?token=secret", "https://example.com/#token", "garbage"} {
		if _, err := validateProbeURL(target); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
}
