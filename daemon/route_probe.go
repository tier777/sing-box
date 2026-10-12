package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ProbeRoute is intentionally independent of the URLTest history: a cached
// latency (or an idle traffic counter) is not evidence of current connectivity.
func (s *StartedService) ProbeRoute(ctx context.Context, request *RouteProbeRequest) (*RouteProbeResult, error) {
	if request.OutboundTag == "" {
		return nil, status.Error(codes.InvalidArgument, "an explicit outbound is required")
	}
	target, err := validateProbeURL(request.TargetURL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err = s.waitForStarted(ctx); err != nil {
		return nil, err
	}
	s.serviceAccess.RLock()
	instance := s.instance
	s.serviceAccess.RUnlock()
	if instance == nil {
		return nil, status.Error(codes.Unavailable, "service stopped")
	}
	outbound, err := resolveOutbound(instance, request.OutboundTag)
	if err != nil {
		return nil, err
	}
	// DNS uses the running service's resolver, not the host's system resolver.
	resolved := dialer.NewResolveDialer(instance.ctx, outbound, true, "", adapter.DNSQueryOptions{}, 0)
	return probeRoute(ctx, request, target, resolved, adapter.RootPoolFromContext(instance.ctx)), nil
}

func validateProbeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || len(raw) > 2048 {
		return nil, status.Error(codes.InvalidArgument, "probe requires an HTTPS URL without credentials, query or fragment")
	}
	return u, nil
}

func probeRoute(ctx context.Context, request *RouteProbeRequest, target *url.URL, detour N.Dialer, roots *x509.CertPool) *RouteProbeResult {
	result := &RouteProbeResult{OutboundTag: request.OutboundTag, TargetURL: request.TargetURL, Stage: "connect"}
	started := time.Now()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		TLSHandshakeStart: func() { result.Stage = "tls" },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				result.Stage = "http"
			}
		},
	}))
	req.Header.Set("User-Agent", "SFM-Route-Health/1")
	resp, err := client.Do(req)
	result.CheckedAt = time.Now().UnixMilli()
	result.LatencyMs = time.Since(started).Milliseconds()
	if err != nil {
		// Do not return response bodies, cookies, authentication URLs or secrets.
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Reachable = true // TLS verified + HTTP response, even a site-side 403.
	result.Stage = "http"
	result.HttpStatus = int32(resp.StatusCode)
	// Exit metadata is only accepted from Cloudflare's verified trace endpoint.
	if (target.Hostname() == "www.cloudflare.com" || target.Hostname() == "1.1.1.1") && target.Path == "/cdn-cgi/trace" && resp.StatusCode == http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if readErr == nil {
			for _, line := range strings.Split(string(body), "\n") {
				key, value, _ := strings.Cut(line, "=")
				if key == "ip" && net.ParseIP(value) != nil {
					result.ExitIP = value
				}
				if key == "loc" && len(value) == 2 {
					result.Country = value
				}
			}
		}
	}
	return result
}
