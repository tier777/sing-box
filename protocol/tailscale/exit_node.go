//go:build with_gvisor

package tailscale

import (
	"net/netip"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/net/tsaddr"
	"github.com/sagernet/tailscale/types/key"
)

// id: selectors bind a saved choice to the peer's stable identity, rather than
// an IP/name that could later belong to a different machine.
func configuredExitPeer(selector string, status *ipnstate.Status) (*ipnstate.PeerStatus, error) {
	if status == nil {
		return nil, E.New("Tailscale status is unavailable")
	}
	var address netip.Addr
	stableID := strings.TrimPrefix(selector, "id:")
	if !strings.HasPrefix(selector, "id:") {
		prefs := new(ipn.Prefs)
		if err := prefs.SetExitNodeIP(selector, status); err != nil {
			return nil, err
		}
		address = prefs.ExitNodeIP
	}
	for _, peer := range status.Peer {
		if peer == nil {
			continue
		}
		match := strings.HasPrefix(selector, "id:") && string(peer.ID) == stableID && stableID != ""
		for _, ip := range peer.TailscaleIPs {
			if address.IsValid() && ip == address {
				match = true
			}
		}
		if match {
			if !peer.ExitNodeOption || peer.Expired || peer.PublicKey.IsZero() {
				return nil, E.New("selected peer is not an available exit-node identity")
			}
			return peer, nil
		}
	}
	return nil, E.New("configured exit node was not found; no alternative selected")
}

// WireGuard gets its peers from the same live per-peer routing source as
// LocalBackend.PeerForIP. An accepted preferences edit alone is insufficient:
// cached routes may still select the old exit while reconfiguration completes.
func exitDestinationAllowed(expected *key.NodePublic, destination netip.Addr, actual key.NodePublic, found bool) bool {
	if !destination.IsValid() {
		return false
	}
	if tsaddr.IsTailscaleIP(destination) {
		return true
	}
	return expected != nil && !expected.IsZero() && found && actual == *expected
}

func (t *Endpoint) allowExitDestination(destination netip.Addr) bool {
	if t.exitNode == "" {
		return true
	}
	expected := t.exitExpected.Load()
	if tsaddr.IsTailscaleIP(destination) {
		return true
	}
	if expected == nil || t.server == nil {
		return false
	}
	peer, found := t.server.ExportLocalBackend().PeerForIP(destination)
	if !found || peer.IsSelf {
		return false
	}
	return exitDestinationAllowed(expected, destination, peer.Node.Key(), true)
}
