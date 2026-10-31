//go:build with_gvisor

package tailscale

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
)

func TestConfiguredExitPeerPinsStableIdentity(t *testing.T) {
	a, b := key.NewNode().Public(), key.NewNode().Public()
	chosen := &ipnstate.PeerStatus{ID: tailcfg.StableNodeID("chosen"), PublicKey: a, ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.80.1.1")}}
	other := &ipnstate.PeerStatus{ID: tailcfg.StableNodeID("other"), PublicKey: b, ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.80.1.2")}}
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{a: chosen, b: other}}
	for _, selector := range []string{"id:chosen", "100.80.1.1"} {
		peer, err := configuredExitPeer(selector, status)
		if err != nil || peer.ID != chosen.ID {
			t.Fatalf("selection %q: %v %v", selector, peer, err)
		}
	}
	for _, selector := range []string{"id:missing", "id:", ""} {
		if _, err := configuredExitPeer(selector, status); err == nil {
			t.Fatalf("%q must not select another exit", selector)
		}
	}
	chosen.Expired = true
	if _, err := configuredExitPeer("id:chosen", status); err == nil {
		t.Fatal("expired key accepted")
	}
	chosen.Expired = false
	chosen.ExitNodeOption = false
	if _, err := configuredExitPeer("id:chosen", status); err == nil {
		t.Fatal("non-exit peer accepted")
	}
	if _, err := configuredExitPeer("id:chosen", nil); err == nil {
		t.Fatal("missing status accepted")
	}
}

func TestExitGateRejectsOldOrMissingLivePeer(t *testing.T) {
	a, b := key.NewNode().Public(), key.NewNode().Public()
	for _, destination := range []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")} {
		if !exitDestinationAllowed(&a, destination, a, true) {
			t.Fatal("selected live exit rejected")
		}
		if exitDestinationAllowed(nil, destination, a, true) || exitDestinationAllowed(&a, destination, b, true) || exitDestinationAllowed(&a, destination, a, false) {
			t.Fatal("old, alternative or missing exit allowed")
		}
	}
	if !exitDestinationAllowed(nil, netip.MustParseAddr("100.80.1.1"), key.NodePublic{}, false) {
		t.Fatal("tailnet peer should remain reachable")
	}
	if exitDestinationAllowed(&a, netip.Addr{}, a, true) {
		t.Fatal("invalid destination allowed")
	}
}

func TestProtectedExitCannotBeDisabledInPlace(t *testing.T) {
	endpoint := &Endpoint{exitNode: "id:chosen"}
	for _, target := range []string{"", "other"} {
		if endpoint.SetTailscaleExitNode(context.Background(), target) == nil {
			t.Fatal("protected choice changed without reload")
		}
	}
	endpoint.started.Store(true)
	// No wireguard engine exists in this test. Packets must be dropped before
	// reaching it while the requested exit has not installed matching routes.
	if err := endpoint.WritePackets([][]byte{nil, {0x60}, append([]byte{0x45}, make([]byte, 19)...)}); err != nil {
		t.Fatal(err)
	}
}
