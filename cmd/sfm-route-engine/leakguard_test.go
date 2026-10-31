package main

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestPFRules(t *testing.T) {
	local := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8:1::/64")}
	allow := renderPFRules([]int{501, 65}, "utun7", local)
	block := renderPFRules([]int{501, 65}, "", local)
	for _, want := range []string{"pass out quick on utun7 all", "192.168.1.0/24", "2001:db8:1::/64", "user { 501 65 }"} {
		if !strings.Contains(allow, want) {
			t.Errorf("allow rules miss %q:\n%s", want, allow)
		}
	}
	if strings.Contains(allow, "port { 53 853 }") {
		t.Error("DNS to the local network must stay available while the tunnel runs")
	}
	if strings.Contains(block, "utun") || !strings.Contains(block, "port { 53 853 }") {
		t.Errorf("blocking rules must not allow any tunnel and must stop DNS:\n%s", block)
	}
	for _, rules := range []string{allow, block} {
		lines := strings.Split(strings.TrimSpace(rules), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "pass ") && !strings.HasSuffix(line, " no state") {
				t.Fatalf("a pass rule must not leave a floating state after tunnel removal: %s", line)
			}
		}
		if last := lines[len(lines)-1]; last != "block return out quick proto { tcp udp } user { 501 65 }" {
			t.Errorf("the user block must be the final rule, got %q", last)
		}
	}
}

func TestStateResetIsScopedToConcreteHostAddresses(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("192.168.1.7"), netip.MustParseAddr("100.111.11.30"),
		netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("192.168.1.7"),
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"),
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"),
		netip.MustParseAddr("224.0.0.1"), {},
	}
	want := [][]string{{"-k", "192.168.1.7"}, {"-k", "100.111.11.30"}, {"-k", "2001:db8::7"}}
	if got := stateResetCommands(addresses); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected state reset scope: %v", got)
	}
}

func TestOtherVPNInterfacesAreNotLocal(t *testing.T) {
	for _, name := range []string{"utun4", "ipsec0", "ppp0"} {
		if !isTunnelName(name) {
			t.Errorf("%s must not count as local network", name)
		}
	}
	for _, name := range []string{"en0", "en7"} {
		if isTunnelName(name) {
			t.Errorf("%s is a physical interface", name)
		}
	}
}
