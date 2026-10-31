package main

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// renderPFRules builds the leak-protection anchor. Matching by socket owner
// limits it to the controlling user's apps and their DNS resolver; the root
// engine itself keeps reaching its servers and the DIRECT outbound.
func renderPFRules(users []int, tunnel string, local []netip.Prefix) string {
	userList := make([]string, 0, len(users))
	for _, uid := range users {
		userList = append(userList, fmt.Sprint(uid))
	}
	owners := "{ " + strings.Join(userList, " ") + " }"
	var v4, v6 []string
	for _, prefix := range local {
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.String())
		} else {
			v6 = append(v6, prefix.String())
		}
	}
	var b strings.Builder
	b.WriteString("# SFM Routes leak protection. Managed by the engine.\n")
	b.WriteString("pass quick on lo0 all no state\n")
	if tunnel != "" {
		fmt.Fprintf(&b, "pass out quick on %s all no state\n", tunnel)
	}
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67 no state\n")
	b.WriteString("pass out quick inet6 proto udp from any port 546 to any port 547 no state\n")
	if tunnel == "" {
		// Without the tunnel, even a local resolver would forward names to the provider.
		fmt.Fprintf(&b, "block return out quick proto { tcp udp } to any port { 53 853 } user %s\n", owners)
	}
	fmt.Fprintf(&b, "pass out quick inet to { 224.0.0.0/4 255.255.255.255 169.254.0.0/16%s } no state\n", joinPrefixes(v4))
	fmt.Fprintf(&b, "pass out quick inet6 to { ff00::/8 fe80::/10%s } no state\n", joinPrefixes(v6))
	fmt.Fprintf(&b, "block return out quick proto { tcp udp } user %s\n", owners)
	return b.String()
}

// Existing floating PF states are checked before rules. Clear only states
// originating at this Mac when protection is first armed, so an earlier
// direct/other-VPN socket cannot bypass the new block. Our pass rules create
// no new states that could outlive a tunnel change.
func stateResetCommands(addresses []netip.Addr) [][]string {
	var commands [][]string
	seen := make(map[netip.Addr]bool)
	for _, address := range addresses {
		address = address.Unmap().WithZone("")
		if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || seen[address] {
			continue
		}
		seen[address] = true
		commands = append(commands, []string{"-k", address.String()})
	}
	return commands
}

func localStateAddresses() []netip.Addr {
	interfaces, _ := net.Interfaces()
	var result []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			if network, ok := address.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(network.IP); ok {
					result = append(result, ip)
				}
			}
		}
	}
	return result
}

func joinPrefixes(prefixes []string) string {
	if len(prefixes) == 0 {
		return ""
	}
	return " " + strings.Join(prefixes, " ")
}

// localNetworks lists on-link subnets of physical interfaces. Tunnels of this
// or any other VPN are excluded: reaching them would be a leak, not LAN use.
func localNetworks() []netip.Prefix {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[netip.Prefix]bool{}
	var result []netip.Prefix
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isTunnelName(iface.Name) {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			bits, _ := ipNet.Mask.Size()
			if ip.IsLinkLocalUnicast() || (ip.Is4() && bits < 16) || (ip.Is6() && bits < 48) {
				continue
			}
			prefix := netip.PrefixFrom(ip, bits).Masked()
			if !seen[prefix] {
				seen[prefix] = true
				result = append(result, prefix)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func isTunnelName(name string) bool {
	for _, prefix := range []string{"utun", "ipsec", "ppp", "tun", "tap", "gif", "stf", "awdl", "llw", "anpi", "bridge"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
