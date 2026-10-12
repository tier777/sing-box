package daemon

import (
	"context"
	stdjson "encoding/json"
	"sort"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Only an allowlist of presentation fields leaves the service process. Never
// expose config JSON, passwords, cookies, tokens, server credentials or pins.
func newRouteCatalog(options option.Options) *RouteCatalog {
	raw, _ := json.Marshal(options)
	var config map[string]any
	_ = stdjson.Unmarshal(raw, &config)
	all := map[string]map[string]any{}
	order := []string{}
	for _, section := range []string{"outbounds", "endpoints"} {
		entries, _ := config[section].([]any)
		for _, entry := range entries {
			value, _ := entry.(map[string]any)
			tag, _ := value["tag"].(string)
			if tag != "" {
				all[tag] = value
				order = append(order, tag)
			}
		}
	}
	var directFallback func(string, map[string]bool) bool
	directFallback = func(tag string, seen map[string]bool) bool {
		if seen[tag] {
			return true
		} // cycles are never certified as VPN-only
		seen[tag] = true
		defer delete(seen, tag)
		value, found := all[tag]
		if !found {
			return true
		}
		if value["type"] == "direct" {
			return true
		}
		members, _ := value["outbounds"].([]any)
		for _, member := range members {
			name, _ := member.(string)
			if directFallback(name, seen) {
				return true
			}
		}
		return false
	}
	destinations := map[string][]string{}
	route, _ := config["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	for _, rule := range rules {
		r, _ := rule.(map[string]any)
		tag, _ := r["outbound"].(string)
		if tag == "" {
			continue
		}
		var labels []string
		var walk func(map[string]any)
		walk = func(node map[string]any) {
			for _, key := range []string{"domain", "domain_suffix", "ip_cidr", "rule_set"} {
				switch v := node[key].(type) {
				case string:
					labels = append(labels, v)
				case []any:
					for _, item := range v {
						if text, ok := item.(string); ok {
							labels = append(labels, text)
						}
					}
				}
			}
			children, _ := node["rules"].([]any)
			for _, child := range children {
				if c, ok := child.(map[string]any); ok {
					walk(c)
				}
			}
		}
		walk(r)
		destinations[tag] = append(destinations[tag], labels...)
	}
	catalog := &RouteCatalog{Routes: []*RouteDescriptor{}}
	for _, tag := range order {
		value := all[tag]
		kind, _ := value["type"].(string)
		if kind == "block" || kind == "dns" {
			continue
		}
		bind, _ := value["bind_interface"].(string)
		detour, _ := value["detour"].(string)
		labels := destinations[tag]
		sort.Strings(labels)
		catalog.Routes = append(catalog.Routes, &RouteDescriptor{Tag: tag, Type: kind, BindInterface: bind, Detour: detour, Destinations: labels, DirectFallback: directFallback(tag, map[string]bool{})})
	}
	return catalog
}

func (s *StartedService) GetRouteCatalog(ctx context.Context, _ *emptypb.Empty) (*RouteCatalog, error) {
	if err := s.waitForStarted(ctx); err != nil {
		return nil, err
	}
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.instance == nil || s.instance.routeCatalog == nil {
		return nil, status.Error(codes.Unavailable, "active route catalog unavailable")
	}
	result := proto.Clone(s.instance.routeCatalog).(*RouteCatalog)
	result.StartedAt = s.startedAt.UnixMilli()
	return result, nil
}
