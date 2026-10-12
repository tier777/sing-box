package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"regexp"
	"strings"
	"sync"
	"time"
)

type LocalEngineController struct {
	UnimplementedLocalEngineServer
	Service    *StartedService
	wakeAccess sync.Mutex
	lastWake   time.Time
}

func (e *LocalEngineController) StartProfile(ctx context.Context, r *LocalProfileRequest) (*emptypb.Empty, error) {
	if r == nil || len(r.ConfigContent) == 0 || len(r.ConfigContent) > 2<<20 {
		return nil, status.Error(codes.InvalidArgument, "missing or oversized profile")
	}
	if err := ValidateLocalProfile(r.ConfigContent); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Never tear down a working instance for a malformed replacement.
	if err := e.Service.CheckConfig(ctx, r.ConfigContent); err != nil {
		return nil, err
	}
	if err := e.Service.StartOrReloadService(ctx, r.ConfigContent, nil); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// Root profiles intentionally support a small set of networking features.
// File-backed input, external services and executable plugins are excluded
// before even CheckConfig (which can open log files during construction).
var localStateName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func ValidateLocalProfile(content string) error {
	var config map[string]any
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		return fmt.Errorf("local engine requires a JSON profile: %w", err)
	}
	allowedSections := map[string]bool{"$schema": true, "log": true, "dns": true, "certificate": true, "inbounds": true, "outbounds": true, "endpoints": true, "route": true, "experimental": true}
	for key := range config {
		if !allowedSections[key] {
			return fmt.Errorf("local engine does not allow section %q", key)
		}
	}
	allowed := map[string]map[string]bool{
		"inbounds":  {"tun": true},
		"outbounds": {"direct": true, "hysteria2": true, "hysteria": true, "http": true, "socks": true, "shadowsocks": true, "selector": true, "urltest": true, "block": true, "dns": true},
		"endpoints": {"tailscale": true, "openconnect": true, "wireguard": true},
	}
	for section, types := range allowed {
		entries, _ := config[section].([]any)
		for _, entry := range entries {
			fields, _ := entry.(map[string]any)
			kind, _ := fields["type"].(string)
			if !types[kind] {
				return fmt.Errorf("local engine does not allow %s type %q", section, kind)
			}
		}
	}
	if experimental, ok := config["experimental"].(map[string]any); ok {
		for key := range experimental {
			if key != "cache_file" {
				return fmt.Errorf("experimental option %q is disabled in local engine profiles", key)
			}
		}
		if cache, exists := experimental["cache_file"]; exists {
			if _, ok := cache.(map[string]any); !ok {
				return fmt.Errorf("cache_file must be an object with default helper storage")
			}
		}
	}
	var walk func(any, string) error
	walk = func(value any, parent string) error {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "ssh_server" && child != nil && child != false {
					return fmt.Errorf("privileged Tailscale SSH server is disabled")
				}
				if key == "state_directory" {
					name, ok := child.(string)
					if !ok || !localStateName.MatchString(name) {
						return fmt.Errorf("state_directory must be a single helper-local name containing letters, digits, underscore or hyphen")
					}
					continue
				}
				// cache_file is an object at this exact location, not a filesystem name.
				if key == "cache_file" && parent == "experimental" {
					if err := walk(child, key); err != nil {
						return err
					}
					continue
				}
				if key == "output" || key == "home" || key == "external_ui" || key == "directory" || strings.HasSuffix(key, "_directory") || key == "path" || strings.HasSuffix(key, "_file") || strings.HasSuffix(key, "_files") || strings.HasSuffix(key, "_path") && key != "process_path" {
					return fmt.Errorf("file-based option %q is disabled in local engine profiles", key)
				}
				if err := walk(child, key); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := walk(child, parent); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(config, "")
}
func (e *LocalEngineController) StopProfile(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	if err := e.Service.CloseService(); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
func (e *LocalEngineController) State(context.Context, *emptypb.Empty) (*ServiceStatus, error) {
	e.Service.serviceAccess.RLock()
	defer e.Service.serviceAccess.RUnlock()
	return proto.Clone(e.Service.serviceStatus).(*ServiceStatus), nil
}
func (e *LocalEngineController) Wake(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	e.wakeAccess.Lock()
	defer e.wakeAccess.Unlock()
	// App and helper sleep detection may arrive together. Only one reset is needed.
	if time.Since(e.lastWake) < 5*time.Second {
		return &emptypb.Empty{}, nil
	}
	e.Service.lifecycleAccess.Lock()
	defer e.Service.lifecycleAccess.Unlock()
	e.lastWake = time.Now()
	e.Service.serviceAccess.Lock()
	e.Service.serviceStatus.NetworkEpoch = e.lastWake.UnixMilli()
	e.Service.serviceAccess.Unlock()
	i := e.Service.Instance()
	if i != nil && i.Box() != nil {
		i.Box().CloseIdleConnections()
		i.Box().Network().ResetNetwork(context.Background())
	}
	return &emptypb.Empty{}, nil
}
