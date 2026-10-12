package daemon

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// LeakGuard is the system firewall half of leak protection. Apply with an
// empty tunnel blocks the user's traffic except the local network; with a
// tunnel it also lets that traffic through the engine's own interface.
// Rules stay in the kernel when the helper exits, so a crash fails closed.
type LeakGuard interface {
	Supported() error
	Apply(tunnel string) error
	Release() error
}

type leakState struct {
	Enabled bool `json:"enabled"`
	Armed   bool `json:"armed"`
}

// LeakProtection arms on every profile start and disarms only on an explicit
// stop or when the user turns the setting off. Reloads, profile switches,
// engine failures, sleep and helper restarts all keep it armed.
type LeakProtection struct {
	Guard    LeakGuard
	StateDir string

	access  sync.Mutex
	state   leakState
	applied bool
	tunnel  string
	config  string
	lastErr string
}

const (
	leakStateFile   = "leak-protection.json"
	leakProfileFile = "leak-protection-profile.json"
)

// Load restores the persisted state. When the previous helper was armed, the
// block is applied before anything else and the last profile is returned so
// the caller can restart it.
func (p *LeakProtection) Load() (recoverProfile string) {
	p.access.Lock()
	defer p.access.Unlock()
	p.state = leakState{Enabled: true}
	if content, err := os.ReadFile(filepath.Join(p.StateDir, leakStateFile)); err == nil {
		_ = json.Unmarshal(content, &p.state)
	}
	if !p.state.Armed {
		return ""
	}
	p.applyLocked("")
	if content, err := os.ReadFile(filepath.Join(p.StateDir, leakProfileFile)); err == nil {
		p.config = string(content)
	}
	return p.config
}

func (p *LeakProtection) BeforeStart(config string) error {
	p.access.Lock()
	defer p.access.Unlock()
	// Remembered even when disabled, so enabling later can find the tunnel.
	p.config = config
	if !p.state.Enabled {
		return nil
	}
	if err := p.Guard.Supported(); err != nil {
		p.lastErr = err.Error()
		return err
	}
	// Block first: a reload or profile switch removes the tunnel for a moment.
	if err := p.applyLocked(""); err != nil {
		return err
	}
	p.state.Armed = true
	return p.saveLocked()
}

// Stopped is called only for an explicit user stop.
func (p *LeakProtection) Stopped() error {
	p.access.Lock()
	defer p.access.Unlock()
	wasActive := p.state.Armed || p.applied
	p.state.Armed = false
	p.config = ""
	var err error
	if wasActive {
		err = p.releaseLocked()
	}
	return errors.Join(err, p.saveLocked())
}

func (p *LeakProtection) Set(enabled bool, running bool, tunnel string, config string) error {
	p.access.Lock()
	defer p.access.Unlock()
	p.state.Enabled = enabled
	if !enabled {
		var err error
		if p.state.Armed || p.applied {
			err = p.releaseLocked()
		}
		p.state.Armed = false
		p.config = ""
		return errors.Join(err, p.saveLocked())
	}
	if running {
		if err := p.Guard.Supported(); err != nil {
			p.lastErr = err.Error()
			return errors.Join(err, p.saveLocked())
		}
		p.state.Armed = true
		if config != "" {
			p.config = config
		}
		if err := p.applyLocked(tunnel); err != nil {
			return errors.Join(err, p.saveLocked())
		}
	}
	return p.saveLocked()
}

// Reconcile follows the engine: the tunnel is allowed only while the service
// is started and its interface exists. Anything else blocks.
func (p *LeakProtection) Reconcile(started bool, tunnel string) {
	p.access.Lock()
	defer p.access.Unlock()
	if !p.state.Armed {
		if p.applied {
			_ = p.releaseLocked()
		}
		return
	}
	if !started {
		tunnel = ""
	}
	_ = p.applyLocked(tunnel)
}

func (p *LeakProtection) Status() *LeakProtectionStatus {
	p.access.Lock()
	defer p.access.Unlock()
	status := &LeakProtectionStatus{
		Supported: p.Guard.Supported() == nil,
		Enabled:   p.state.Enabled,
		Armed:     p.state.Armed,
		// Only rules that are actually loaded block anything; a failed
		// guard is reported through Error, never as protection.
		Blocking: p.state.Armed && p.applied && p.tunnel == "",
		Tunnel:   p.tunnel,
		Error:    p.lastErr,
	}
	return status
}

func (p *LeakProtection) Config() string {
	p.access.Lock()
	defer p.access.Unlock()
	return p.config
}

func (p *LeakProtection) applyLocked(tunnel string) error {
	if err := p.Guard.Apply(tunnel); err != nil {
		p.lastErr = err.Error()
		return err
	}
	p.applied = true
	p.tunnel = tunnel
	p.lastErr = ""
	return nil
}

func (p *LeakProtection) releaseLocked() error {
	err := p.Guard.Release()
	if err != nil {
		p.lastErr = err.Error()
		return err
	}
	p.applied = false
	p.tunnel = ""
	p.lastErr = ""
	return nil
}

func (p *LeakProtection) saveLocked() error {
	content, _ := json.Marshal(p.state)
	if err := writePrivateFile(filepath.Join(p.StateDir, leakStateFile), content); err != nil {
		return err
	}
	profilePath := filepath.Join(p.StateDir, leakProfileFile)
	if !p.state.Armed || p.config == "" {
		if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	// Kept in the root-only state directory beside the Tailscale state.
	return writePrivateFile(profilePath, []byte(p.config))
}

func writePrivateFile(path string, content []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// TunnelInterface finds the interface carrying the profile's TUN address.
func TunnelInterface(config string) string {
	var profile struct {
		Inbounds []struct {
			Type    string `json:"type"`
			Address any    `json:"address"`
		} `json:"inbounds"`
	}
	if json.Unmarshal([]byte(config), &profile) != nil {
		return ""
	}
	var wanted []netip.Addr
	for _, inbound := range profile.Inbounds {
		if inbound.Type != "tun" {
			continue
		}
		var addresses []string
		switch value := inbound.Address.(type) {
		case string:
			addresses = append(addresses, value)
		case []any:
			for _, item := range value {
				if text, ok := item.(string); ok {
					addresses = append(addresses, text)
				}
			}
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address); err == nil {
				wanted = append(wanted, prefix.Addr())
			}
		}
	}
	if len(wanted) == 0 {
		return ""
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || !strings.HasPrefix(iface.Name, "utun") {
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
			for _, candidate := range wanted {
				if ip.Unmap() == candidate {
					return iface.Name
				}
			}
		}
	}
	return ""
}
