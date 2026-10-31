package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// LeakProtection arms on every profile start. Stopping the VPN keeps the
// firewall armed; only disabling protection releases it. Reloads, profile
// switches, engine failures, sleep and helper restarts also keep it armed.
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

// Stopped blocks before the tunnel is removed. Forget the recovery profile so
// a helper restart restores the block without restarting a deliberately stopped VPN.
func (p *LeakProtection) Stopped() error {
	p.access.Lock()
	defer p.access.Unlock()
	if p.state.Enabled {
		if err := p.Guard.Supported(); err != nil {
			p.lastErr = err.Error()
			return err
		}
		if err := p.applyLocked(""); err != nil {
			return err
		}
		p.state.Armed = true
	} else if p.applied {
		if err := p.releaseLocked(); err != nil {
			return err
		}
	}
	p.config = ""
	return p.saveLocked()
}

func (p *LeakProtection) Set(enabled bool, running bool, tunnel string, config string) error {
	p.access.Lock()
	defer p.access.Unlock()
	if !enabled {
		if p.state.Armed || p.applied {
			if err := p.releaseLocked(); err != nil {
				return err
			}
		}
		p.state.Enabled = false
		p.state.Armed = false
		p.config = ""
		return p.saveLocked()
	}
	if err := p.Guard.Supported(); err != nil {
		p.lastErr = err.Error()
		return err
	}
	if !running {
		tunnel = ""
	}
	if err := p.applyLocked(tunnel); err != nil {
		return err
	}
	p.state.Enabled = true
	p.state.Armed = true
	if config != "" {
		p.config = config
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
