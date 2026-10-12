//go:build darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	pfctlPath    = "/sbin/pfctl"
	pfAnchor     = "com.apple/050.SFMRoutes"
	pfSystemConf = "/etc/pf.conf"
	pfMainAnchor = `anchor "com.apple/*"`
)

var pfTokenPattern = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// pfGuard keeps its rules in a child of the system "com.apple/*" anchor and
// holds its own pf enable reference, so other tools releasing theirs do not
// switch protection off.
type pfGuard struct {
	users     []int
	tokenPath string

	access sync.Mutex
	loaded string
	token  string
}

func newLeakGuard(uid int, stateDir string) *pfGuard {
	users := []int{uid}
	if resolver, err := user.Lookup("_mdnsresponder"); err == nil {
		if id, err := strconv.Atoi(resolver.Uid); err == nil {
			users = append(users, id)
		}
	} else {
		users = append(users, 65)
	}
	guard := &pfGuard{users: users, tokenPath: filepath.Join(stateDir, "pf-token")}
	if content, err := os.ReadFile(guard.tokenPath); err == nil {
		guard.token = strings.TrimSpace(string(content))
	}
	return guard
}

func (g *pfGuard) Supported() error {
	if os.Geteuid() != 0 {
		return errors.New("leak protection requires the installed root helper")
	}
	if _, err := os.Stat(pfctlPath); err != nil {
		return fmt.Errorf("pfctl unavailable: %w", err)
	}
	return nil
}

func (g *pfGuard) Apply(tunnel string) error {
	g.access.Lock()
	defer g.access.Unlock()
	rules := renderPFRules(g.users, tunnel, localNetworks())
	enabled, err := g.enableLocked()
	if err != nil {
		return err
	}
	if rules == g.loaded && !enabled {
		return nil
	}
	if err = g.ensureMainAnchorLocked(); err != nil {
		return err
	}
	if _, err = pfctl([]byte(rules), "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	g.loaded = rules
	return nil
}

func (g *pfGuard) Release() error {
	g.access.Lock()
	defer g.access.Unlock()
	var result error
	if _, err := pfctl(nil, "-a", pfAnchor, "-F", "rules"); err != nil {
		result = err
	}
	g.loaded = ""
	if g.token != "" {
		// A stale token after reboot is harmless; pf reports it unknown.
		_, _ = pfctl(nil, "-X", g.token)
		g.token = ""
		_ = os.Remove(g.tokenPath)
	}
	return result
}

// enableLocked takes this helper's pf reference when it has none, or when pf
// was disabled behind its back (e.g. a reboot with a stale token file). It
// reports whether pf was just enabled, which requires reloading the anchor.
func (g *pfGuard) enableLocked() (bool, error) {
	if g.token != "" && pfEnabled() {
		return false, nil
	}
	output, err := pfctl(nil, "-E")
	if err != nil {
		return false, err
	}
	match := pfTokenPattern.FindSubmatch(output)
	if match == nil {
		return false, fmt.Errorf("pfctl -E returned no reference token")
	}
	g.token = string(match[1])
	if err = os.WriteFile(g.tokenPath, []byte(g.token), 0o600); err != nil {
		return true, err
	}
	g.loaded = ""
	return true, nil
}

// The system ruleset only evaluates child anchors through "com.apple/*". If
// pf was never loaded since boot, load the system's own configuration.
func (g *pfGuard) ensureMainAnchorLocked() error {
	output, err := pfctl(nil, "-s", "rules")
	if err == nil && bytes.Contains(output, []byte(pfMainAnchor)) {
		return nil
	}
	system, readErr := os.ReadFile(pfSystemConf)
	if readErr != nil || !bytes.Contains(system, []byte(pfMainAnchor)) {
		return fmt.Errorf("the system pf configuration has no %s anchor; leak protection cannot attach", pfMainAnchor)
	}
	if _, err = pfctl(nil, "-f", pfSystemConf); err != nil {
		return err
	}
	output, err = pfctl(nil, "-s", "rules")
	if err != nil || !bytes.Contains(output, []byte(pfMainAnchor)) {
		return fmt.Errorf("pf did not load the %s anchor", pfMainAnchor)
	}
	return nil
}

func pfEnabled() bool {
	output, err := pfctl(nil, "-s", "info")
	return err == nil && bytes.Contains(output, []byte("Status: Enabled"))
}

func pfctl(stdin []byte, args ...string) ([]byte, error) {
	command := exec.Command(pfctlPath, args...)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
