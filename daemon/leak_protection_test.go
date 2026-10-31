package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ownedTestTunnel struct {
	adapter.Inbound
	name string
	err  error
}

func (t ownedTestTunnel) Type() string                         { return "tun" }
func (t ownedTestTunnel) TunnelInterfaceName() (string, error) { return t.name, t.err }

func TestOwnedTunnelInterfaceFailsClosed(t *testing.T) {
	lookup := func(name string) (*net.Interface, error) {
		// An unrelated utun99 with the same IP is never enumerated or considered.
		if name != "utun8" {
			return nil, errors.New("not present")
		}
		return &net.Interface{Name: name, Flags: net.FlagUp}, nil
	}
	for _, tc := range []struct {
		name    string
		devices []adapter.Inbound
		want    string
	}{
		{"own device", []adapter.Inbound{ownedTestTunnel{name: "utun8"}}, "utun8"},
		{"missing device", []adapter.Inbound{ownedTestTunnel{name: "utun7"}}, ""},
		{"physical interface", []adapter.Inbound{ownedTestTunnel{name: "en0"}}, ""},
		{"failed device", []adapter.Inbound{ownedTestTunnel{err: errors.New("closed")}}, ""},
		{"ambiguous own devices", []adapter.Inbound{ownedTestTunnel{name: "utun8"}, ownedTestTunnel{name: "utun8"}}, ""},
		{"no device", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownedTunnelInterface(tc.devices, lookup); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := ownedTunnelInterface([]adapter.Inbound{ownedTestTunnel{name: "utun8"}}, func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name}, nil
	}); got != "" {
		t.Fatal("down device must block")
	}
}

type fakeGuard struct {
	calls       []string
	failApply   bool
	failRelease bool
}

func (g *fakeGuard) Supported() error { return nil }
func (g *fakeGuard) Apply(tunnel string) error {
	if g.failApply {
		return errors.New("pf unavailable")
	}
	g.calls = append(g.calls, "apply:"+tunnel)
	return nil
}
func (g *fakeGuard) Release() error {
	if g.failRelease {
		return errors.New("pf release failed")
	}
	g.calls = append(g.calls, "release")
	return nil
}

func TestLeakProtectionStaysArmedUntilDisabled(t *testing.T) {
	dir := t.TempDir()
	guard := &fakeGuard{}
	p := &LeakProtection{Guard: guard, StateDir: dir}
	if p.Load() != "" || !p.Status().Enabled {
		t.Fatal("fresh state must be enabled and idle")
	}
	if err := p.BeforeStart(`{"secret":"x"}`); err != nil {
		t.Fatal(err)
	}
	if s := p.Status(); !s.Armed || !s.Blocking {
		t.Fatalf("start must block until the tunnel exists: %+v", s)
	}
	info, err := os.Stat(filepath.Join(dir, leakProfileFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("armed profile must be private: %v %v", info, err)
	}
	p.Reconcile(true, "utun9")
	if s := p.Status(); s.Blocking || s.Tunnel != "utun9" {
		t.Fatalf("running tunnel must be allowed: %+v", s)
	}
	// Engine failure, reload or sleep: the service is not started.
	p.Reconcile(false, "utun9")
	if s := p.Status(); !s.Armed || !s.Blocking {
		t.Fatalf("lost service must fail closed: %+v", s)
	}
	// A restarted helper restores the block and the profile.
	restarted := &LeakProtection{Guard: &fakeGuard{}, StateDir: dir}
	if restarted.Load() != `{"secret":"x"}` || !restarted.Status().Blocking {
		t.Fatal("armed state must survive a helper restart")
	}
	if err := p.Stopped(); err != nil {
		t.Fatal(err)
	}
	if s := p.Status(); !s.Armed || !s.Blocking {
		t.Fatalf("explicit VPN stop must keep blocking: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(dir, leakProfileFile)); !os.IsNotExist(err) {
		t.Fatal("profile copy must be removed after stop")
	}
	stopped := &LeakProtection{Guard: &fakeGuard{}, StateDir: dir}
	if stopped.Load() != "" || !stopped.Status().Blocking {
		t.Fatal("a deliberately stopped VPN must remain blocked after restart, without reconnecting")
	}
	if err := p.Set(false, false, "", ""); err != nil {
		t.Fatal(err)
	}
	if s := p.Status(); s.Armed || s.Enabled || s.Blocking {
		t.Fatalf("separate disable must release: %+v", s)
	}
	want := []string{"apply:", "apply:utun9", "apply:", "apply:", "release"}
	if !reflect.DeepEqual(guard.calls, want) {
		t.Fatalf("guard calls %v, want %v", guard.calls, want)
	}
	disabled := &LeakProtection{Guard: &fakeGuard{}, StateDir: dir}
	if disabled.Load() != "" || disabled.Status().Armed || disabled.Status().Enabled {
		t.Fatal("explicitly disabled state must survive a restart")
	}
}

func TestLeakProtectionSetting(t *testing.T) {
	guard := &fakeGuard{}
	p := &LeakProtection{Guard: guard, StateDir: t.TempDir()}
	p.Load()
	if err := p.Set(false, false, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.BeforeStart("{}"); err != nil {
		t.Fatal(err)
	}
	p.Reconcile(true, "utun3")
	if s := p.Status(); s.Armed || len(guard.calls) != 0 {
		t.Fatalf("disabled protection must not touch pf: %+v %v", s, guard.calls)
	}
	// Turning it on while connected arms immediately with the live tunnel.
	if err := p.Set(true, true, "utun3", ""); err != nil {
		t.Fatal(err)
	}
	if s := p.Status(); !s.Armed || s.Blocking || s.Tunnel != "utun3" {
		t.Fatalf("enabling while running: %+v", s)
	}
	if err := p.Set(false, true, "utun3", ""); err != nil {
		t.Fatal(err)
	}
	if s := p.Status(); s.Armed || s.Enabled {
		t.Fatalf("disabling must disarm: %+v", s)
	}
	if err := p.Set(true, false, "utun3", ""); err != nil {
		t.Fatal(err)
	}
	if s := p.Status(); !s.Armed || !s.Blocking || s.Tunnel != "" {
		t.Fatalf("enabling while VPN is off must block immediately: %+v", s)
	}
}

func TestLeakProtectionFailedDisableStaysArmed(t *testing.T) {
	guard := &fakeGuard{}
	p := &LeakProtection{Guard: guard, StateDir: t.TempDir()}
	p.Load()
	if err := p.BeforeStart("{}"); err != nil {
		t.Fatal(err)
	}
	guard.failRelease = true
	if p.Set(false, false, "", "") == nil {
		t.Fatal("release failure must be reported")
	}
	if s := p.Status(); !s.Enabled || !s.Armed || !s.Blocking || s.Error == "" {
		t.Fatalf("failed disable must not be shown or saved as disabled: %+v", s)
	}
	restarted := &LeakProtection{Guard: &fakeGuard{}, StateDir: p.StateDir}
	if restarted.Load() != "{}" || !restarted.Status().Blocking {
		t.Fatal("failed disable lost persisted protection")
	}
}

func TestStopProfileRefusesToRemoveTunnelBeforeBlock(t *testing.T) {
	p := &LeakProtection{Guard: &fakeGuard{failApply: true}, StateDir: t.TempDir()}
	p.Load()
	// A nil service intentionally catches an attempt to tear it down before
	// the firewall is installed. No actual tunnel or network is used.
	controller := &LocalEngineController{Protection: p}
	_, err := controller.StopProfile(context.Background(), nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected refusal before closing tunnel: %v", err)
	}
}

func TestLeakProtectionRefusesStartWhenGuardFails(t *testing.T) {
	p := &LeakProtection{Guard: &fakeGuard{failApply: true}, StateDir: t.TempDir()}
	p.Load()
	if p.BeforeStart("{}") == nil {
		t.Fatal("start must be refused when the block cannot be installed")
	}
	if s := p.Status(); s.Armed || s.Error == "" {
		t.Fatalf("failure must be reported: %+v", s)
	}
}

func TestFailedGuardIsNotReportedAsBlocking(t *testing.T) {
	guard := &fakeGuard{}
	p := &LeakProtection{Guard: guard, StateDir: t.TempDir()}
	p.Load()
	if err := p.BeforeStart("{}"); err != nil {
		t.Fatal(err)
	}
	guard.failApply = true
	p.Reconcile(false, "")
	// The earlier block is still loaded in pf, so it still blocks.
	if s := p.Status(); !s.Blocking || s.Error == "" {
		t.Fatalf("a failed update must keep the loaded block and report the error: %+v", s)
	}
	restarted := &LeakProtection{Guard: &fakeGuard{failApply: true}, StateDir: p.StateDir}
	restarted.Load()
	if s := restarted.Status(); s.Blocking || !s.Armed || s.Error == "" {
		t.Fatalf("rules that never loaded must not be reported as blocking: %+v", s)
	}
}
