package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeGuard struct {
	calls     []string
	failApply bool
}

func (g *fakeGuard) Supported() error { return nil }
func (g *fakeGuard) Apply(tunnel string) error {
	if g.failApply {
		return errors.New("pf unavailable")
	}
	g.calls = append(g.calls, "apply:"+tunnel)
	return nil
}
func (g *fakeGuard) Release() error { g.calls = append(g.calls, "release"); return nil }

func TestLeakProtectionStaysArmedUntilExplicitStop(t *testing.T) {
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
	if s := p.Status(); s.Armed || s.Blocking {
		t.Fatalf("explicit stop must disarm: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(dir, leakProfileFile)); !os.IsNotExist(err) {
		t.Fatal("profile copy must be removed after stop")
	}
	want := []string{"apply:", "apply:utun9", "apply:", "release"}
	if !reflect.DeepEqual(guard.calls, want) {
		t.Fatalf("guard calls %v, want %v", guard.calls, want)
	}
	if (&LeakProtection{Guard: &fakeGuard{}, StateDir: dir}).Load() != "" {
		t.Fatal("stopped state must not restore a profile")
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
	if s := p.Status(); s.Armed || len(guard.calls) != 1 || guard.calls[0] != "release" {
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
