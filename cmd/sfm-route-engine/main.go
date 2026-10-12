package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/service"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The helper starts idle. Installation alone NEVER creates a tunnel or changes
// DNS/routes. The user starts a selected profile from the unprivileged app.
func main() {
	check := flag.String("check-profile", "", "validate a profile without installing or starting a tunnel")
	uid := flag.Int("uid", -1, "Mac user allowed to control this engine")
	root := flag.String("state-dir", "/Library/Application Support/SFMRoutes/State", "private engine state")
	socket := flag.String("socket-dir", "", "per-user control socket directory")
	testMode := flag.Bool("unprivileged-test", false, "isolated test, does not grant TUN privileges")
	flag.Parse()
	if *check != "" {
		content, err := os.ReadFile(*check)
		if err != nil {
			fatal(err)
		}
		if len(content) > 2<<20 {
			fatal(errors.New("oversized profile"))
		}
		if err = daemon.ValidateLocalProfile(string(content)); err != nil {
			fatal(err)
		}
		ctx := include.Context(context.Background())
		service.MustRegister[adapter.SecurityPolicy](ctx, denyPrivilegedFeatures{})
		instance := daemon.NewStartedService(daemon.ServiceOptions{Context: ctx, Handler: localPlatform{}, LogMaxLines: 10})
		defer instance.Close()
		if err = instance.CheckConfig(ctx, string(content)); err != nil {
			fatal(err)
		}
		fmt.Println("profile valid (not started)")
		return
	}
	if *uid < 0 || (*uid == 0 && !*testMode) {
		fatal(fmt.Errorf("an explicit non-root controller UID is required"))
	}
	if os.Geteuid() != 0 && !*testMode {
		fatal(fmt.Errorf("run the installed helper with administrator privileges"))
	}
	if *socket == "" {
		*socket = fmt.Sprintf("/var/run/io.github.tier777.sfmroutes-%d", *uid)
	}
	for _, p := range []string{*root, *socket} {
		if err := os.MkdirAll(p, 0700); err != nil {
			fatal(err)
		}
	}
	// The user may traverse the control directory, but cannot replace its socket.
	for _, p := range []string{*root, *socket} {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			fatal(fmt.Errorf("unsafe helper directory: %s", p))
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
			fatal(fmt.Errorf("helper directory must be owned by engine user and not writable by others: %s", p))
		}
	}
	if err := os.Chmod(*root, 0700); err != nil {
		fatal(err)
	}
	if err := os.Chmod(*socket, 0711); err != nil {
		fatal(err)
	}
	if err := os.Chdir(*root); err != nil {
		fatal(err)
	}
	path := filepath.Join(*socket, "command.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			fatal(fmt.Errorf("control path is not a socket"))
		}
		if peer, dialErr := net.DialTimeout("unix", path, time.Second); dialErr == nil {
			peer.Close()
			fatal(fmt.Errorf("another engine is already listening"))
		}
		if err = os.Remove(path); err != nil {
			fatal(err)
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		fatal(err)
	}
	defer listener.Close()
	defer os.Remove(path)
	if os.Geteuid() == 0 {
		if err = os.Chown(path, *uid, -1); err != nil {
			fatal(err)
		}
	}
	if err = os.Chmod(path, 0600); err != nil {
		fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	engineContext := include.Context(ctx)
	service.MustRegister[adapter.SecurityPolicy](engineContext, denyPrivilegedFeatures{})
	engineService := daemon.NewStartedService(daemon.ServiceOptions{Context: engineContext, Handler: localPlatform{}, LogMaxLines: 500})
	defer engineService.Close()
	control := &daemon.LocalEngineController{Service: engineService}
	if !*testMode {
		control.Protection = &daemon.LeakProtection{Guard: newLeakGuard(*uid, *root), StateDir: *root}
		// A previous helper that was armed (crash, reinstall, reboot) blocks
		// first, then brings the same profile back.
		if profile := control.Protection.Load(); profile != "" {
			go func() {
				if _, err := control.StartProfile(ctx, &daemon.LocalProfileRequest{ConfigContent: profile}); err != nil {
					fmt.Fprintln(os.Stderr, "restore armed profile:", err)
				}
			}()
		}
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					control.ReconcileProtection()
				}
			}
		}()
	}
	server := daemon.NewServer(engineService, "") // access is enforced by the Unix socket
	daemon.RegisterLocalEngineServer(server, control)
	go func() {
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, err)
			cancel()
		}
	}()
	// CLI has no NEProvider.wake callback. Detect missed wall-clock ticks on wake.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		last := time.Now().Unix()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				if now.Unix()-last > 10 {
					_, _ = control.Wake(ctx, &emptypb.Empty{})
				}
				last = now.Unix()
			}
		}
	}()
	<-ctx.Done()
	server.Stop()
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

type localPlatform struct{}

func (localPlatform) WriteDebugMessage(string) {}
func (localPlatform) ConnectSSHAgent() (int32, error) {
	return -1, errors.New("SSH agent forwarding is disabled in the local engine")
}

type denyPrivilegedFeatures struct{}

func (denyPrivilegedFeatures) CheckFeature(_ context.Context, feature string) error {
	return fmt.Errorf("local engine disables privileged feature %s", feature)
}
