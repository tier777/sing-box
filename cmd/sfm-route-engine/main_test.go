package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Runs only when given the freshly built helper. It never includes a TUN,
// remote endpoint, authentication or modification of system routes/DNS.
func TestIdleHelperLifecycle(t *testing.T) {
	binary := os.Getenv("SFM_TEST_ENGINE")
	if binary == "" {
		t.Skip("set SFM_TEST_ENGINE to test the packaged helper")
	}
	root, err := os.MkdirTemp("/private/tmp", "sfm-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socket := filepath.Join(root, "socket")
	state := filepath.Join(root, "state")
	command := exec.Command(binary, "--unprivileged-test", "--uid", strconv.Itoa(os.Getuid()), "--socket-dir", socket, "--state-dir", state)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	path := filepath.Join(socket, "command.sock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper never created socket: %s", output.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe socket permissions: %v %v", info, err)
	}
	conn, err := grpc.NewClient("passthrough:///local-engine-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := daemon.NewLocalEngineClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	get := func() *daemon.ServiceStatus {
		t.Helper()
		value, err := client.State(ctx, &emptypb.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if get().Status != daemon.ServiceStatus_IDLE {
		t.Fatal("installation must start idle")
	}
	if _, err = client.StartProfile(ctx, &daemon.LocalProfileRequest{ConfigContent: `{"outbounds":[{"type":"direct","tag":"test-direct"}],"route":{"final":"test-direct"}}`}); err != nil {
		t.Fatal(err)
	}
	if get().Status != daemon.ServiceStatus_STARTED {
		t.Fatal("valid non-tunnel profile did not start")
	}
	if _, err = client.StartProfile(ctx, &daemon.LocalProfileRequest{ConfigContent: `{"log":{"output":"/etc/forbidden"}}`}); err == nil {
		t.Fatal("root file path accepted")
	}
	if get().Status != daemon.ServiceStatus_STARTED {
		t.Fatal("invalid replacement stopped working instance")
	}
	if _, err = client.Wake(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	epoch := get().NetworkEpoch
	if epoch == 0 {
		t.Fatal("missing reset generation")
	}
	if _, err = client.Wake(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if get().NetworkEpoch != epoch {
		t.Fatal("duplicate wake reset")
	}
	if _, err = client.StopProfile(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if get().Status != daemon.ServiceStatus_IDLE {
		t.Fatal("stop did not return idle")
	}
}
