package libbox

import (
	"context"
	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/protobuf/types/known/emptypb"
	"time"
)

type LocalEngineState struct {
	State        int32
	Error        string
	NetworkEpoch int64
}

func (c *CommandClient) localEngineClient() (daemon.LocalEngineClient, context.Context, error) {
	_, ctx, err := c.getClientForCall()
	if err != nil {
		return nil, nil, err
	}
	c.clientAccess.RLock()
	defer c.clientAccess.RUnlock()
	return daemon.NewLocalEngineClient(c.grpcConn), ctx, nil
}
func (c *CommandClient) LocalEngineStart(configContent string) error {
	client, parent, err := c.localEngineClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	_, err = client.StartProfile(ctx, &daemon.LocalProfileRequest{ConfigContent: configContent})
	return err
}
func (c *CommandClient) LocalEngineStop() error {
	client, parent, err := c.localEngineClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	_, err = client.StopProfile(ctx, &emptypb.Empty{})
	return err
}
func (c *CommandClient) GetLocalEngineState() (*LocalEngineState, error) {
	client, parent, err := c.localEngineClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	value, err := client.State(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return &LocalEngineState{State: int32(value.Status), Error: value.ErrorMessage, NetworkEpoch: value.NetworkEpoch}, nil
}
func (c *CommandClient) LocalEngineWake() error {
	client, parent, err := c.localEngineClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	_, err = client.Wake(ctx, &emptypb.Empty{})
	return err
}
