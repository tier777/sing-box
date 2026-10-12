package libbox

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/protobuf/types/known/emptypb"
	"time"
)

type RouteProbeResult struct {
	OutboundTag string
	TargetURL   string
	Reachable   bool
	CheckedAt   int64
	LatencyMs   int64
	HTTPStatus  int32
	Stage       string
	Error       string
	ExitIP      string
	Country     string
}

func (c *CommandClient) GetRouteCatalog() (string, error) {
	client, parent, err := c.getClientForCall()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	catalog, err := client.GetRouteCatalog(ctx, &emptypb.Empty{})
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(catalog)
	return string(encoded), err
}

func (c *CommandClient) ProbeRoute(outboundTag string, targetURL string) (*RouteProbeResult, error) {
	client, parent, err := c.getClientForCall()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	r, err := client.ProbeRoute(ctx, &daemon.RouteProbeRequest{OutboundTag: outboundTag, TargetURL: targetURL})
	if err != nil {
		return nil, err
	}
	return &RouteProbeResult{
		OutboundTag: r.OutboundTag, TargetURL: r.TargetURL, Reachable: r.Reachable,
		CheckedAt: r.CheckedAt, LatencyMs: r.LatencyMs, HTTPStatus: r.HttpStatus,
		Stage: r.Stage, Error: r.Error, ExitIP: r.ExitIP, Country: r.Country,
	}, nil
}
