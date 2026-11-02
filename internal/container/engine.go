package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/safedep/dry/log"
)

// engineBaseURL has a host only because a URL needs one. The transport dials
// the socket.
const engineBaseURL = "http://engine"

// maxEngineResponseBytes bounds a reply, so a broken engine cannot fill the
// daemon's memory.
const maxEngineResponseBytes = 16 << 20

// engineClient talks to the Docker Engine API on a Unix socket. Docker serves
// that API, and Podman serves a compatible one, so one client covers both.
type engineClient struct {
	http *http.Client
}

func newEngineClient(socket string) *engineClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 1,
	}
	return &engineClient{http: &http.Client{Transport: transport}}
}

func (e *engineClient) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, engineBaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Debugf("container: close the reply to %s: %v", path, err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxEngineResponseBytes)).Decode(v); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	return nil
}

type engineVersion struct {
	Components []struct {
		Name string `json:"Name"`
	} `json:"Components"`
}

// runtime asks the engine which runtime serves it. Podman names itself in
// the components of /version, and Docker does not.
func (e *engineClient) runtime(ctx context.Context) (Runtime, error) {
	var v engineVersion
	if err := e.get(ctx, "/version", &v); err != nil {
		return "", err
	}
	for _, c := range v.Components {
		if strings.Contains(strings.ToLower(c.Name), "podman") {
			return RuntimePodman, nil
		}
	}
	return RuntimeDocker, nil
}

type engineContainer struct {
	ID              string   `json:"Id"`
	Names           []string `json:"Names"`
	Image           string   `json:"Image"`
	ImageID         string   `json:"ImageID"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// containers lists the running containers by their addresses on the
// runtime's networks.
func (e *engineClient) containers(ctx context.Context, runtime Runtime) (map[netip.Addr]Container, error) {
	var list []engineContainer
	if err := e.get(ctx, "/containers/json", &list); err != nil {
		return nil, err
	}
	byAddr := make(map[netip.Addr]Container)
	for _, ec := range list {
		c := Container{
			Runtime: runtime,
			ID:      ec.ID,
			Name:    firstName(ec.Names),
			Image:   ec.Image,
			ImageID: ec.ImageID,
		}
		for _, network := range ec.NetworkSettings.Networks {
			for _, s := range []string{network.IPAddress, network.GlobalIPv6Address} {
				if addr, err := netip.ParseAddr(s); err == nil {
					byAddr[addr.Unmap()] = c
				}
			}
		}
	}
	return byAddr, nil
}

// firstName drops the "/" that the engine puts in front of a name.
func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}
