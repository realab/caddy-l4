// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4shadowtls

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&ShadowTLSHandler{})
}

// Handler is a handler that can proxy connections.
type ShadowTLSHandler struct {
	HandshakeUpstream *Upstream `json:"handshake_upstream,omitempty"`
	DataUpstream      *Upstream `json:"data_upstream,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*ShadowTLSHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.shadow_tls",
		New: func() caddy.Module { return new(ShadowTLSHandler) },
	}
}

// Provision sets up the handler.
func (h *ShadowTLSHandler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)

	if h.HandshakeUpstream == nil {
		return fmt.Errorf("handshake_upstream is required")
	}
	if h.DataUpstream == nil {
		return fmt.Errorf("data_upstream is required")
	}
	if err := h.HandshakeUpstream.provision(ctx, h); err != nil {
		return fmt.Errorf("handshake_upstream: %v", err)
	}
	if err := h.DataUpstream.provision(ctx, h); err != nil {
		return fmt.Errorf("data_upstream: %v", err)
	}
	return nil
}

// Handle handles the downstream connection.
func (h *ShadowTLSHandler) Handle(down *layer4.Connection, next layer4.Handler) error {
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	clientHello, ok := down.GetVar(ClientHelloInfoKey).(ClientHelloInfo)
	if !ok {
		return fmt.Errorf("no tls client hello found")
	}

	var handshakePeer *peer
	for _, p := range h.HandshakeUpstream.peers {
		hostName := repl.ReplaceAll(p.address.Host, "")
		if hostName == clientHello.ServerName {
			handshakePeer = p
			break
		}
	}
	if handshakePeer == nil {
		return fmt.Errorf("no handshake peer found for server name: %s", clientHello.ServerName)
	}
	handshakeConn, err := h.dialHandshakePeer(handshakePeer, repl, down, clientHello)
	if err != nil {
		return err
	}

	// make sure upstream connections all get closed
	defer func() {
		_ = handshakeConn.Close()
	}()

	return nil
}

func (h *ShadowTLSHandler) dialHandshakePeer(p *peer, repl *caddy.Replacer, down *layer4.Connection, clientHello ClientHelloInfo) (net.Conn, error) {
	addr := p.address
	if addr.StartPort == 0 && addr.EndPort == 0 {
		addr.StartPort = 443
		addr.EndPort = 443
	}

	hostPort := repl.ReplaceAll(addr.JoinHostPort(0), "")

	tlsCfg := new(tls.Config)
	clientHello.FillTLSClientConfig(tlsCfg)
	handshakeConn, err := tls.Dial(p.address.Network, hostPort, tlsCfg)
	if err != nil {
		h.logger.Error("failed to dial handshake peer",
			zap.String("remote", down.RemoteAddr().String()),
			zap.String("handshake_server", hostPort),
			zap.Error(err))
		return nil, err
	}
	h.logger.Info("dial handshake peer",
		zap.String("remote", down.RemoteAddr().String()),
		zap.String("handshake_server", hostPort),
		zap.String("handshake_conn", handshakeConn.RemoteAddr().String()))
	return handshakeConn, nil
}

func (h *ShadowTLSHandler) Cleanup() error {
	// remove hosts from our config from the pool
	for _, dialAddr := range h.HandshakeUpstream.Dial {
		_, _ = peers.Delete(dialAddr)
	}
	for _, dialAddr := range h.DataUpstream.Dial {
		_, _ = peers.Delete(dialAddr)
	}
	return nil
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	shadow_tls {
//		handshake_server <server>
//		data_server <server>
//	}
func (h *ShadowTLSHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Consume all same-line options
	for d.NextArg() {
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "handshake_server":
			u := &Upstream{}
			if err := u.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			h.HandshakeUpstream = u
		case "data_server":
			u := &Upstream{}
			if err := u.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			h.DataUpstream = u
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	if h.HandshakeUpstream == nil {
		u := &Upstream{
			Dial: []string{"{l4.shadow_tls.server_name}"},
		}
		h.HandshakeUpstream = u
	}

	return nil
}

// peers is the global repository for peers that are
// currently in use by active configuration(s). This
// allows the state of remote hosts to be preserved
// through config reloads.
var peers = caddy.NewUsagePool()

// Interface guards
var (
	_ caddy.CleanerUpper    = (*ShadowTLSHandler)(nil)
	_ caddy.Provisioner     = (*ShadowTLSHandler)(nil)
	_ caddyfile.Unmarshaler = (*ShadowTLSHandler)(nil)
	_ layer4.NextHandler    = (*ShadowTLSHandler)(nil)
)

// Used to properly shutdown half-closed connections (see PR #73).
// Implemented by net.TCPConn, net.UnixConn, tls.Conn, qtls.Conn.
type closeWriter interface {
	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

// Ensure we notice if CloseWrite changes for these important connections
var (
	_ closeWriter = (*net.TCPConn)(nil)
	_ closeWriter = (*net.UnixConn)(nil)
	_ closeWriter = (*tls.Conn)(nil)
)
