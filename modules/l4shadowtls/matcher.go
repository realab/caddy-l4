package l4shadowtls

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddy.RegisterModule(&MatchShadowTLS{})
}

type MatchShadowTLS struct {
	MatchersRaw caddy.ModuleMap `json:"-" caddy:"namespace=shadow_tls.handshake_match"`

	matchers []caddytls.ConnectionMatcher
	logger   *zap.Logger
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (m *MatchShadowTLS) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &m.MatchersRaw)
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m *MatchShadowTLS) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatchersRaw)
}

// Provision sets up the handler.
func (m *MatchShadowTLS) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	mods, err := ctx.LoadModule(m, "MatchersRaw")
	if err != nil {
		return fmt.Errorf("loading ShadowTLS matchers: %v", err)
	}
	for _, modIface := range mods.(map[string]interface{}) {
		m.matchers = append(m.matchers, modIface.(caddytls.ConnectionMatcher))
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (*MatchShadowTLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.shadow_tls",
		New: func() caddy.Module { return new(MatchShadowTLS) },
	}
}

func (m *MatchShadowTLS) Match(cx *layer4.Connection) (bool, error) {
	// read the header bytes
	const recordHeaderLen = 5
	hdr := make([]byte, recordHeaderLen)
	_, err := io.ReadFull(cx, hdr)
	if err != nil {
		return false, err
	}

	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return false, nil
	}

	// get length of the ClientHello message and read it
	length := int(uint16(hdr[3])<<8 | uint16(hdr[4])) // ignoring version in hdr[1:3] - like https://github.com/inetaf/tcpproxy/blob/master/sni.go#L170
	rawHello := make([]byte, length)
	_, err = io.ReadFull(cx, rawHello)
	if err != nil {
		return false, err
	}

	// parse the ClientHello
	chi := parseRawClientHello(rawHello)
	chi.Conn = cx

	// also add values to the replacer
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("l4.shadow_tls.server_name", chi.ClientHelloInfo.ServerName)
	repl.Set("l4.shadow_tls.version", chi.Version)

	for _, matcher := range m.matchers {
		// TODO: even though we have more data than the standard lib's
		// ClientHelloInfo lets us fill, the matcher modules we use do
		// not accept our own type; but the advantage of this is that
		// we can reuse TLS connection matchers from the tls app - but
		// it would be nice if we found a way to give matchers all
		// the infoz
		if !matcher.Match(&chi.ClientHelloInfo) {
			return false, nil
		}
	}

	m.logger.Debug("matched",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.String("server_name", chi.ClientHelloInfo.ServerName),
	)

	return true, nil
}

// UnmarshalCaddyfile sets up the MatchTLS from Caddyfile tokens. Syntax:
//
//	tls {
//		matcher [<args...>]
//		matcher [<args...>]
//	}
//	tls matcher [<args...>]
//	tls
func (m *MatchShadowTLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	matcherSet, err := l4tls.ParseCaddyfileNestedMatcherSet(d)
	if err != nil {
		return err
	}
	m.MatchersRaw = matcherSet

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchShadowTLS)(nil)
	_ caddyfile.Unmarshaler = (*MatchShadowTLS)(nil)
)
