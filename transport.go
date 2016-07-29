package onion

import (
	"crypto"
	"net"

	tpt "github.com/ipfs/go-libp2p-transport"
	ma "github.com/jbenet/go-multiaddr"
	"github.com/yawning/bulb"
	"golang.org/x/net/proxy"
)

// OnionTransport implements go-libp2p-transport's Transport interface
type OnionTransport struct {
	controlConn *bulb.Conn
	auth        *proxy.Auth
	port        uint16
	key         crypto.PrivateKey
}

// NewOnionTransport creates a OnionTransport
// If key is nil then generate a new key.
func NewOnionTransport(controlNet, controlAddr string, port uint16, key crypto.PrivateKey, auth *proxy.Auth) (*OnionTransport, error) {
	conn, err := bulb.Dial(controlNet, controlAddr)
	if err != nil {
		return nil, err
	}
	o := OnionTransport{
		controlConn: conn,
		auth:        auth,
		port:        port,
		key:         key,
	}
	return &o, nil
}

func (t *OnionTransport) Dialer(_ ma.Multiaddr, opts ...tpt.DialOpt) (tpt.Dialer, error) {
	dialer := OnionDialer{
		auth: t.auth,
	}
	return dialer, nil
}

func (t *OnionTransport) Listen(a ma.Multiaddr) (tpt.Listener, error) {
	listener := OnionListener{
		port: t.port,
		key:  t.key,
	}
	return listener, nil
}

func (t *OnionTransport) Matches(a ma.Multiaddr) bool {
	// XXX fix me
	return true
}

// OnionDialer implements go-libp2p-transport's Dialer interface
type OnionDialer struct {
	auth *proxy.Auth
}

func (d *OnionDialer) Dial() (tpt.Conn, error) {
	dialer, err := bulb.Dialer(d.auth)
	if err != nil {
		return nil, err
	}
	dialer
}

func (d *OnionDialer) Matches(a ma.Multiaddr) bool {
	// XXX fix me
	return true
}

// OnionListener implements go-libp2p-transport's Listener interface
type OnionListener struct {
	port uint16
	key  crypto.PrivateKey
}

func (l *OnionListener) Accept() (tpt.Conn, error) {
}

func (l *OnionListener) Close() error {
}

func (l *OnionListener) Addr() net.Addr {
}

func (l *OnionListener) Multiaddr() ma.Multiaddr {
}

// OnionConn implement's go-libp2p-transport's Conn interface
type OnionConn struct {
	transport *OnionTransport
	conn      *bulb.Conn
}

func (c *OnionConn) Transport() {
	return c.transport
}

func (c *OnionConn) LocalMultiaddr() ma.Multiaddr {
}

func (c *OnionConn) RemoteMultiaddr() ma.Multiaddr {
}
