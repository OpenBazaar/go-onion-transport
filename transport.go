package onion

import (
	"crypto"
	"net"

	tpt "github.com/ipfs/go-libp2p-transport"
	ma "github.com/jbenet/go-multiaddr"
	manet "github.com/jbenet/go-multiaddr-net"

	"github.com/yawning/bulb"
	"golang.org/x/net/proxy"
)

func IsValidOnionMultiAddr(a ma.Multiaddr) bool {
	netaddr, err := manet.ToNetAddr(a)
	if err != nil {
		return false
	}
	addr := strings.Split(netaddr.String(), ":")
	if len(addr) != 2 {
		return false
	}

	// onion address without the ".onion" substring
	if len(addr[0]) != 16 {
		return false
	}
	onionHostBytes, err := base32.StdEncoding.DecodeString(strings.ToUpper(addr[0]))
	if err != nil {
		return false
	}

	// onion port number
	i, err := strconv.Atoi(addr[1])
	if err != nil {
		return false
	}
	if i >= 65536 || i < 1 {
		return false
	}

	return true
}

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

func (t *OnionTransport) Dialer(laddr ma.Multiaddr, opts ...tpt.DialOpt) (tpt.Dialer, error) {
	dialer := OnionDialer{
		auth:      t.auth,
		laddr:     &laddr,
		transport: t,
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
	return IsValidOnionMultiAddr(a)
}

// OnionDialer implements go-libp2p-transport's Dialer interface
type OnionDialer struct {
	auth      *proxy.Auth
	conn      *OnionConn
	laddr     *ma.Multiaddr
	transport *OnionTransport
}

func (d *OnionDialer) Dial(raddr ma.Multiaddr) (tpt.Conn, error) {
	dialer, err := bulb.Dialer(d.auth)
	if err != nil {
		return nil, err
	}
	netaddr, err := manet.ToNetAddr(raddr)
	if err != nil {
		return nil, err
	}
	onionConn := OnionConn{
		transport: d.transport,
		laddr:     d.laddr,
		raddr:     raddr,
	}
	onionConn.conn, err = dialer.Dial(netaddr.Network(), netaddr.String())
	if err != nil {
		return nil, err
	}
	return onionConn, nil
}

func (d *OnionDialer) Matches(a ma.Multiaddr) bool {
	return IsValidOnionMultiAddr(a)
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
	conn      net.Conn
	laddr     *ma.Multiaddr
	raddr     *ma.Multiaddr
}

func (c *OnionConn) Transport() *OnionTransport {
	return c.transport
}

func (c *OnionConn) LocalMultiaddr() ma.Multiaddr {
	return *c.laddr
}

func (c *OnionConn) RemoteMultiaddr() ma.Multiaddr {
	return *c.raddr
}
