package client

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	kitlog "github.com/go-kit/log"

	"github.com/ortuman/jackal/pkg/component/xep0114"
	"github.com/ortuman/jackal/pkg/host"
	"github.com/ortuman/jackal/pkg/router/stream"
	"github.com/ortuman/jackal/pkg/session"
	"github.com/ortuman/jackal/pkg/transport"
)

type ClientState uint32

const (
	ClinetConnecting ClientState = iota
	ClientConnected
	ClientSecuring
	ClientAuthenticating
	ClientAuthenticated
	ClientVerifyingDialbackKey
	ClientAuthorizingDialbackKey
	ClientDisconnected
)

type flags struct {
	mtx sync.RWMutex
	fs  uint8
}

type ClientSocket struct {
	// Fields for client
	conn net.Conn
	dTLS tls.Dialer
	cfg  xep0114.ListenerConfig
	// secretKey string
	// jid  jid.JID
	// remoteJid jid.JID
	host *host.Host
	// comps     *component.Components
	// router    router.Router
	// shapers   shaper.Shapers
	// hk        *hook.Hooks
	logger kitlog.Logger
	tr     transport.Transport

	tlsCfg *tls.Config
	// connHandlerFn func(conn net.Conn)

	// kv      kv.KV
	session *session.Session

	// mu    sync.RWMutex
	// state ClientState

	// flags        flags
	// pendingQueue []stravaganza.Element
}

func NewConn(cfg xep0114.ListenerConfig) *ClientSocket {
	return &ClientSocket{
		cfg: cfg,
	}
}

func (c *ClientSocket) Close() error {
	return c.conn.Close()
}

func (c *ClientSocket) HandleCoon(conn net.Conn) {

}

func (c *ClientSocket) Start(ctx context.Context) error {
	// Start
	d := net.Dialer{
		Timeout:   c.cfg.ConnectTimeout,
		KeepAlive: c.cfg.KeepAliveTimeout,
	}
	dTLS := tls.Dialer{
		NetDialer: &d,
		Config:    c.tlsCfg,
	}
	conn, err := dTLS.DialContext(ctx, "tcp", c.getAddress())
	c.dTLS = dTLS
	c.conn = conn
	c.tr = transport.NewSocketTransport(conn, c.cfg.ConnectTimeout, c.cfg.KeepAliveTimeout)
	id := nextStreamID()
	c.session = session.New(
		session.C2SSession,
		id.String(),
		c.tr,
		c.host.ConvertToHosts(),
		session.Config{
			MaxStanzaSize: c.cfg.MaxStanzaSize,
		},
		c.logger,
	)
	return err
}

func (c *ClientSocket) getAddress() string {
	return c.cfg.BindAddr + ":" + strconv.Itoa(c.cfg.Port)
}

var currentID uint64

func nextStreamID() stream.C2SID {
	return stream.C2SID(atomic.AddUint64(&currentID, 1))
}
