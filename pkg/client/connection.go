package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	kitlog "github.com/go-kit/log"
	"github.com/jackal-xmpp/runqueue/v2"
	"github.com/jackal-xmpp/stravaganza"
	"github.com/jackal-xmpp/stravaganza/jid"

	streamerror "github.com/jackal-xmpp/stravaganza/errors/stream"
	xmppparser "github.com/jackal-xmpp/stravaganza/parser"
	"github.com/ortuman/jackal/pkg/c2s"
	"github.com/ortuman/jackal/pkg/hook"
	"github.com/ortuman/jackal/pkg/host"
	"github.com/ortuman/jackal/pkg/router/stream"
	"github.com/ortuman/jackal/pkg/session"
	"github.com/ortuman/jackal/pkg/transport"
)

type ClientState uint32

const (
	ClientConnecting ClientState = iota
	ClientConnected
	ClientSecuring
	ClientAuthenticating
	ClientAuthenticated
	ClientVerifyingDialbackKey
	ClientAuthorizingDialbackKey
	ClientDisconnected
)

type ClientSocket struct {
	UserAuth UserAuth
	id       string
	// Fields for client
	conn       net.Conn
	dTLSDialer tls.Dialer
	cfg        c2s.ListenerConfig
	// secretKey string
	jid       jid.JID
	remoteJid jid.JID
	host      *host.Host
	// comps     *component.Components
	// router    router.Router
	// shapers   shaper.Shapers
	hk     *hook.Hooks
	logger kitlog.Logger
	tr     transport.Transport

	tlsCfg *tls.Config
	// connHandlerFn func(conn net.Conn)

	// kv      kv.KV
	session *session.Session

	mu    sync.RWMutex
	state ClientState

	rq *runqueue.RunQueue

	onClose func(s *ClientSocket)
	dbResCh chan stream.DialbackResult

	flags        flags
	pendingQueue []stravaganza.Element
}

func NewConn(cfg c2s.ListenerConfig) *ClientSocket {
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
	dTLSDialer := tls.Dialer{
		NetDialer: &d,
		Config:    c.tlsCfg,
	}
	conn, err := dTLSDialer.DialContext(ctx, "tcp", c.getAddress())
	c.dTLSDialer = dTLSDialer
	c.conn = conn
	c.tr = transport.NewSocketTransport(conn, c.cfg.ConnectTimeout, c.cfg.KeepAliveTimeout)
	id := nextStreamID()
	c.id = id.String()
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

func (c *ClientSocket) setState(state ClientState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
}

func (c *ClientSocket) getState() ClientState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *ClientSocket) getAddress() string {
	return c.cfg.BindAddr + ":" + strconv.Itoa(c.cfg.Port)
}

func (c *ClientSocket) readLoop() {
	elem, sErr := c.session.Receive()
	for {
		if c.getState() == ClientDisconnected {
			return
		}
		c.handleSessionResult(elem, sErr)
		elem, sErr = c.session.Receive()
	}
}

func (c *ClientSocket) handleSessionResult(elem stravaganza.Element, sErr error) {
	doneCh := make(chan struct{})
	c.rq.Run(func() {
		defer close(doneCh)

		ctx, cancel := c.requestContext()
		defer cancel()

		switch {
		case sErr == nil && elem != nil:
			err := c.handleElement(ctx, elem)
			if err != nil {
				// level.Warn(c.logger).Log("msg", "failed to process outgoing S2S session element", "err", err, "id", s.ID())
				_ = c.close(ctx)
				return
			}

		case sErr != nil:
			c.handleSessionError(ctx, sErr)
		}
	})
	<-doneCh
}

func (s *ClientSocket) handleElement(ctx context.Context, elem stravaganza.Element) error {
	var err error
	switch s.getState() {
	case ClientConnecting:
		err = s.handleConnecting(ctx, elem)
	case ClientConnected:
		err = s.handleConnected(ctx, elem)
	case ClientSecuring:
		err = s.handleSecuring(ctx, elem)
	case ClientAuthenticating:
		err = s.handleAuthenticating(ctx, elem)
	case ClientVerifyingDialbackKey:
		err = s.handleVerifyingDialbackKey(ctx, elem)
	case ClientAuthorizingDialbackKey:
		err = s.handleAuthorizingDialbackKey(ctx, elem)
	}
	return err
}

func (s *ClientSocket) handleConnecting(_ context.Context, _ stravaganza.Element) error {
	s.setState(ClientConnected)
	return nil
}

func (s *ClientSocket) handleConnected(ctx context.Context, elem stravaganza.Element) error {
	if elem.Name() != "stream:features" {
		return s.disconnect(ctx, streamerror.E(streamerror.UnsupportedStanzaType))
	}
	if !s.flags.isSecured() {
		if elem.ChildNamespace("starttls", tlsNamespace) == nil {
			// unsecured connections are unsupported
			return s.disconnect(ctx, streamerror.E(streamerror.PolicyViolation))
		}
		s.setState(ClientSecuring)

		startTLS := stravaganza.NewBuilder("starttls").
			WithAttribute(stravaganza.Namespace, tlsNamespace).
			Build()
		return s.sendElement(ctx, startTLS)
	}
	if s.flags.isAuthenticated() {
		return s.finishAuthentication(ctx)
	}
	if hasExternalAuthMechanism(elem) {
		s.setState(ClientAuthenticating)
		return s.sendElement(ctx, stravaganza.NewBuilder("auth").
			WithAttribute(stravaganza.Namespace, saslNamespace).
			WithAttribute("mechanism", "EXTERNAL").
			WithText(base64.StdEncoding.EncodeToString([]byte(s.jid.String()))).
			Build(),
		)
	}

	// switch s.typ {
	// case defaultType:
	// 	switch {
	// 	case hasExternalAuthMechanism(elem):
	// 		s.setState(outAuthenticating)
	// 		return s.sendElement(ctx, stravaganza.NewBuilder("auth").
	// 			WithAttribute(stravaganza.Namespace, saslNamespace).
	// 			WithAttribute("mechanism", "EXTERNAL").
	// 			WithText(base64.StdEncoding.EncodeToString([]byte(s.sender))).
	// 			Build(),
	// 		)

	// 	case hasDialbackFeature(elem):
	// 		streamID := s.session.StreamID()

	// 		// register dialback request
	// 		if err := registerDbRequest(ctx, s.target, s.sender, streamID, s.kv); err != nil {
	// 			return err
	// 		}
	// 		s.setState(outVerifyingDialbackKey)
	// 		return s.sendElement(ctx, stravaganza.NewBuilder("db:result").
	// 			WithAttribute(stravaganza.From, s.sender).
	// 			WithAttribute(stravaganza.To, s.target).
	// 			WithText(
	// 				dbKey(
	// 					s.cfg.dbSecret,
	// 					s.target,
	// 					s.sender,
	// 					streamID,
	// 				),
	// 			).
	// 			Build(),
	// 		)

	// 	default:
	// 		return s.disconnect(ctx, streamerror.E(streamerror.RemoteConnectionFailed))
	// 	}

	// case dialbackType:
	// 	s.setState(outAuthorizingDialbackKey)
	// 	return s.sendElement(ctx, stravaganza.NewBuilder("db:verify").
	// 		WithAttribute(stravaganza.ID, s.dbParams.StreamID).
	// 		WithAttribute(stravaganza.From, s.dbParams.From).
	// 		WithAttribute(stravaganza.To, s.dbParams.To).
	// 		WithText(s.dbParams.Key).
	// 		Build(),
	// 	)
	// }
	return nil
}

func (s *ClientSocket) handleSecuring(ctx context.Context, elem stravaganza.Element) error {
	if elem.Name() != "proceed" {
		return s.disconnect(ctx, streamerror.E(streamerror.UnsupportedStanzaType))
	} else if elem.Attribute(stravaganza.Namespace) != tlsNamespace {
		return s.disconnect(ctx, streamerror.E(streamerror.InvalidNamespace))
	}
	// proceed with TLS securing
	s.tr.StartTLS(s.tlsCfg, true)

	s.flags.setSecured()
	s.restartSession()

	return s.session.OpenStream(ctx)
}

func (c *ClientSocket) handleAuthenticating(ctx context.Context, elem stravaganza.Element) error {
	if elem.Attribute(stravaganza.Namespace) != saslNamespace {
		return c.disconnect(ctx, streamerror.E(streamerror.InvalidNamespace))
	}
	switch elem.Name() {
	case "success":
		c.flags.setAuthenticated()

		c.restartSession()
		return c.session.OpenStream(ctx)

	case "failure":
		return c.disconnect(ctx, streamerror.E(streamerror.RemoteConnectionFailed))

	default:
		return c.disconnect(ctx, streamerror.E(streamerror.UnsupportedStanzaType))
	}
}

func (c *ClientSocket) handleVerifyingDialbackKey(ctx context.Context, elem stravaganza.Element) error {
	switch elem.Name() {
	case "db:result":
		switch elem.Attribute(stravaganza.Type) {
		case "valid":
			// level.Info(c.logger).Log("msg", "Client dialback key successfully verified", "from", c.sender, "to", c.target)
			return c.finishAuthentication(ctx)

		default:
			// level.Info(c.logger).Log("msg", "failed to verify Client dialback key", "from", c.sender, "to", c.target)
			return c.disconnect(ctx, streamerror.E(streamerror.RemoteConnectionFailed))
		}

	default:
		return c.disconnect(ctx, streamerror.E(streamerror.UnsupportedStanzaType))
	}
}

func (c *ClientSocket) handleAuthorizingDialbackKey(ctx context.Context, elem stravaganza.Element) error {
	switch elem.Name() {
	case "db:verify":
		typ := elem.Attribute(stravaganza.Type)
		isValid := typ == "valid"

		c.dbResCh <- stream.DialbackResult{
			Valid: isValid,
			Error: elem.Child("error"),
		}
		return c.disconnect(ctx, nil)

	default:
		return c.disconnect(ctx, streamerror.E(streamerror.UnsupportedStanzaType))
	}
}

func (c *ClientSocket) handleSessionError(ctx context.Context, err error) {
	switch err {
	case xmppparser.ErrStreamClosedByPeer:
		_ = c.session.Close(ctx)
		fallthrough

	default:
		_ = c.close(ctx)
	}
}

func hasExternalAuthMechanism(streamFeatures stravaganza.Element) bool {
	mechanisms := streamFeatures.ChildNamespace("mechanisms", saslNamespace)
	if mechanisms == nil {
		return false
	}
	for _, m := range mechanisms.AllChildren() {
		if m.Name() == "mechanism" && m.Text() == "EXTERNAL" {
			return true
		}
	}
	return false
}

func hasDialbackFeature(streamFeatures stravaganza.Element) bool {
	return streamFeatures.ChildrenNamespace("dialback", dialbackNamespace) != nil
}

func (c *ClientSocket) finishAuthentication(ctx context.Context) error {
	c.setState(ClientAuthenticated)

	// send pending elements
	for _, elem := range c.pendingQueue {
		if err := c.sendElement(ctx, elem); err != nil {
			return err
		}
	}
	c.pendingQueue = nil
	return nil
}

func (c *ClientSocket) disconnect(ctx context.Context, streamErr *streamerror.Error) error {
	if c.getState() == ClientConnecting {
		_ = c.session.OpenStream(ctx)
	}
	if streamErr != nil {
		if err := c.sendElement(ctx, streamErr.Element()); err != nil {
			return err
		}
	}
	_ = c.session.Close(ctx)
	return c.close(ctx)
}

func (c *ClientSocket) sendElement(ctx context.Context, elem stravaganza.Element) error {
	err := c.session.Send(ctx, elem)
	if err != nil {
		return err
	}
	err = c.runHook(ctx, hook.C2SStreamElementSent, &hook.C2SStreamInfo{
		ID:      c.ID(),
		JID:     c.JID(),
		Element: elem,
	})
	return err
}

func (s *ClientSocket) restartSession() {
	_ = s.session.Reset(s.tr)
	s.setState(ClientConnecting)
}

func (c *ClientSocket) JID() *jid.JID {
	return &c.jid
}

func (c *ClientSocket) ID() string {
	return c.id
}

func (c *ClientSocket) runHook(ctx context.Context, hookName string, inf *hook.C2SStreamInfo) error {
	_, err := c.hk.Run(hookName, &hook.ExecutionContext{
		Info:    inf,
		Sender:  c,
		Context: ctx,
	})
	return err
}

func (c *ClientSocket) requestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
}

func (c *ClientSocket) close(ctx context.Context) error {
	// unregister S2S out stream
	c.setState(ClientDisconnected)

	if c.onClose != nil {
		c.onClose(c)
	}
	if c.dbResCh != nil {
		close(c.dbResCh)
	}

	// run unregistered S2S hook
	err := c.runHook(ctx, hook.C2SStreamDisconnected, &hook.C2SStreamInfo{
		ID: c.ID(),
	})
	if err != nil {
		return err
	}

	// close underlying transport
	_ = c.tr.Close()
	return nil
}

var currentID uint64

func nextStreamID() stream.C2SID {
	return stream.C2SID(atomic.AddUint64(&currentID, 1))
}
