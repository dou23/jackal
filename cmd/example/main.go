// xmpp_client.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"time"

	"mellium.im/sasl"
	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/ping"
	"mellium.im/xmpp/stanza"
)

type XMPPClient struct {
	session    *xmpp.Session
	ctx        context.Context
	cancel     context.CancelFunc
	jid        jid.JID
	pingTicker *time.Ticker
}

type MessageBody struct {
	stanza.Message
	Body string `xml:"body"`
}

func NewXMPPClient(serverAddr, jidStr, password string) (*XMPPClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	localJID, err := jid.Parse(jidStr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid JID: %w", err)
	}

	// 加载证书
	cert, err := tls.LoadX509KeyPair(
		".cert\\cert.pem",
		".cert\\key.pem")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	// 配置 TLS
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // 开发环境可设置为 true，生产环境建议正确配置证书
	}

	// 连接到 XMPP 服务器
	session, err := xmpp.DialClientSession(
		ctx, localJID,
		xmpp.StartTLS(tlsConfig),
		xmpp.SASL(jidStr, password, sasl.ScramSha256), // 指定密码和 PLAIN 机制
		xmpp.BindResource(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to XMPP server: %w", err)
	}

	bot := &XMPPClient{
		session: session,
		ctx:     ctx,
		cancel:  cancel,
		jid:     localJID,
	}

	// 启动消息监听协程
	// go bot.listen()

	// 发送初始 presence
	pres := stanza.Presence{Type: stanza.AvailablePresence}
	if err := bot.session.Encode(ctx, pres); err != nil {
		log.Printf("Failed to send presence: %v", err)
	}

	// log.Printf("Successed to send presence: %v", pres)

	// 启动心跳机制，每5秒发送一次ping
	bot.StartKeepAlive(5 * time.Second)

	go func() {

		bot.session.Serve(xmpp.HandlerFunc(func(t xmlstream.TokenReadEncoder, start *xml.StartElement) error {
			d := xml.NewTokenDecoder(t)

			log.Printf("Replying to token name: %s", start.Name.Local)

			// Ignore anything that's not a message. In a real system we'd want to at
			// least respond to IQs.
			if start.Name.Local != "message" {
				return nil
			}

			msg := MessageBody{}
			err = d.DecodeElement(&msg, start)
			if err != nil && err != io.EOF {
				log.Printf("Error decoding message: %q", err)
				return nil
			}

			// Don't reflect messages unless they are chat messages and actually have a
			// body.
			// In a real world situation we'd probably want to respond to IQs, at least.
			if msg.Body == "" || msg.Type != stanza.ChatMessage {
				return nil
			}

			reply := MessageBody{
				Message: stanza.Message{
					To: msg.From.Bare(),
				},
				Body: msg.Body,
			}
			log.Printf("Replying to message %q from %s with body %q", msg.ID, reply.To, reply.Body)
			err = t.Encode(reply)
			if err != nil {
				log.Printf("Error responding to message %q: %q", msg.ID, err)
			}
			return nil
		}))

	}()
	return bot, nil
}

func (b *XMPPClient) SendNotification(to, body string) error {
	target, err := jid.Parse(to)
	if err != nil {
		return err
	}

	// 直接构造一个完整的 XML 消息
	msg := struct {
		XMLName xml.Name `xml:"message"`
		To      string   `xml:"to,attr"`
		Type    string   `xml:"type,attr"`
		Body    string   `xml:"body"`
	}{
		To:   target.String(),
		Type: "chat",
		Body: body,
	}

	return b.session.Encode(b.ctx, msg)
}

func (b *XMPPClient) Close() {
	b.cancel()
	b.session.Close()
}

// StartKeepAlive 启动心跳机制
func (c *XMPPClient) StartKeepAlive(interval time.Duration) {
	c.pingTicker = time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-c.pingTicker.C:
				err := c.SendPing()
				if err != nil {
					fmt.Printf("发送心跳包失败: %v", err)
				}
			case <-c.ctx.Done():
				c.pingTicker.Stop()
				fmt.Printf("发送心跳包终止")
				return
			}
		}
	}()
}

// SendPing 发送ping请求到服务器
func (c *XMPPClient) SendPing() error {
	fmt.Printf("发送心跳包 \n")
	return ping.Send(c.ctx, c.session, c.session.RemoteAddr())
}

// Disconnect 断开连接
func (c *XMPPClient) Disconnect() error {
	// 停止心跳
	if c.pingTicker != nil {
		c.pingTicker.Stop()
	}
	c.cancel()

	// 发送离线状态
	err := c.session.Send(context.Background(), stanza.Presence{Type: stanza.UnavailablePresence}.Wrap(nil))
	if err != nil {
		fmt.Printf("发送离线状态失败: %v", err)
	}

	// 关闭会话
	return c.session.Close()
}

func main() {
	// 初始化 XMPP Bot
	bot, err := NewXMPPClient(
		"localhost:5222", // XMPP 服务器地址
		"bot@localhost",  // 在 XMPP 服务器中创建的账号
		"123456",
	)
	if err != nil {
		log.Fatal("Failed to init XMPP bot:", err)
	}
	defer bot.Close()

	// 模拟业务：订单创建后发送通知
	// go func() {
	// 	time.Sleep(3 * time.Second)
	// 	err := bot.SendNotification("user@jackal.imx", "📦 新订单 #12345 已创建！")
	// 	if err != nil {
	// 		log.Println("Failed to send notification:", err)
	// 	}
	// }()

	for {
		select {}
	}

}
