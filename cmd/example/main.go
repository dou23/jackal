// xmpp_client.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"log"
	"time"

	"mellium.im/sasl"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"
)

type XMPPBot struct {
	client *xmpp.Session
	ctx    context.Context
	cancel context.CancelFunc
}

func NewXMPPBot(serverAddr, jidStr, password string) (*XMPPBot, error) {
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

	bot := &XMPPBot{
		client: session,
		ctx:    ctx,
		cancel: cancel,
	}

	// 启动消息监听协程
	go bot.listen()

	// 发送初始 presence
	pres := stanza.Presence{Type: stanza.AvailablePresence}
	if err := bot.client.Encode(ctx, pres); err != nil {
		log.Printf("Failed to send presence: %v", err)
	}

	return bot, nil
}

func (b *XMPPBot) listen() {
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
			token, err := b.client.TokenReader().Token()
			if err != nil {
				log.Printf("XMPP read error: %v", err)
				time.Sleep(time.Second)
				continue
			}

			switch msg := token.(type) {
			case stanza.Message:
				log.Printf("Received message from %s", msg.From)
				// 如果需要处理消息内容，需要进一步解析 XML 流
			}
		}
	}
}

func (b *XMPPBot) handleCommand(from jid.JID, cmd string) {
	// 示例：响应 "status" 命令
	if cmd == "status" {
		// 直接构造一个完整的 XML 消息
		msg := struct {
			XMLName xml.Name `xml:"message"`
			To      string   `xml:"to,attr"`
			Type    string   `xml:"type,attr"`
			Body    string   `xml:"body"`
		}{
			To:   from.String(),
			Type: "chat",
			Body: "✅ Service is running!",
		}

		if err := b.client.Encode(b.ctx, msg); err != nil {
			log.Printf("Failed to send reply: %v", err)
		}
	}
}

func (b *XMPPBot) SendNotification(to, body string) error {
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

	return b.client.Encode(b.ctx, msg)
}

func (b *XMPPBot) Close() {
	b.cancel()
	b.client.Close()
}

func main() {
	// 初始化 XMPP Bot
	bot, err := NewXMPPBot(
		"localhost:5222", // XMPP 服务器地址
		"bot@localhost",  // 在 XMPP 服务器中创建的账号
		"123456",
	)
	if err != nil {
		log.Fatal("Failed to init XMPP bot:", err)
	}
	defer bot.Close()

	// 模拟业务：订单创建后发送通知
	go func() {
		time.Sleep(3 * time.Second)
		err := bot.SendNotification("user@localhost", "📦 新订单 #12345 已创建！")
		if err != nil {
			log.Println("Failed to send notification:", err)
		}
	}()

}
