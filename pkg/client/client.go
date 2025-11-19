package client

import "crypto/tls"

//jackal client

type Client struct {
	// Fields for client
	cfg Config
}

type HostConfig struct {
	Host string `fig:"host"`
	Port int    `fig:"port" default:"5222"`
	TLS  bool   `fig:"tls" default:"true"`
	Cert tls.Certificate
}

func New(cfg Config) *Client {
	return &Client{
		cfg: cfg,
	}
}
