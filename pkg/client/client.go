package client

import "crypto/tls"

//jackal client

type Client struct {
	// Fields for client
	cfg Config
}

func NewClient(cfg Config) *Client {
	return &Client{
		cfg: cfg,
	}
}