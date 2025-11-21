package client

//jackal client

type Client struct {
	// Fields for client
	Cfg          Config
	UserAuth     UserAuth
	ClientSocket *ClientSocket
}

type UserAuth struct {
	Username string
	Password string
}

func NewClient(cfg Config) *Client {
	c := &Client{
		Cfg: cfg,
	}
	c.ClientSocket = NewConn(cfg.ServerCfg.Listener)
	return c
}
