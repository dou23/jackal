package main

import (
	"github.com/ortuman/jackal/pkg/c2s"
	"github.com/ortuman/jackal/pkg/client"
)

func main() {
	c:=client.NewClient(client.Config{
		ServerCfg: client.ServiceConfig{
			Listener: c2s.ListenerConfig{ 

			},
		},
	})
}
