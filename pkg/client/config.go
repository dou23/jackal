package client

import (
	"path/filepath"

	"github.com/ortuman/jackal/pkg/module/xep0313"

	"github.com/kkyr/fig"
	"github.com/ortuman/jackal/pkg/auth/pepper"
	"github.com/ortuman/jackal/pkg/c2s"
	"github.com/ortuman/jackal/pkg/component/xep0114"
	"github.com/ortuman/jackal/pkg/host"
	"github.com/ortuman/jackal/pkg/module/offline"
	"github.com/ortuman/jackal/pkg/module/xep0092"
	"github.com/ortuman/jackal/pkg/module/xep0198"
	"github.com/ortuman/jackal/pkg/module/xep0199"
	"github.com/ortuman/jackal/pkg/storage"
)

const (
	kvClusterType   = "kv"
	noneClusterType = "none"
)

// LoggerConfig defines logger configuration.
type LoggerConfig struct {
	Level  string `fig:"level" default:"debug"`
	Format string `fig:"format"`
}

// HTTPConfig defines HTTP configuration.
type HTTPConfig struct {
	Port int `fig:"port" default:"6060"`
}

// ServiceConfig defines C2S subsystem configuration.
type ServiceConfig struct {
	Listener c2s.ListenerConfig `fig:"listener"`
}

// ComponentsConfig defines application components configuration.
type ComponentsConfig struct {
	Listeners xep0114.ListenersConfig `fig:"listeners"`
	Secret    string                  `fig:"secret"`
}

// ModulesConfig defines application modules configuration.
type ModulesConfig struct {
	// Enabled specifies total set of enabled modules
	Enabled []string `fig:"enabled"`

	// Offline: offline storage
	Offline offline.Config `fig:"offline"`

	// XEP-0092: Software Version
	Version xep0092.Config `fig:"version"`

	// XEP-0198: Stream Management
	Stream xep0198.Config `fig:"stream"`

	// XEP-0199: XMPP Ping
	Ping xep0199.Config `fig:"ping"`

	// XEP-0313: Message Archive Management
	Mam xep0313.Config `fig:"mam"`
}

// Config defines jackal application configuration.
type Config struct {
	MemoryBallastSize int `fig:"memory_ballast_size" default:"134217728"`

	Logger LoggerConfig `fig:"logger"`

	Peppers pepper.Config  `fig:"peppers"`
	Storage storage.Config `fig:"storage"`
	Hosts   host.Config    `fig:"host"`

	ServerCfg  ServiceConfig    `fig:"service"`
	Components ComponentsConfig `fig:"components"`
	Modules    ModulesConfig    `fig:"modules"`
}

func loadConfig(configFile string) (*Config, error) {
	var cfg Config
	file := filepath.Base(configFile)
	dir := filepath.Dir(configFile)

	err := fig.Load(&cfg, fig.File(file), fig.Dirs(dir), fig.UseEnv("jackal"))
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
