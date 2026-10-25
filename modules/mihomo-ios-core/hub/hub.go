package hub

import (
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/common/mobilelog"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/hub/route"
	"github.com/Dreamacro/clash/log"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalController = externalController
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.General.Secret = secret
	}
}

// Parse call at the beginning of clash
func Parse(options ...Option) error {
	mobilelog.Native("info", "hub.Parse entered. Calling executor.Parse.")
	cfg, err := executor.Parse()
	if err != nil {
		mobilelog.Native("error", "hub.Parse failed while loading the config through executor.Parse: "+err.Error())
		return err
	}
	mobilelog.Native("info", "hub.Parse loaded the runtime config successfully.")

	for _, option := range options {
		option(cfg)
	}

	if cfg.General.ExternalUI != "" {
		route.SetUIPath(cfg.General.ExternalUI)
	}

	if cfg.General.ExternalController != "" {
		mobilelog.Native("info", "hub.Parse is starting the external controller goroutine.")
		go route.Start(cfg.General.ExternalController, cfg.General.ExternalControllerTLS,
			cfg.General.Secret, cfg.TLS.Certificate, cfg.TLS.PrivateKey, cfg.General.LogLevel == log.DEBUG)
	}

	mobilelog.Native("info", "hub.Parse is entering executor.ApplyConfig.")
	executor.ApplyConfig(cfg, true)
	mobilelog.Native("info", "hub.Parse returned from executor.ApplyConfig.")
	return nil
}
