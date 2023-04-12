package config

import (
	"vulnbot/logger"

	"github.com/BurntSushi/toml"
)

type SeverityConfig struct {
	Label       string
	Slack_emoji string
}

type EcosystemConfig struct {
	Label       string
	Slack_emoji string
}

type TeamConfig struct {
	Name          string
	Github_slug   string
	Slack_channel string
}

type TomlConfig struct {
	Default_slack_channel string
	Severity              []SeverityConfig
	Ecosystem             []EcosystemConfig
	Team                  []TeamConfig
}

func LoadConfig() TomlConfig {
	var config TomlConfig
	log := logger.Get()

	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading config file.")
	}
	log.Debug().Any("config", config).Msg("Config loaded.")
	return config
}

func GetIconForSeverity(severity string, severities []SeverityConfig) string {
	for _, config := range severities {
		if config.Label == severity {
			return config.Slack_emoji
		}
	}
	return " "
}

func GetIconForEcosystem(ecosystem string, ecosystems []EcosystemConfig) string {
	for _, config := range ecosystems {
		if config.Label == ecosystem {
			return config.Slack_emoji
		}
	}
	return " "
}

func GetTeamConfigBySlug(teamSlug string, teams []TeamConfig) TeamConfig {
	for _, team := range teams {
		if team.Github_slug == teamSlug {
			return team
		}
	}
	return TeamConfig{}
}
