package config

import (
	"fmt"

	"github.com/underdog-tech/vulnbot/logger"

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

func LoadConfig(configFilePath *string) TomlConfig {
	var config TomlConfig
	log := logger.Get()

	_, err := toml.DecodeFile(*configFilePath, &config)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading config file.")
	}
	log.Debug().Any("config", config).Msg("Config loaded.")
	return config
}

func GetIconForSeverity(severity string, severities []SeverityConfig) (string, error) {
	for _, config := range severities {
		if config.Label == severity {
			return config.Slack_emoji, nil
		}
	}
	return "", fmt.Errorf("No Slack icon available for severity %s", severity)
}

func GetIconForEcosystem(ecosystem string, ecosystems []EcosystemConfig) (string, error) {
	for _, config := range ecosystems {
		if config.Label == ecosystem {
			return config.Slack_emoji, nil
		}
	}
	return "", fmt.Errorf("No Slack icon available for ecosystem %s", ecosystem)
}

func GetTeamConfigBySlug(teamSlug string, teams []TeamConfig) (TeamConfig, error) {
	for _, team := range teams {
		if team.Github_slug == teamSlug {
			return team, nil
		}
	}
	return TeamConfig{}, fmt.Errorf("No config found for team %s", teamSlug)
}
