package main

import (
	"dependabot-alert-bot/logger"

	"github.com/BurntSushi/toml"
)

type severityConfig struct {
	Label       string
	Slack_emoji string
}

type ecosystemConfig struct {
	Label       string
	Slack_emoji string
}

type teamConfig struct {
	Name          string
	Github_slug   string
	Slack_channel string
}

type tomlConfig struct {
	Default_slack_channel string
	Severity              []severityConfig
	Ecosystem             []ecosystemConfig
	Team                  []teamConfig
}

func loadConfig() tomlConfig {
	var config tomlConfig
	log := logger.Get()

	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading config file.")
	}
	log.Debug().Any("config", config).Msg("Config loaded.")
	return config
}

func getIconForSeverity(severity string, severities []severityConfig) string {
	for _, config := range severities {
		if config.Label == severity {
			return config.Slack_emoji
		}
	}
	return " "
}

func getIconForEcosystem(ecosystem string, ecosystems []ecosystemConfig) string {
	for _, config := range ecosystems {
		if config.Label == ecosystem {
			return config.Slack_emoji
		}
	}
	return " "
}

func getTeamConfigBySlug(teamSlug string, teams []teamConfig) teamConfig {
	for _, team := range teams {
		if team.Github_slug == teamSlug {
			return team
		}
	}
	return teamConfig{}
}
